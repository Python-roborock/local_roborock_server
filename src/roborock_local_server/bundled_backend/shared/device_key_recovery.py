"""Persistent device key recovery helpers for onboarding bootstrap encryption."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import logging
import multiprocessing
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import gmpy2  # type: ignore

from .data_helpers import utcnow_iso


LOG = logging.getLogger("real_stack.device_key_recovery")
DEFAULT_RSA_E = 65537
MIN_RSA_SIGNATURE_BYTES = 128
MAX_QUERY_SAMPLE_COUNT = 16
MAX_HEADER_SAMPLE_COUNT = 64
SAVE_REPLACE_RETRIES = 8
SAVE_REPLACE_RETRY_SEC = 0.05
_MP_CTX = multiprocessing.get_context("spawn")


def split_signed_query(query: str) -> tuple[str, str] | None:
    """Return canonical query without signature and decoded signature b64 text."""
    if not query or "signature=" not in query:
        return None
    parts = query.split("&")
    canonical_parts: list[str] = []
    signature_raw = ""
    for part in parts:
        if part.startswith("signature=") and not signature_raw:
            signature_raw = part[len("signature=") :]
            continue
        canonical_parts.append(part)
    if not signature_raw:
        return None
    canonical = "&".join(canonical_parts)
    try:
        signature_b64 = urllib.parse.unquote(signature_raw)
        base64.b64decode(signature_b64, validate=True)
    except Exception:
        return None
    return canonical, signature_b64


def _emsa_pkcs1_v1_5_sha256(msg: str, key_bytes: int) -> int:
    digest = hashlib.sha256(msg.encode("utf-8")).digest()
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    if key_bytes < len(digest_info) + 3:
        raise ValueError("key too small for PKCS1v1.5 SHA-256 encoding")
    ps = b"\xff" * (key_bytes - len(digest_info) - 3)
    em = b"\x00\x01" + ps + b"\x00" + digest_info
    return int.from_bytes(em, "big")


def _gcd_many(values: list[Any]) -> Any:
    if not values:
        return 0
    acc = values[0]
    for value in values[1:]:
        acc = gmpy2.gcd(acc, value)
    return acc


def recover_modulus_from_samples(
    samples: list[tuple[str, str]],
    *,
    e: int = DEFAULT_RSA_E,
) -> int | None:
    """Recover an RSA modulus from canonical query/signature pairs."""
    dedup: dict[str, str] = {}
    for canonical, sig_b64 in samples:
        if canonical and canonical not in dedup:
            dedup[canonical] = sig_b64
    if len(dedup) < 2:
        return None

    pairs = list(dedup.items())
    sig_lengths = [len(base64.b64decode(sig_b64)) for _canonical, sig_b64 in pairs]
    key_bytes = max(sig_lengths)
    xs: list[Any] = []
    verifiers: list[tuple[int, int]] = []
    for canonical, sig_b64 in pairs:
        sig_bytes = base64.b64decode(sig_b64)
        if len(sig_bytes) != key_bytes:
            continue
        sig_int = int.from_bytes(sig_bytes, "big")
        em_int = _emsa_pkcs1_v1_5_sha256(canonical, key_bytes)
        x = gmpy2.mpz(sig_int) ** e - gmpy2.mpz(em_int)
        xs.append(abs(x))
        verifiers.append((sig_int, em_int))

    if len(xs) < 2:
        return None

    n_any = _gcd_many(xs)
    if not n_any:
        return None
    n_int = int(n_any)
    target_bits = key_bytes * 8

    def _verify_candidate(candidate: int) -> bool:
        if candidate <= 0:
            return False
        for sig_int, em_int in verifiers:
            if pow(sig_int, e, candidate) != em_int:
                return False
        return True

    if n_int.bit_length() == target_bits and _verify_candidate(n_int):
        return n_int

    # Sometimes gcd(x_i) retains a small cofactor (for example 3*n with sparse samples).
    # Try removing small-prime factors and re-verify exact RSA relation.
    candidate = n_int
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31)
    factor_powers: list[tuple[int, int]] = []
    for prime in small_primes:
        power = 0
        while candidate % prime == 0:
            candidate //= prime
            power += 1
        if power:
            factor_powers.append((prime, power))

    if not factor_powers:
        return None

    divisors = [1]
    for prime, power in factor_powers:
        next_divisors: list[int] = []
        prime_power = 1
        for _ in range(power + 1):
            for value in divisors:
                next_divisors.append(value * prime_power)
            prime_power *= prime
        divisors = next_divisors
        if len(divisors) > 4096:
            break

    for divisor in sorted(set(divisors)):
        trial = n_int // divisor
        if trial.bit_length() != target_bits:
            continue
        if _verify_candidate(trial):
            return trial
    return None


def encrypt_json_oaep_sha1_b64(pubkey: Any, payload: dict[str, Any] | list[Any] | str) -> str:
    if isinstance(payload, str):
        plain = payload
    else:
        plain = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    data = plain.encode("utf-8")
    key_bytes = pubkey.key_size // 8
    chunk_max = key_bytes - 2 * 20 - 2
    out = bytearray()
    for idx in range(0, len(data), chunk_max):
        out.extend(
            pubkey.encrypt(
                data[idx : idx + chunk_max],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                ),
            )
        )
    return base64.b64encode(bytes(out)).decode("ascii")


def _recover_modulus_subprocess(
    samples: list[tuple[str, str]],
    e: int,
    conn: Any,
) -> None:
    try:
        modulus = recover_modulus_from_samples(samples, e=e)
        conn.send((int(modulus) if modulus else None, ""))
    except Exception as exc:  # noqa: BLE001
        conn.send((None, str(exc)))
    finally:
        conn.close()


class DeviceKeyCache:
    """Persistent sample/key store with async public-key recovery."""

    def __init__(self, state_file: str | Path) -> None:
        self.state_file = Path(state_file)

        self._lock = threading.Lock()
        self._recovering: set[str] = set()
        self._samples: dict[str, list[tuple[str, str]]] = {}
        self._header_samples: dict[str, list[dict[str, str]]] = {}
        self._modulus: dict[str, int] = {}
        self._pubkeys: dict[str, Any] = {}
        self._recovery_meta: dict[str, dict[str, str]] = {}

        self._load()
        self._resume_pending_recoveries()

    @staticmethod
    def _normalize_recovery_meta(raw: Any) -> dict[str, str]:
        if not isinstance(raw, dict):
            return {}
        out: dict[str, str] = {}
        for key in ("state", "note", "error", "started_at", "finished_at"):
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                out[key] = value.strip()
        return out

    def _set_recovery_meta_locked(
        self,
        did: str,
        *,
        state: str,
        note: str = "",
        error: str = "",
        started_at: str = "",
        finished_at: str = "",
    ) -> bool:
        current = dict(self._recovery_meta.get(did) or {})
        current["state"] = state
        if note:
            current["note"] = note
        elif "note" in current:
            current.pop("note", None)
        if error:
            current["error"] = error
        elif "error" in current:
            current.pop("error", None)
        if started_at:
            current["started_at"] = started_at
        if finished_at:
            current["finished_at"] = finished_at
        previous = dict(self._recovery_meta.get(did) or {})
        if previous == current:
            return False
        self._recovery_meta[did] = current
        return True

    def _state_tmp_file(self) -> Path:
        return self.state_file.with_suffix(self.state_file.suffix + ".tmp")

    def _load(self) -> None:
        tmp_file = self._state_tmp_file()
        candidate_paths: list[Path] = []
        if tmp_file.exists():
            try:
                state_exists = self.state_file.exists()
                tmp_is_newer = (not state_exists) or (
                    tmp_file.stat().st_mtime_ns >= self.state_file.stat().st_mtime_ns
                )
            except OSError:
                tmp_is_newer = False
            if tmp_is_newer:
                candidate_paths.extend([tmp_file, self.state_file])
            else:
                candidate_paths.extend([self.state_file, tmp_file])
        else:
            candidate_paths.append(self.state_file)

        raw: dict[str, Any] | None = None
        source_path: Path | None = None
        for candidate in candidate_paths:
            if not candidate.exists():
                continue
            try:
                parsed = json.loads(candidate.read_text(encoding="utf-8"))
            except Exception as exc:
                LOG.warning("state load failed from %s: %s", candidate, exc)
                continue
            devices = parsed.get("devices")
            if not isinstance(devices, dict):
                LOG.warning("state load skipped %s: missing or invalid devices map", candidate)
                continue
            raw = parsed
            source_path = candidate
            break

        if raw is None:
            return
        if source_path == tmp_file and tmp_file.exists():
            try:
                tmp_file.replace(self.state_file)
            except OSError as exc:
                LOG.warning("state promote failed from %s to %s: %s", tmp_file, self.state_file, exc)

        devices = raw.get("devices", {})
        if not isinstance(devices, dict):
            return
        for did, item in devices.items():
            if not isinstance(did, str) or not isinstance(item, dict):
                continue

            sample_list = item.get("samples", [])
            if isinstance(sample_list, list):
                clean_samples: list[tuple[str, str]] = []
                for sample in sample_list:
                    if not isinstance(sample, dict):
                        continue
                    canonical = str(sample.get("canonical", "")).strip()
                    signature_b64 = str(sample.get("signature_b64", "")).strip()
                    if not canonical or not signature_b64:
                        continue
                    clean_samples.append((canonical, signature_b64))
                if clean_samples:
                    self._samples[did] = clean_samples

            header_samples = item.get("header_samples", [])
            if isinstance(header_samples, list):
                clean_headers: list[dict[str, str]] = []
                for sample in header_samples:
                    if not isinstance(sample, dict):
                        continue
                    signature_b64 = str(sample.get("signature_b64", "")).strip()
                    if not signature_b64:
                        continue
                    try:
                        sig_len = len(base64.b64decode(signature_b64, validate=True))
                    except Exception:
                        continue
                    clean_headers.append(
                        {
                            "method": str(sample.get("method", "")).strip().upper(),
                            "path": str(sample.get("path", "")).strip(),
                            "query": str(sample.get("query", "")).strip(),
                            "nonce": str(sample.get("nonce", "")).strip(),
                            "ts": str(sample.get("ts", "")).strip(),
                            "signature_b64": signature_b64,
                            "body_sha256": str(sample.get("body_sha256", "")).strip(),
                            "signature_len": str(sig_len),
                        }
                    )
                if clean_headers:
                    self._header_samples[did] = clean_headers

            mod_hex = str(item.get("modulus_hex", "")).strip()
            if mod_hex:
                try:
                    self._set_modulus_locked(did, int(mod_hex, 16))
                except Exception:
                    LOG.warning("Invalid modulus in %s for did=%s", self.state_file, did)

            recovery_meta = self._normalize_recovery_meta(item.get("recovery"))
            if recovery_meta:
                if did in self._modulus and recovery_meta.get("state") != "recovered":
                    recovery_meta["state"] = "recovered"
                    recovery_meta["note"] = "Public key is available."
                self._recovery_meta[did] = recovery_meta
            elif did in self._modulus:
                self._set_recovery_meta_locked(did, state="recovered", note="Public key is available.")

    def _resume_pending_recoveries(self) -> None:
        pending: list[str] = []
        with self._lock:
            for did, samples in self._samples.items():
                if did in self._pubkeys:
                    continue
                if len(samples) < 2:
                    continue
                pending.append(did)
        for did in pending:
            self.maybe_recover_async(did)

    def _save(self) -> None:
        devices: dict[str, Any] = {}
        all_dids = set(self._samples) | set(self._header_samples) | set(self._modulus) | set(self._recovery_meta)
        for did in sorted(all_dids):
            samples = [{"canonical": c, "signature_b64": b} for c, b in self._samples.get(did, [])]
            item: dict[str, Any] = {
                "samples": samples,
                "header_samples": self._header_samples.get(did, []),
            }
            if did in self._modulus:
                item["modulus_hex"] = format(self._modulus[did], "x")
            if did in self._recovery_meta:
                item["recovery"] = self._recovery_meta[did]
            devices[did] = item

        payload = {"devices": devices}
        payload_text = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
        tmp = self._state_tmp_file()
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(payload_text, encoding="utf-8")

        for attempt in range(SAVE_REPLACE_RETRIES):
            try:
                tmp.replace(self.state_file)
                return
            except PermissionError:
                if attempt + 1 < SAVE_REPLACE_RETRIES:
                    time.sleep(SAVE_REPLACE_RETRY_SEC)
                    continue
                break
        self.state_file.write_text(payload_text, encoding="utf-8")
        try:
            tmp.unlink()
        except OSError:
            pass

    def _save_safe_locked(self) -> None:
        try:
            self._save()
        except Exception as exc:
            LOG.warning("state save failed for %s: %s", self.state_file, exc)

    def _set_modulus_locked(self, did: str, modulus: int) -> None:
        self._modulus[did] = modulus
        self._pubkeys[did] = rsa.RSAPublicNumbers(DEFAULT_RSA_E, modulus).public_key()

    def set_public_key_pem(self, did: str, pem_text: str) -> None:
        pub = serialization.load_pem_public_key(pem_text.encode("ascii"))
        numbers = pub.public_numbers()
        if not isinstance(numbers, rsa.RSAPublicNumbers):
            raise ValueError("not an RSA public key")
        with self._lock:
            self._set_modulus_locked(did, int(numbers.n))
            self._set_recovery_meta_locked(
                did,
                state="recovered",
                note="Public key loaded from PEM.",
                finished_at=utcnow_iso(),
            )
            self._save_safe_locked()

    def get_known_dids(self) -> list[str]:
        with self._lock:
            return sorted(set(self._samples) | set(self._header_samples) | set(self._pubkeys) | set(self._recovery_meta))

    def get_pubkey(self, did: str) -> Any | None:
        with self._lock:
            return self._pubkeys.get(did)

    def add_signed_query(self, did: str, query: str) -> bool:
        parsed = split_signed_query(query)
        if not parsed or not did:
            return False
        canonical, signature_b64 = parsed
        with self._lock:
            arr = self._samples.setdefault(did, [])
            if (canonical, signature_b64) in arr:
                return False
            arr.append((canonical, signature_b64))
            if len(arr) > MAX_QUERY_SAMPLE_COUNT:
                del arr[:-MAX_QUERY_SAMPLE_COUNT]
            if did not in self._pubkeys:
                note = f"Captured {len(arr)} query signature sample(s)."
                self._set_recovery_meta_locked(did, state="collecting", note=note)
            self._save_safe_locked()
        return True

    def add_header_signature(
        self,
        did: str,
        *,
        method: str,
        path: str,
        query: str,
        nonce: str,
        ts: str,
        signature_b64: str,
        body_sha256: str = "",
    ) -> bool:
        sign = (signature_b64 or "").strip()
        if not did or not sign:
            return False
        try:
            sig_len = len(base64.b64decode(sign, validate=True))
        except Exception:
            return False
        entry = {
            "method": (method or "").strip().upper(),
            "path": (path or "").strip(),
            "query": (query or "").strip(),
            "nonce": (nonce or "").strip(),
            "ts": (ts or "").strip(),
            "signature_b64": sign,
            "body_sha256": (body_sha256 or "").strip(),
            "signature_len": str(sig_len),
        }
        with self._lock:
            arr = self._header_samples.setdefault(did, [])
            if entry in arr:
                return False
            arr.append(entry)
            if len(arr) > MAX_HEADER_SAMPLE_COUNT:
                del arr[:-MAX_HEADER_SAMPLE_COUNT]
            if did not in self._pubkeys and did not in self._samples:
                note = f"Captured {len(arr)} header sign sample(s)."
                self._set_recovery_meta_locked(did, state="collecting", note=note)
            self._save_safe_locked()
        return True

    def maybe_recover_async(self, did: str) -> None:
        with self._lock:
            if did in self._pubkeys:
                changed = self._set_recovery_meta_locked(did, state="recovered", note="Public key is available.")
                if changed:
                    self._save_safe_locked()
                return
            samples = list(self._samples.get(did, []))
            if len(samples) < 2:
                note = f"Need at least 2 query signature samples ({len(samples)} captured)."
                changed = self._set_recovery_meta_locked(did, state="collecting", note=note)
                if changed:
                    self._save_safe_locked()
                return
            sig_lengths: list[int] = []
            for _canonical, sig_b64 in samples:
                try:
                    sig_lengths.append(len(base64.b64decode(sig_b64, validate=True)))
                except Exception:
                    continue
            if not sig_lengths:
                changed = self._set_recovery_meta_locked(
                    did,
                    state="failed",
                    note="Query signatures are malformed.",
                    error="No valid base64 query signatures.",
                )
                if changed:
                    self._save_safe_locked()
                return
            max_sig_len = max(sig_lengths)
            if max_sig_len < MIN_RSA_SIGNATURE_BYTES:
                changed = self._set_recovery_meta_locked(
                    did,
                    state="blocked",
                    note=(
                        f"Captured signatures are {max_sig_len} bytes; "
                        f"need >= {MIN_RSA_SIGNATURE_BYTES} for RSA recovery."
                    ),
                )
                if changed:
                    self._save_safe_locked()
                return
            if did in self._recovering:
                return

            self._recovering.add(did)
            started_at = utcnow_iso()
            self._set_recovery_meta_locked(
                did,
                state="recovering",
                note="Recovering RSA modulus from query signatures.",
                started_at=started_at,
            )
            self._save_safe_locked()

        def _worker() -> None:
            started = time.time()
            try:
                parent_conn, child_conn = _MP_CTX.Pipe(duplex=False)
                process = _MP_CTX.Process(
                    target=_recover_modulus_subprocess,
                    args=(samples, DEFAULT_RSA_E, child_conn),
                    daemon=True,
                )
                process.start()
                child_conn.close()
                process.join()

                modulus: int | None = None
                error = ""
                if parent_conn.poll():
                    modulus, error = parent_conn.recv()
                parent_conn.close()
                if process.exitcode not in (0, None) and not error:
                    raise RuntimeError(f"Recovery subprocess exited with code {process.exitcode}.")
                if error:
                    raise RuntimeError(error)
                finished_at = utcnow_iso()
                with self._lock:
                    if not modulus:
                        self._set_recovery_meta_locked(
                            did,
                            state="failed",
                            note="Could not recover modulus from captured samples.",
                            error="recover_modulus_from_samples returned no modulus.",
                            finished_at=finished_at,
                        )
                        self._save_safe_locked()
                        return
                    self._set_modulus_locked(did, modulus)
                    self._set_recovery_meta_locked(
                        did,
                        state="recovered",
                        note=(
                            f"Recovered {modulus.bit_length()}-bit public key in "
                            f"{time.time() - started:.1f}s."
                        ),
                        error="",
                        finished_at=finished_at,
                    )
                    self._save_safe_locked()
                LOG.info("Recovered RSA public key for did=%s (%d bits)", did, modulus.bit_length())
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    self._set_recovery_meta_locked(
                        did,
                        state="failed",
                        note="Recovery raised an exception.",
                        error=str(exc),
                        finished_at=utcnow_iso(),
                    )
                    self._save_safe_locked()
                LOG.warning("Failed recovering public key for did=%s: %s", did, exc)
            finally:
                with self._lock:
                    self._recovering.discard(did)

        thread = threading.Thread(target=_worker, name=f"key-recover-{did}", daemon=True)
        thread.start()

    def encrypt_for_did(self, did: str, payload: dict[str, Any] | list[Any] | str) -> str | None:
        pub = self.get_pubkey(did)
        if pub is None:
            return None
        return encrypt_json_oaep_sha1_b64(pub, payload)
