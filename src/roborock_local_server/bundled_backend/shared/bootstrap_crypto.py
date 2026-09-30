"""Bootstrap encryption helpers for /region and /nc responses."""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

LOG = logging.getLogger("real_stack.bootstrap_crypto")


def _encrypt_json_oaep_sha1_b64(pubkey: Any, payload: dict[str, Any] | list[Any] | str) -> str:
    if isinstance(payload, str):
        plain = payload
    else:
        plain = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    data = plain.encode("utf-8")
    key_bytes = pubkey.key_size // 8
    chunk_max = key_bytes - 2 * 20 - 2  # OAEP-SHA1 payload limit
    out = bytearray()
    for idx in range(0, len(data), chunk_max):
        chunk = data[idx : idx + chunk_max]
        out.extend(
            pubkey.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                ),
            )
        )
    return base64.b64encode(bytes(out)).decode("ascii")


class BootstrapEncryptor:
    """Loads known device public keys from key-state JSON and encrypts bootstrap payloads."""

    def __init__(self, state_file: Path | None) -> None:
        self.state_file = state_file
        self._pubkeys: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if self.state_file is None:
            return
        if not self.state_file.exists():
            LOG.warning("Device key state file not found: %s", self.state_file)
            return
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception as exc:
            LOG.warning("Failed reading key state file %s: %s", self.state_file, exc)
            return
        devices = raw.get("devices")
        if not isinstance(devices, dict):
            LOG.warning("Key state file %s has no 'devices' object", self.state_file)
            return

        loaded = 0
        for did, item in devices.items():
            if not isinstance(did, str) or not isinstance(item, dict):
                continue
            mod_hex = str(item.get("modulus_hex") or "").strip()
            if not mod_hex:
                continue
            try:
                n = int(mod_hex, 16)
                pub = rsa.RSAPublicNumbers(65537, n).public_key()
            except Exception as exc:
                LOG.warning("Invalid modulus for did=%s in %s: %s", did, self.state_file, exc)
                continue
            self._pubkeys[did] = pub
            loaded += 1
        LOG.info("Bootstrap encryptor loaded %d public keys from %s", loaded, self.state_file)

    def known_dids(self) -> list[str]:
        return sorted(self._pubkeys.keys())

    def get_pubkey(self, did: str) -> Any | None:
        return self._pubkeys.get(did)

    def encrypt_for_did(self, did: str, payload: dict[str, Any] | list[Any] | str) -> str | None:
        pub = self._pubkeys.get(did)
        if pub is None:
            return None
        try:
            return _encrypt_json_oaep_sha1_b64(pub, payload)
        except Exception as exc:
            LOG.warning("Encryption failed for did=%s: %s", did, exc)
            return None

