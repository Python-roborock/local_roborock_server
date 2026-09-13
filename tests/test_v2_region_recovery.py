"""Check the captured v2 wire contract without embedding owner captures."""

import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import pytest

from roborock_local_server.bundled_backend.shared import device_key_recovery as recovery


def sample(**changes):
    entry = {
        "method": "GET",
        "path": "/.roborock.com/region",
        "query": "did=synthetic&token=x%2by+z%2F&signature=old",
        "nonce": "abc123",
        "ts": "1234567890",
        "signature_b64": base64.b64encode(b"S" * 512).decode(),
        "version": "v2",
    }
    entry.update(changes)
    return entry


def test_v2_preserves_exact_wire_bytes_and_removes_signature_suffix():
    canonical, _signature = recovery.split_v2_region_sample(sample())
    assert canonical == "did=synthetic&token=x%2by+z%2F:abc123:1234567890"


@pytest.mark.parametrize(
    "changes",
    [
        {"version": ""},
        {"version": "v1"},
        {"method": "POST"},
        {"path": "/b/region"},
        {"path": "/nc"},
        {"nonce": ""},
        {"ts": ""},
        {"query": ""},
        {"signature_b64": "invalid"},
        {"signature_b64": base64.b64encode(b"S" * 32).decode()},
        {"signature_b64": base64.b64encode(b"S" * 256).decode()},
    ],
)
def test_other_protocols_and_incomplete_samples_are_not_v2_rsa(changes):
    assert recovery.split_v2_region_sample(sample(**changes)) is None


def test_v2_headers_survive_restart_and_resume_recovery(tmp_path, monkeypatch):
    resumed = []
    monkeypatch.setattr(recovery.DeviceKeyCache, "maybe_recover_async", lambda self, did: resumed.append(did))
    path = tmp_path / "state.json"
    cache = recovery.DeviceKeyCache(path)
    for nonce in ("abc123", "def456"):
        assert cache.add_header_signature("synthetic", **sample(nonce=nonce))
    restored = recovery.DeviceKeyCache(path)
    assert resumed == ["synthetic"]
    assert json.loads(path.read_text())["devices"]["synthetic"]["header_samples"][0]["version"] == "v2"
    with restored._lock:
        pairs, algorithm, source = restored._recovery_samples_locked("synthetic")
    assert len(pairs) == 2
    assert pairs[0][0] == "did=synthetic&token=x%2by+z%2F:abc123:1234567890"
    assert algorithm == "sha384"
    assert source == "v2 region header"


def test_unversioned_saved_header_samples_are_not_guessed(tmp_path, monkeypatch):
    resumed = []
    monkeypatch.setattr(recovery.DeviceKeyCache, "maybe_recover_async", lambda self, did: resumed.append(did))
    path = tmp_path / "state.json"
    headers = [sample(nonce=n) for n in ("abc123", "def456")]
    for header in headers:
        del header["version"]
    path.write_text(json.dumps({"devices": {"synthetic": {"header_samples": headers}}}))
    recovery.DeviceKeyCache(path)
    assert resumed == []


@pytest.mark.parametrize("tamper_holdout", [False, True])
def test_v2_worker_verifies_samples_beyond_recovery_subset(monkeypatch, tamper_holdout):
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    pairs = []
    for i in range(4):
        message = f"synthetic-query-{i}:abc123:1234567890"
        signature = key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA384())
        pairs.append((message, base64.b64encode(signature).decode()))
    modulus = key.public_key().public_numbers().n

    def recovered(subset, *, e, hash_name, diagnostics):
        assert len(subset) == 3
        assert e == 65537 and hash_name == "sha384"
        return modulus

    monkeypatch.setattr(recovery, "recover_modulus_from_samples", recovered)
    if tamper_holdout:
        pairs[-1] = (pairs[-1][0] + "modified", pairs[-1][1])

    class Connection:
        payload = None

        def send(self, payload):
            self.payload = payload

        def close(self):
            pass

    conn = Connection()
    recovery._recover_modulus_subprocess(pairs, 65537, conn, "sha384")
    value, error, _traceback, diagnostics = conn.payload
    assert error == ""
    assert value == (None if tamper_holdout else modulus)
    assert diagnostics["verified_samples"] == (3 if tamper_holdout else 4)
