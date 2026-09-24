"""Owner OTA sender must pin the hosted bytes before forming the command."""

import hashlib
from io import BytesIO
import json
from pathlib import Path

import pytest

from scripts import q7_owner_ota


def _artifact(path: Path) -> bytes:
    payload = bytes(range(16))
    path.mkdir()
    (path / "q7-migration-v03.bin.gz.aes").write_bytes(payload)
    (path / "metadata.json").write_text(json.dumps({
        "firmware": "roborock.vacuum.sc05 03.01.74, pinned inspected firmware profile",
        "package": "q7-migration-v03.bin.gz.aes",
        "encrypted_size_bytes": len(payload),
        "encrypted_sha256": hashlib.sha256(payload).hexdigest(),
        "encrypted_md5": hashlib.md5(payload).hexdigest(),
        "signed": False,
    }))
    return payload


def test_owner_request_uses_exact_hosted_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifact = tmp_path / "artifact"
    payload = _artifact(artifact)
    monkeypatch.setattr(q7_owner_ota, "urlopen", lambda _url, timeout: BytesIO(payload))
    request = q7_owner_ota.package_request(artifact, "http://192.0.2.1/update")
    assert request == {
        "packageUrl": "http://192.0.2.1/update",
        "md5": hashlib.md5(payload).hexdigest(),
        "packageSize": "16",
        "signed": False,
        "packageType": "robot",
    }


def test_owner_request_rejects_wrong_hosted_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "artifact"
    _artifact(artifact)
    monkeypatch.setattr(q7_owner_ota, "urlopen", lambda _url, timeout: BytesIO(b"wrong"))
    with pytest.raises(ValueError, match="Host"):
        q7_owner_ota.package_request(artifact, "http://192.0.2.1/update")
    with pytest.raises(ValueError, match="loopback"):
        q7_owner_ota.package_request(artifact, "http://127.0.0.1/update")


def test_cloud_key_preflight_rejects_stale_server_import() -> None:
    duid = "current-cloud-duid"
    key = "0123456789abcdef"
    pinned = {
        "duid_sha256": hashlib.sha256(duid.encode()).hexdigest(),
        "local_key_sha256": hashlib.sha256(key.encode()).hexdigest(),
    }
    assert q7_owner_ota.cloud_key_matches_server_import(pinned, duid=duid, local_key=key)
    assert not q7_owner_ota.cloud_key_matches_server_import(pinned, duid=duid, local_key="fedcba9876543210")
    assert not q7_owner_ota.cloud_key_matches_server_import(pinned, duid="different-duid", local_key=key)
    assert not q7_owner_ota.cloud_key_matches_server_import(None, duid=duid, local_key=key)
    assert not q7_owner_ota.cloud_key_matches_server_import(
        {**pinned, "local_key_sha256": "é" * 64}, duid=duid, local_key=key
    )
