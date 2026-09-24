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
