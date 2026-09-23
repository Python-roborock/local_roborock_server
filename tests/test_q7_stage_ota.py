"""The Q7 staging CLI validates bytes and never sends a device command."""

import hashlib
import json
from pathlib import Path

import httpx
import pytest

from scripts import q7_stage_ota as staging


PAYLOAD = b"synthetic-block!"


def _artifact(tmp_path: Path) -> Path:
    folder = tmp_path / "artifact"
    folder.mkdir()
    name = "return-noop-v03.bin.gz.aes"
    (folder / name).write_bytes(PAYLOAD)
    (folder / "metadata.json").write_text(json.dumps({
        "firmware": "roborock.vacuum.sc05 03.01.74 (synthetic test)",
        "signed": False,
        "encrypted_file": name,
        "encrypted_size_bytes": len(PAYLOAD),
        "encrypted_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
        "encrypted_md5": hashlib.md5(PAYLOAD).hexdigest(),
    }), encoding="utf-8")
    return folder


def test_inspect_rejects_changed_encrypted_bytes(tmp_path: Path) -> None:
    folder = _artifact(tmp_path)
    _payload, details = staging.inspect(folder)
    assert details["encrypted_size_bytes"] == 16
    (folder / "return-noop-v03.bin.gz.aes").write_bytes(b"changed-16-bytes")
    with pytest.raises(ValueError, match="do not match metadata"):
        staging.inspect(folder)


def test_stage_only_uses_admin_login_and_package_upload(tmp_path: Path) -> None:
    folder = _artifact(tmp_path)
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/admin/api/login":
            assert json.loads(request.content) == {"password": "synthetic-password"}
            return httpx.Response(200, json={"ok": True})
        assert request.url.path == "/admin/api/q7/ota-package"
        assert request.content == PAYLOAD
        assert request.headers["x-q7-sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
        return httpx.Response(200, json={
            "download_path": "/q7/ota-package/" + "a" * 64,
            "encrypted_size_bytes": len(PAYLOAD),
            "encrypted_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
            "encrypted_md5": hashlib.md5(PAYLOAD).hexdigest(),
            "expires_in_seconds": 900,
        })

    result = staging.stage(
        server="https://local.example:555",
        artifact_dir=folder,
        admin_password="synthetic-password",
        transport=httpx.MockTransport(handler),
    )
    assert paths == ["/admin/api/login", "/admin/api/q7/ota-package"]
    assert result["download_url"] == "https://local.example:555/q7/ota-package/" + "a" * 64
    assert result["device_command_sent"] is False
