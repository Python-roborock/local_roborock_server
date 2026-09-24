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


def test_inspect_api_only_pair_requires_explicit_package_and_matching_digest(tmp_path: Path) -> None:
    folder = tmp_path / "api-only"
    folder.mkdir()
    packages = {}
    for kind, name in staging.API_ONLY_PACKAGE_NAMES.items():
        payload = PAYLOAD if kind == "set-api" else b"restore-16-bytes"
        (folder / name).write_bytes(payload)
        packages[kind] = {
            "file": name,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "md5": hashlib.md5(payload).hexdigest(),
        }
    (folder / "metadata.json").write_text(json.dumps({
        "model": "roborock.vacuum.sc05",
        "target_firmware": "03.01.74",
        "signed": False,
        "packages": packages,
    }), encoding="utf-8")

    with pytest.raises(ValueError, match="require --package"):
        staging.inspect(folder)
    for kind, name in staging.API_ONLY_PACKAGE_NAMES.items():
        _payload, details = staging.inspect(folder, package_kind=kind)
        assert details["package"] == name
        assert details["encrypted_sha256"] == packages[kind]["sha256"]
    (folder / staging.API_ONLY_PACKAGE_NAMES["restore-api"]).write_bytes(b"changed-16-bytes")
    with pytest.raises(ValueError, match="do not match metadata"):
        staging.inspect(folder, package_kind="restore-api")
