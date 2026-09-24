"""The Q7 migration manifest preparer never contacts a robot."""

import json
import hashlib
from pathlib import Path

import httpx
import pytest

from scripts import q7_prepare_migration as prep


def _prepare(tmp_path: Path, **overrides: object) -> dict[str, str]:
    arguments = {
        "server": "https://local.example:555",
        "duid": "synthetic-duid",
        "api_url": "https://local.example:555",
        "mqtt_url": "ssl://local.example:8883",
        "out": tmp_path / "private" / "migration.json",
        "admin_password": "synthetic-admin-password",
    }
    arguments.update(overrides)
    return prep.prepare(**arguments)


def test_bad_target_urls_are_rejected_before_server_contact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_client(**_kwargs: object) -> None:
        raise AssertionError("Invalid target URL must not reserve credentials")

    monkeypatch.setattr(prep.httpx, "Client", unexpected_client)
    for field, value in (
        ("api_url", "http://local.example:555"),
        ("api_url", "https://local.example:bad"),
        ("mqtt_url", "tcp://local.example:8883"),
        ("mqtt_url", "ssl://local.example:8883;touch-bad"),
    ):
        with pytest.raises(ValueError, match=field):
            _prepare(tmp_path, **{field: value})
    with pytest.raises(ValueError, match="--server"):
        _prepare(tmp_path, server="https://local.example:bad")


def test_preparer_writes_private_manifest_with_cloud_key_pin_without_printing_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    requests: list[tuple[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content)
        requests.append((request.url.path, data))
        if request.url.path == "/admin/api/login":
            return httpx.Response(200, json={"ok": True})
        assert request.url.path == "/admin/api/q7/migration-credentials"
        return httpx.Response(200, json={
            "did": "",
            "duid": "synthetic-duid",
            "mqtt_clientid": "1" * 16,
            "mqtt_usr": "2" * 16,
            "mqtt_passwd": "3" * 32,
            "local_key_sha256": hashlib.sha256(b"0123456789abcdef").hexdigest(),
        })

    original_client = httpx.Client
    monkeypatch.setattr(
        prep.httpx, "Client",
        lambda **kwargs: original_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    result = _prepare(tmp_path)
    manifest = tmp_path / "private" / "migration.json"
    assert result["manifest"] == str(manifest.resolve())
    assert json.loads(manifest.read_text(encoding="utf-8")) == {
        "api_url": "https://local.example:555",
        "mqtt_url": "ssl://local.example:8883",
        "mqtt_clientid": "1" * 16,
        "mqtt_usr": "2" * 16,
        "mqtt_passwd": "3" * 32,
        "_preflight": {
            "duid_sha256": hashlib.sha256(b"synthetic-duid").hexdigest(),
            "local_key_sha256": hashlib.sha256(b"0123456789abcdef").hexdigest(),
        },
    }
    assert requests == [
        ("/admin/api/login", {"password": "synthetic-admin-password"}),
        ("/admin/api/q7/migration-credentials", {"did": "", "duid": "synthetic-duid"}),
    ]
    assert capsys.readouterr().out == ""
    with pytest.raises(FileExistsError):
        _prepare(tmp_path)
    assert len(requests) == 2


def test_preparer_refuses_server_without_key_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/admin/api/login":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(200, json={
            "duid": "synthetic-duid",
            "mqtt_clientid": "1" * 16,
            "mqtt_usr": "2" * 16,
            "mqtt_passwd": "3" * 32,
        })

    original_client = httpx.Client
    monkeypatch.setattr(
        prep.httpx, "Client",
        lambda **kwargs: original_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    with pytest.raises(ValueError, match="fingerprint"):
        _prepare(tmp_path)
    assert not (tmp_path / "private" / "migration.json").exists()
