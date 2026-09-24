"""Owner OTA sender must pin the hosted bytes before forming the command."""

import argparse
import asyncio
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest
from roborock.data import UserData

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


def test_email_code_list_creates_reusable_private_account_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = UserData.from_dict({
        "rriot": {"u": "mqtt-user", "s": "mqtt-secret", "h": "mqtt-host", "k": "mqtt-key", "r": {}},
        "token": "private-token",
    })
    home = SimpleNamespace(
        products=[
            SimpleNamespace(id="q7-product", model="roborock.vacuum.sc05"),
            SimpleNamespace(id="other-product", model="roborock.vacuum.a15"),
        ],
        devices=[
            SimpleNamespace(duid="q7-cloud-duid", product_id="q7-product", fv="03.01.80", online=True,
                            local_key="0123456789abcdef"),
            SimpleNamespace(duid="other-duid", product_id="other-product", fv="01.00.00", online=True,
                            local_key="fedcba9876543210"),
        ],
    )
    events: list[str] = []

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    class FakeApi:
        def __init__(self, email: str, *, base_url: str | None = None, session: object):
            events.append(f"api:{email}:{base_url or 'discover'}")
            assert isinstance(session, FakeSession)

        @property
        async def base_url(self) -> str:
            return "https://owner.example.test"

        async def request_code_v4(self) -> None:
            events.append("request_code")

        async def code_login_v4(self, code: str) -> UserData:
            events.append(f"code_login:{code}")
            return owner

        async def get_home_data_v3(self, user_data: UserData):
            assert user_data.rriot.u == "mqtt-user"
            events.append("home_data")
            return home

    monkeypatch.setattr(q7_owner_ota.aiohttp, "ClientSession", FakeSession)
    monkeypatch.setattr(q7_owner_ota, "RoborockApiClient", FakeApi)
    monkeypatch.setattr("builtins.input", lambda _prompt: " 123456 ")
    monkeypatch.setattr(q7_owner_ota, "create_mqtt_session", lambda _params: pytest.fail("list contacted MQTT"))

    export = tmp_path / "private" / "owner-account.json"
    args = argparse.Namespace(email="owner@example.test", account=None, save_account=export, list=True)
    result = asyncio.run(q7_owner_ota.run(args))
    assert result == {
        "devices": [{
            "duid": "q7-cloud-duid", "firmware": "03.01.80", "cloud_online": True,
            "local_key_length": 16,
        }],
        "command_sent": False,
    }
    saved = json.loads(export.read_text(encoding="utf-8"))
    assert saved["username"] == "owner@example.test"
    assert saved["base_url"] == "https://owner.example.test"
    assert UserData.from_dict(saved["user_data"]).token == "private-token"
    if os.name != "nt":
        assert stat.S_IMODE(export.stat().st_mode) == 0o600
    assert events == ["api:owner@example.test:discover", "request_code", "code_login:123456", "home_data"]

    args.email, args.account, args.save_account = None, export, None
    assert asyncio.run(q7_owner_ota.run(args)) == result
    assert events[-2:] == ["api:owner@example.test:https://owner.example.test", "home_data"]

    args.email, args.account, args.save_account = "owner@example.test", None, export
    with pytest.raises(FileExistsError, match="already exists"):
        asyncio.run(q7_owner_ota.run(args))
    assert events.count("request_code") == 1
