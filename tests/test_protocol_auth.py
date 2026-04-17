import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor
from shared.protocol_auth import ProtocolAuthStore, build_hawk_authorization


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _seed_cloud_snapshot(path: Path) -> None:
    _write_json(
        path,
        {
            "meta": {"username": "user@example.com"},
            "user_data": {
                "uid": 1001,
                "token": "local-token-123",
                "rruid": "local-rruid-123",
                "rriot": {
                    "u": "hawk-user-123",
                    "s": "hawk-session-123",
                    "h": "hawk-secret-123",
                    "k": "hawk-mqtt-key-123",
                    "r": {
                        "r": "US",
                        "a": "https://api-us.roborock.com",
                        "m": "ssl://mqtt-us.roborock.com:8883",
                        "l": "https://wood-us.roborock.com",
                    },
                },
            },
            "home_data": {"id": 12345, "name": "Test Home", "devices": []},
        },
    )


def _build_supervisor(tmp_path: Path, *, with_snapshot: bool = True) -> tuple[ReleaseSupervisor, Path]:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    _write_json(paths.inventory_path, {"home": {"id": 12345, "name": "Test Home"}, "devices": []})
    if with_snapshot:
        _seed_cloud_snapshot(paths.cloud_snapshot_path)
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    return supervisor, paths.cloud_snapshot_path


def test_protected_routes_require_native_token_and_hawk_auth(tmp_path: Path) -> None:
    supervisor, snapshot_path = _build_supervisor(tmp_path)
    client = TestClient(supervisor.app)

    unauth_home = client.get("/api/v1/getHomeDetail")
    assert unauth_home.status_code == 401
    assert unauth_home.json()["data"]["auth"] == "token"

    token_headers = {
        "Authorization": "local-token-123",
        "header_username": "local-rruid-123",
    }
    authed_home = client.get("/api/v1/getHomeDetail", headers=token_headers)
    assert authed_home.status_code == 200
    assert authed_home.json()["data"]["rrHomeId"] == 12345

    unauth_inbox = client.get("/user/inbox/latest")
    assert unauth_inbox.status_code == 401
    assert unauth_inbox.json()["data"]["auth"] == "hawk"

    auth_store = ProtocolAuthStore(snapshot_path)
    user = auth_store.availability().user
    assert user is not None
    hawk_headers = {
        "Authorization": build_hawk_authorization(
            user=user,
            path="/user/inbox/latest",
            timestamp=int(time.time()),
            nonce="nonce-protocol-auth",
        )
    }
    authed_inbox = client.get("/user/inbox/latest", headers=hawk_headers)
    assert authed_inbox.status_code == 200
    assert authed_inbox.json()["data"]["count"] == 0


def test_protected_routes_require_imported_cloud_snapshot(tmp_path: Path) -> None:
    supervisor, _snapshot_path = _build_supervisor(tmp_path, with_snapshot=False)
    client = TestClient(supervisor.app)

    response = client.get("/api/v1/getHomeDetail")
    assert response.status_code == 412
    assert response.json()["msg"] == "cloud_user_data_required"


def test_protocol_code_login_routes_reuse_cloud_import_manager(tmp_path: Path, monkeypatch) -> None:
    supervisor, _snapshot_path = _build_supervisor(tmp_path)
    client = TestClient(supervisor.app)
    captured: dict[str, str] = {}

    async def fake_request_code(*, email: str, base_url: str = "") -> dict[str, object]:
        captured["request_email"] = email
        captured["request_base_url"] = base_url
        return {"success": True, "step": "code_requested"}

    async def fake_submit_code(*, session_id: str, code: str) -> dict[str, object]:
        captured["submit_session_id"] = session_id
        captured["submit_code"] = code
        return {"success": True, "step": "inventory_fetched"}

    monkeypatch.setattr(supervisor.cloud_manager, "request_code", fake_request_code)
    monkeypatch.setattr(supervisor.cloud_manager, "find_pending_session_id", lambda *, email, base_url="": "pending-1")
    monkeypatch.setattr(supervisor.cloud_manager, "submit_code", fake_submit_code)

    send_response = client.post("/api/v5/email/code/send", json={"email": "user@example.com"})
    assert send_response.status_code == 200
    assert send_response.json()["data"]["sent"] is True
    assert captured["request_email"] == "user@example.com"

    login_response = client.post(
        "/api/v5/auth/email/login/code",
        json={"email": "user@example.com", "code": "123456"},
    )
    assert login_response.status_code == 200
    assert login_response.json()["data"]["token"] == "local-token-123"
    assert captured["submit_session_id"] == "pending-1"
    assert captured["submit_code"] == "123456"


def test_protocol_password_login_is_rejected(tmp_path: Path) -> None:
    supervisor, _snapshot_path = _build_supervisor(tmp_path)
    client = TestClient(supervisor.app)

    response = client.post("/api/v5/auth/email/login/pwd", json={"email": "user@example.com", "password": "secret"})
    assert response.status_code == 400
    assert response.json()["msg"] == "password_login_not_supported"
