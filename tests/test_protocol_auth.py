import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import PROTOCOL_AUTH_SYNC_PATH, ReleaseSupervisor
from https_server.routes.auth.service import load_cloud_user_data
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


def _protocol_user_data(
    *,
    token: str,
    rruid: str,
    hawk_id: str,
    hawk_session: str,
    hawk_key: str,
    mqtt_key: str,
) -> dict[str, object]:
    return {
        "uid": 1001,
        "token": token,
        "rruid": rruid,
        "rriot": {
            "u": hawk_id,
            "s": hawk_session,
            "h": hawk_key,
            "k": mqtt_key,
        },
    }


def _token_headers(login_payload: dict[str, object]) -> dict[str, str]:
    return {
        "Authorization": str(login_payload["token"]),
        "header_username": str(login_payload["rruid"]),
    }


def _build_supervisor(tmp_path: Path, *, with_snapshot: bool = True) -> tuple[ReleaseSupervisor, object]:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    _write_json(paths.inventory_path, {"home": {"id": 12345, "name": "Test Home"}, "devices": []})
    if with_snapshot:
        _seed_cloud_snapshot(paths.cloud_snapshot_path)
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    return supervisor, paths


def _build_supervisor_with_protocol_toggle(
    tmp_path: Path,
    *,
    protocol_auth_enabled: bool,
) -> tuple[ReleaseSupervisor, object]:
    config_file = write_release_config(tmp_path, protocol_auth_enabled=protocol_auth_enabled)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    _write_json(paths.inventory_path, {"home": {"id": 12345, "name": "Test Home"}, "devices": []})
    _seed_cloud_snapshot(paths.cloud_snapshot_path)
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    return supervisor, paths


def test_protected_routes_require_native_token_and_hawk_auth(tmp_path: Path) -> None:
    supervisor, paths = _build_supervisor(tmp_path)
    client = TestClient(supervisor.app)

    unauth_home = client.get("/api/v1/getHomeDetail")
    assert unauth_home.status_code == 401
    assert unauth_home.json()["code"] == 2010
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
    assert unauth_inbox.json()["code"] == 40101
    assert unauth_inbox.json()["data"]["auth"] == "hawk"

    auth_store = ProtocolAuthStore(paths.cloud_snapshot_path)
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


def test_token_auth_failures_use_roborock_invalid_credentials_code(tmp_path: Path) -> None:
    supervisor, _paths = _build_supervisor(tmp_path)
    client = TestClient(supervisor.app)

    bad_token = client.get("/api/v1/getHomeDetail", headers={"Authorization": "wrong-token"})
    assert bad_token.status_code == 401
    assert bad_token.json()["code"] == 2010
    assert bad_token.json()["msg"] == "invalid_credentials"
    assert bad_token.json()["data"]["reason"] == "invalid_token"

    wrong_user = client.get(
        "/api/v1/getHomeDetail",
        headers={
            "Authorization": "local-token-123",
            "header_username": "wrong-rruid",
        },
    )
    assert wrong_user.status_code == 401
    assert wrong_user.json()["code"] == 2010
    assert wrong_user.json()["data"]["reason"] == "invalid_header_username"


def test_local_pin_login_succeeds_without_imported_cloud_snapshot(tmp_path: Path) -> None:
    supervisor, _paths = _build_supervisor(tmp_path, with_snapshot=False)
    client = TestClient(supervisor.app)

    send_response = client.post(
        "/api/v5/email/code/send",
        json={"email": "USER@example.com", "baseUrl": "https://api-us.roborock.com"},
    )
    assert send_response.status_code == 200
    assert send_response.json()["data"]["sent"] is True

    login_response = client.post(
        "/api/v5/auth/email/login/code",
        json={"email": "USER@example.com", "code": "123456", "baseUrl": "https://api-us.roborock.com"},
    )
    assert login_response.status_code == 200
    login_payload = login_response.json()["data"]
    assert login_payload["email"] == "user@example.com"
    assert login_payload["token"].startswith("rr")
    assert login_payload["rriot"]["r"]["a"] == supervisor.context.api_url()
    assert login_payload["rriot"]["r"]["m"] == supervisor.context.mqtt_url()
    assert login_payload["rriot"]["r"]["l"] == supervisor.context.wood_url()

    home_response = client.get("/api/v1/getHomeDetail", headers=_token_headers(login_payload))
    assert home_response.status_code == 200
    assert home_response.json()["data"]["rrHomeId"] == 12345

    user_info = client.get("/api/v1/userInfo", headers=_token_headers(login_payload))
    assert user_info.status_code == 200
    assert user_info.json()["data"]["email"] == "user@example.com"


def test_protected_routes_skip_protocol_auth_when_disabled(tmp_path: Path) -> None:
    supervisor, _paths = _build_supervisor_with_protocol_toggle(tmp_path, protocol_auth_enabled=False)
    client = TestClient(supervisor.app)

    home_response = client.get("/api/v1/getHomeDetail")
    assert home_response.status_code == 200

    inbox_response = client.get("/user/inbox/latest")
    assert inbox_response.status_code == 200


def test_protocol_code_login_routes_use_local_email_and_pin_without_cloud_manager(tmp_path: Path, monkeypatch) -> None:
    supervisor, _paths = _build_supervisor(tmp_path)
    client = TestClient(supervisor.app)
    snapshot = json.loads(supervisor.paths.cloud_snapshot_path.read_text(encoding="utf-8"))
    snapshot.setdefault("meta", {})["username"] = "imported@example.com"
    snapshot.setdefault("user_data", {})["email"] = "imported@example.com"
    supervisor.paths.cloud_snapshot_path.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")

    async def fail_request_code(*, email: str, base_url: str = "") -> dict[str, object]:
        _ = email, base_url
        raise AssertionError("protocol code send must not call cloud_manager.request_code")

    async def fail_submit_code(*, session_id: str, code: str) -> dict[str, object]:
        _ = session_id, code
        raise AssertionError("protocol code submit must not call cloud_manager.submit_code")

    monkeypatch.setattr(supervisor.cloud_manager, "request_code", fail_request_code)
    monkeypatch.setattr(supervisor.cloud_manager, "submit_code", fail_submit_code)

    send_response = client.post(
        "/api/v5/email/code/send",
        json={"email": "user@example.com", "baseUrl": supervisor.context.api_url()},
    )
    assert send_response.status_code == 200
    assert send_response.json()["data"]["sent"] is True

    login_response = client.post(
        "/api/v5/auth/email/login/code",
        json={"email": "user@example.com", "code": "123456", "baseUrl": supervisor.context.api_url(), "sessionId": "ignored"},
    )
    assert login_response.status_code == 200
    login_payload = login_response.json()["data"]
    assert login_payload["token"] != "local-token-123"
    assert login_payload["rruid"] != "local-rruid-123"
    assert login_payload["rriot"]["u"] != "hawk-user-123"
    assert login_payload["email"] == "user@example.com"


def test_protocol_code_login_rejects_wrong_email_and_wrong_pin(tmp_path: Path) -> None:
    supervisor, _paths = _build_supervisor(tmp_path, with_snapshot=False)
    client = TestClient(supervisor.app)

    wrong_email = client.post(
        "/api/v5/auth/email/login/code",
        json={"email": "other@example.com", "code": "123456"},
    )
    assert wrong_email.status_code == 401
    assert wrong_email.json()["code"] == 2010
    assert wrong_email.json()["data"]["reason"] == "invalid_login_email"

    wrong_pin = client.post(
        "/api/v5/auth/email/login/code",
        json={"email": "user@example.com", "code": "654321"},
    )
    assert wrong_pin.status_code == 401
    assert wrong_pin.json()["code"] == 2010
    assert wrong_pin.json()["data"]["reason"] == "invalid_login_pin"


def test_protocol_password_login_is_rejected(tmp_path: Path) -> None:
    supervisor, _paths = _build_supervisor(tmp_path)
    client = TestClient(supervisor.app)

    response = client.post("/api/v5/auth/email/login/pwd", json={"email": "user@example.com", "password": "secret"})
    assert response.status_code == 400
    assert response.json()["msg"] == "password_login_not_supported"


def test_protocol_sync_route_persists_additional_sessions_and_redacts_logs(tmp_path: Path) -> None:
    supervisor, paths = _build_supervisor(tmp_path)
    client = TestClient(supervisor.app)
    synced_user_data = _protocol_user_data(
        token="real-cloud-token-999",
        rruid="real-cloud-rruid-999",
        hawk_id="real-cloud-hawk-user",
        hawk_session="real-cloud-hawk-session",
        hawk_key="real-cloud-hawk-secret",
        mqtt_key="real-cloud-mqtt-key",
    )

    sync_response = client.post(
        PROTOCOL_AUTH_SYNC_PATH,
        json={"source": "test_sync", "user_data": synced_user_data},
        headers={"X-Local-Sync-Secret": "abcdefghijklmnopqrstuvwxyz123456"},
    )
    assert sync_response.status_code == 200
    assert sync_response.json()["data"]["stored"] is True
    assert paths.protocol_auth_sessions_path.exists()

    token_headers = {
        "Authorization": "real-cloud-token-999",
        "header_username": "real-cloud-rruid-999",
    }
    authed_home = client.get("/api/v1/getHomeDetail", headers=token_headers)
    assert authed_home.status_code == 200

    auth_store = ProtocolAuthStore(
        paths.cloud_snapshot_path,
        session_store_path=paths.protocol_auth_sessions_path,
    )
    synced_user = next(user for user in auth_store.availability().users if user.token == "real-cloud-token-999")
    hawk_headers = {
        "Authorization": build_hawk_authorization(
            user=synced_user,
            path="/user/inbox/latest",
            timestamp=int(time.time()),
            nonce="nonce-protocol-sync",
        )
    }
    authed_inbox = client.get("/user/inbox/latest", headers=hawk_headers)
    assert authed_inbox.status_code == 200

    log_entries = [
        json.loads(line)
        for line in paths.http_jsonl_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    sync_entry = next(entry for entry in log_entries if entry.get("route") == "protocol_auth_sync")
    assert sync_entry["body_redacted"] is True
    assert "body_text" not in sync_entry
    assert sync_entry["headers"]["x-local-sync-secret"] == "<redacted>"


def test_local_issued_and_imported_sessions_coexist(tmp_path: Path) -> None:
    supervisor, paths = _build_supervisor(tmp_path)
    client = TestClient(supervisor.app)

    local_session = supervisor.protocol_auth.issue_local_session(
        load_cloud_user_data(supervisor.context) or {},
        source="test_local_login",
    )
    imported_user_data = _protocol_user_data(
        token="real-cloud-token-999",
        rruid="real-cloud-rruid-999",
        hawk_id="real-cloud-hawk-user",
        hawk_session="real-cloud-hawk-session",
        hawk_key="real-cloud-hawk-secret",
        mqtt_key="real-cloud-mqtt-key",
    )
    sync_response = client.post(
        PROTOCOL_AUTH_SYNC_PATH,
        json={"source": "test_sync", "user_data": imported_user_data},
        headers={"X-Local-Sync-Secret": "abcdefghijklmnopqrstuvwxyz123456"},
    )
    assert sync_response.status_code == 200

    auth_store = ProtocolAuthStore(
        paths.cloud_snapshot_path,
        session_store_path=paths.protocol_auth_sessions_path,
    )
    availability = auth_store.availability()
    assert len(availability.users) >= 3

    local_token_response = client.get(
        "/api/v1/getHomeDetail",
        headers={
            "Authorization": str(local_session["token"]),
            "header_username": str(local_session["rruid"]),
        },
    )
    assert local_token_response.status_code == 200

    imported_token_response = client.get(
        "/api/v1/getHomeDetail",
        headers={
            "Authorization": "real-cloud-token-999",
            "header_username": "real-cloud-rruid-999",
        },
    )
    assert imported_token_response.status_code == 200

    local_hawk_user = next(user for user in availability.users if user.token == local_session["token"])
    imported_hawk_user = next(user for user in availability.users if user.token == "real-cloud-token-999")

    local_hawk_response = client.get(
        "/user/inbox/latest",
        headers={
            "Authorization": build_hawk_authorization(
                user=local_hawk_user,
                path="/user/inbox/latest",
                timestamp=int(time.time()),
                nonce="nonce-local-issued",
            )
        },
    )
    assert local_hawk_response.status_code == 200

    imported_hawk_response = client.get(
        "/user/inbox/latest",
        headers={
            "Authorization": build_hawk_authorization(
                user=imported_hawk_user,
                path="/user/inbox/latest",
                timestamp=int(time.time()),
                nonce="nonce-imported",
            )
        },
    )
    assert imported_hawk_response.status_code == 200
