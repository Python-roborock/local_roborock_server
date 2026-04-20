import json
import time
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor
from shared.protocol_auth import ProtocolAuthStore, build_hawk_authorization


FIXTURE_PATH = Path(__file__).with_name("fixtures") / "ios_app_init_v4_59_02_anonymized.json"


def _load_fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _cloud_snapshot_with_protocol_user_data(snapshot: dict[str, Any]) -> dict[str, Any]:
    seeded = dict(snapshot)
    seeded["user_data"] = {
        "uid": 1001,
        "token": "anon-app-token",
        "rruid": "anon-rruid",
        "rriot": {
            "u": "user-anon",
            "s": "session-anon",
            "h": "contract-hawk-secret",
            "k": "contract-hawk-mqtt-key",
            "r": {
                "r": "US",
                "a": "https://api-us.roborock.com",
                "m": "ssl://mqtt-us.roborock.com:8883",
                "l": "https://wood-us.roborock.com",
            },
        },
    }
    return seeded


def _record_runtime_presence(supervisor: ReleaseSupervisor, entries: list[dict[str, Any]]) -> None:
    for entry in entries:
        conn_id = str(entry["conn_id"])
        did = str(entry["did"])
        mqtt_user = str(entry["mqtt_user"])
        supervisor.runtime_state.record_mqtt_connection(
            conn_id=conn_id,
            client_ip="testclient",
            client_port=1883,
        )
        supervisor.runtime_state.record_mqtt_message(
            conn_id=conn_id,
            direction="c2b",
            topic=f"rr/d/i/{did}/{mqtt_user}",
            payload_preview="{}",
        )


def _normalize_expected_response(request_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    normalized = json.loads(json.dumps(payload))
    if request_name == "get_home_data":
        for key in ("data", "result"):
            section = normalized.get(key)
            if isinstance(section, dict):
                section.pop("received_devices", None)
    return normalized


def test_ios_app_init_contract_from_anonymized_capture(tmp_path: Path, monkeypatch) -> None:
    fixture = _load_fixture()

    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)

    paths.runtime_dir.mkdir(parents=True, exist_ok=True)
    paths.state_dir.mkdir(parents=True, exist_ok=True)

    seed = fixture["seed"]
    _write_json(paths.inventory_path, seed["inventory"])
    _write_json(paths.cloud_snapshot_path, _cloud_snapshot_with_protocol_user_data(seed["cloud_snapshot"]))
    _write_json(paths.runtime_credentials_path, seed["runtime_credentials"])

    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.refresh_inventory_state()
    _record_runtime_presence(supervisor, seed["runtime_presence"])

    monkeypatch.setattr(time, "time", lambda: fixture["frozen_time"])

    client = TestClient(supervisor.app)
    default_headers = fixture["default_headers"]
    auth_store = ProtocolAuthStore(paths.cloud_snapshot_path)
    user = auth_store.availability().user
    assert user is not None

    for index, request in enumerate(fixture["requests"]):
        headers = dict(default_headers)
        headers.update(request.get("headers", {}))
        if request["path"].startswith(("/user/", "/v2/user/", "/v3/user/")):
            headers["authorization"] = build_hawk_authorization(
                user=user,
                path=request["path"],
                query_values=request.get("query"),
                form_values=request.get("form") or request.get("json"),
                timestamp=fixture["frozen_time"],
                nonce=f"contract-{index}",
            )
        response = client.request(
            method=request["method"],
            url=request["path"],
            headers=headers,
            params=request.get("query"),
            json=request.get("json"),
            data=request.get("form"),
        )
        assert response.status_code == 200, request["name"]
        assert response.json() == _normalize_expected_response(request["name"], request["expected_response"]), request["name"]
