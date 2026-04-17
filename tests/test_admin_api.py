import json
from datetime import datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor, resolve_route
from shared.protocol_auth import ProtocolAuthStore, build_hawk_authorization


def _scene_zone_step(
    *,
    step_id: int,
    device_id: str,
    tid: str,
    zid: int,
    repeat: int,
    fan_power: int,
    water_box_mode: int,
    range_coords: list[int] | None = None,
) -> dict[str, object]:
    zone_payload: dict[str, object] = {"zid": zid, "repeat": repeat}
    if range_coords is not None:
        zone_payload["range"] = list(range_coords)
    return {
        "id": step_id,
        "name": "",
        "type": "CMD",
        "entityId": device_id,
        "param": json.dumps(
            {
                "id": step_id,
                "method": "do_scenes_zones",
                "params": {
                    "data": [
                        {
                            "tid": tid,
                            "zones": [zone_payload],
                            "map_flag": 0,
                            "fan_power": fan_power,
                            "water_box_mode": water_box_mode,
                            "repeat": repeat,
                        }
                    ],
                    "source": 101,
                },
            },
            separators=(",", ":"),
        ),
        "finishDpIds": [130],
    }


def _after_dinner_param_payload(device_id: str, *, include_ranges: bool) -> dict[str, object]:
    return {
        "triggers": [],
        "action": {
            "type": "S",
            "items": [
                _scene_zone_step(
                    step_id=1,
                    device_id=device_id,
                    tid="1773791700088",
                    zid=8,
                    repeat=1,
                    fan_power=108,
                    water_box_mode=200,
                    range_coords=[32800, 22750, 34550, 25350] if include_ranges else None,
                ),
                _scene_zone_step(
                    step_id=2,
                    device_id=device_id,
                    tid="1773791720547",
                    zid=9,
                    repeat=2,
                    fan_power=104,
                    water_box_mode=202,
                    range_coords=[32550, 22650, 34550, 25200] if include_ranges else None,
                ),
            ],
        },
        "matchType": "NONE",
    }


def _write_scene_zone_trace(mqtt_jsonl_path: Path) -> None:
    mqtt_jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    entries = [
        {
            "decoded_messages": [
                {
                    "response_to": {
                        "request_method": "set_scenes_zones",
                        "request_params": {
                            "data": [
                                {
                                    "zones": [
                                        {
                                            "range": [32800, 22750, 34550, 25350],
                                        }
                                    ]
                                }
                            ]
                        },
                        "result": [
                            {
                                "tid": "1773791700088",
                                "zones": [{"zid": 8}],
                            }
                        ],
                    }
                }
            ]
        },
        {
            "decoded_messages": [
                {
                    "response_to": {
                        "request_method": "set_scenes_zones",
                        "request_params": {
                            "data": [
                                {
                                    "zones": [
                                        {
                                            "range": [32550, 22650, 34550, 25200],
                                        }
                                    ]
                                }
                            ]
                        },
                        "result": [
                            {
                                "tid": "1773791720547",
                                "zones": [{"zid": 9}],
                            }
                        ],
                    }
                }
            ]
        },
    ]
    mqtt_jsonl_path.write_text(
        "\n".join(json.dumps(entry, separators=(",", ":")) for entry in entries) + "\n",
        encoding="utf-8",
    )


def _seed_protocol_snapshot(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
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
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )


def _hawk_headers(snapshot_path: Path, path: str, *, form_values: dict[str, object] | None = None, json_values: dict[str, object] | None = None) -> dict[str, str]:
    user = ProtocolAuthStore(snapshot_path).availability().user
    assert user is not None
    return {
        "Authorization": build_hawk_authorization(
            user=user,
            path=path,
            form_values=form_values or json_values,
            nonce=f"nonce-{path.replace('/', '-')}",
        )
    }


def test_admin_login_and_status_flow(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    supervisor = ReleaseSupervisor(config=config, paths=paths)

    client = TestClient(supervisor.app)

    login_page = client.get("/admin")
    assert login_page.status_code == 200
    assert "Sign in to manage the stack." in login_page.text

    unauthenticated_status = client.get("/admin/api/status")
    assert unauthenticated_status.status_code == 401

    bad_login = client.post("/admin/api/login", json={"password": "wrong"})
    assert bad_login.status_code == 401

    good_login = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert good_login.status_code == 200
    assert supervisor.session_manager.cookie_name in good_login.cookies

    status = client.get("/admin/api/status")
    assert status.status_code == 200
    payload = status.json()
    support_urls = [item["url"] for item in payload["support"]["links"]]
    assert support_urls == [
        "https://buymeacoffee.com/lashl",
        "https://paypal.me/LLashley304",
        "https://us.roborock.com/discount/RRSAP202602071713342D18X?redirect=%2Fpages%2Froborock-store%3Fuuid%3DEQe6p1jdZczHEN4Q0nbsG9sZRm0RK1gW5eSM%252FCzcW4Q%253D",
        "https://roborock.pxf.io/B0VYV9",
        "https://amzn.to/4bGfG6B",
    ]
    assert payload["health"]["services"]
    assert payload["pairing"]["active"] is False

    vacuums = client.get("/admin/api/vacuums")
    assert vacuums.status_code == 200
    assert vacuums.json()["vacuums"] == []

    dashboard_page = client.get("/admin")
    assert dashboard_page.status_code == 200
    assert "Cloud Import" in dashboard_page.text

    assert "Num query samples" in dashboard_page.text
    assert "Public Key determined" in dashboard_page.text
    assert "Mqtt connected" in dashboard_page.text
    assert "Buy Me a Coffee" in dashboard_page.text
    assert "PayPal" in dashboard_page.text
    assert "5% Off Roborock Store" in dashboard_page.text
    assert "Roborock Affiliate" in dashboard_page.text
    assert "Amazon Affiliate" in dashboard_page.text

    logout = client.post("/admin/api/logout")
    assert logout.status_code == 200

    status_after_logout = client.get("/admin/api/status")
    assert status_after_logout.status_code == 401


def test_admin_onboarding_endpoints_require_auth_and_manage_session(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    paths.inventory_path.parent.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "devices": [
                    {
                        "duid": "cloud-q7-a",
                        "did": "1103821560705",
                        "name": "Q7 Upstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-a",
                    }
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    paths.runtime_credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "devices": [
                    {
                        "did": "1103821560705",
                        "duid": "cloud-q7-a",
                        "name": "Q7 Upstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-a",
                        "localkey": "local-key-a",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    paths.device_key_state_path.parent.mkdir(parents=True, exist_ok=True)
    paths.device_key_state_path.write_text(
        json.dumps(
            {
                "devices": {
                    "1103821560705": {
                        "pid": "roborock.vacuum.sc05",
                        "modulus_hex": "aa",
                        "samples": [
                            {"canonical": "a=1", "signature_b64": "AQ=="},
                            {"canonical": "a=2", "signature_b64": "Ag=="},
                        ],
                    }
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )

    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.refresh_inventory_state()
    client = TestClient(supervisor.app)

    assert client.get("/admin/api/onboarding/devices").status_code == 401
    assert client.post("/admin/api/onboarding/sessions", json={"duid": "cloud-q7-a"}).status_code == 401

    login = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert login.status_code == 200

    devices = client.get("/admin/api/onboarding/devices")
    assert devices.status_code == 200
    devices_payload = devices.json()
    assert [item["duid"] for item in devices_payload["devices"]] == ["cloud-q7-a"]
    assert devices_payload["devices"][0]["name"] == "Q7 Upstairs"
    assert devices_payload["devices"][0]["onboarding"]["has_public_key"] is True
    assert devices_payload["devices"][0]["onboarding"]["key_state"]["query_samples"] == 2

    started = client.post("/admin/api/onboarding/sessions", json={"duid": "cloud-q7-a"})
    assert started.status_code == 200
    session_payload = started.json()
    session_id = session_payload["session_id"]
    assert session_payload["target"]["duid"] == "cloud-q7-a"
    assert session_payload["target"]["did"] == "1103821560705"
    assert session_payload["has_public_key"] is True
    assert session_payload["public_key_state"] == "ready"

    fetched = client.get(f"/admin/api/onboarding/sessions/{session_id}")
    assert fetched.status_code == 200
    assert fetched.json()["session_id"] == session_id

    missing = client.get("/admin/api/onboarding/sessions/not-the-session")
    assert missing.status_code == 404

    deleted = client.delete(f"/admin/api/onboarding/sessions/{session_id}")
    assert deleted.status_code == 200
    assert deleted.json()["ok"] is True

    deleted_missing = client.get(f"/admin/api/onboarding/sessions/{session_id}")
    assert deleted_missing.status_code == 404


def test_core_only_mode_disables_standalone_admin_routes(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    supervisor = ReleaseSupervisor(config=config, paths=paths, enable_standalone_admin=False)

    client = TestClient(supervisor.app)

    admin_page = client.get("/admin")
    assert admin_page.status_code == 404

    ui_health = client.get("/ui/api/health")
    assert ui_health.status_code == 404

    region_response = client.get("/region")
    assert region_response.status_code == 200


def test_ui_api_health_and_vacuums_require_admin_auth(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    paths.inventory_path.parent.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "devices": [
                    {
                        "duid": "inventory-s7-duid",
                        "name": "S7",
                        "model": "roborock.vacuum.a15",
                    }
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.runtime_state.record_mqtt_connection(
        conn_id="ui-conn-1",
        client_ip="192.168.1.50",
        client_port=1883,
    )
    supervisor.runtime_state.record_mqtt_message(
        conn_id="ui-conn-1",
        direction="c2b",
        topic="rr/m/i/test-user/test-client/inventory-s7-duid",
        payload_preview="{}",
    )

    client = TestClient(supervisor.app)

    assert client.get("/ui/api/health").status_code == 401
    assert client.get("/ui/api/vacuums").status_code == 401

    login = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert login.status_code == 200

    health = client.get("/ui/api/health")
    assert health.status_code == 200
    health_payload = health.json()
    assert health_payload["active_mqtt_connections"] == 1
    assert [vac["duid"] for vac in health_payload["connected_vacuums"]] == ["inventory-s7-duid"]

    vacuums = client.get("/ui/api/vacuums")
    assert vacuums.status_code == 200
    vacuums_payload = vacuums.json()
    assert vacuums_payload["required_onboarding_steps"] == ["region", "nc_prepare"]
    assert vacuums_payload["step_labels"]["region"] == "Region"
    s7 = next(vac for vac in vacuums_payload["vacuums"] if vac["duid"] == "inventory-s7-duid")
    assert s7["name"] == "S7"
    assert s7["connected"] is True



def test_admin_status_health_deduplicates_split_runtime_and_inventory_entries(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)

    paths.runtime_dir.mkdir(parents=True, exist_ok=True)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "devices": [
                    {
                        "duid": "inventory-s7-duid",
                        "name": "S7",
                        "model": "roborock.vacuum.a15",
                        "product_id": "product-s7",
                        "local_key": "inventory-local-key",
                    }
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    paths.runtime_credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "devices": [
                    {
                        "did": "1103811971559",
                        "duid": "",
                        "name": "",
                        "model": "",
                        "product_id": "",
                        "localkey": "",
                        "local_key_source": "",
                        "device_mqtt_usr": "mqtt-user",
                        "updated_at": "2026-03-15T15:40:20.630821+00:00",
                        "last_nc_at": "",
                        "last_mqtt_seen_at": "2026-03-15T15:40:20.630800+00:00",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    paths.device_key_state_path.write_text(
        json.dumps(
            {
                "devices": {
                    "1103811971559": {
                        "pid": "roborock.vacuum.a15",
                    }
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )

    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.refresh_inventory_state()

    client = TestClient(supervisor.app)
    login = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert login.status_code == 200

    raw_runtime_health = supervisor.runtime_state.health_snapshot()
    assert len(raw_runtime_health["all_vacuums"]) == 2

    status_payload = client.get("/admin/api/status").json()
    health_vacuums = status_payload["health"]["all_vacuums"]
    assert len(health_vacuums) == 1
    assert health_vacuums[0]["name"] == "S7"
    assert health_vacuums[0]["did"] == "1103811971559"
    assert health_vacuums[0]["duid"] == "inventory-s7-duid"


def test_admin_status_health_deduplicates_split_same_model_entries_via_persisted_did_mapping(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)

    paths.runtime_dir.mkdir(parents=True, exist_ok=True)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "devices": [
                    {
                        "duid": "cloud-q7-a",
                        "name": "Q7 Upstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-a",
                        "local_key": "local-key-a",
                    },
                    {
                        "duid": "cloud-q7-b",
                        "name": "Q7 Downstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-b",
                        "local_key": "local-key-b",
                    },
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    paths.runtime_credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "devices": [
                    {
                        "did": "1103821560705",
                        "duid": "cloud-q7-a",
                        "name": "Q7 Upstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-a",
                        "localkey": "local-key-a",
                        "local_key_source": "inventory",
                        "device_mqtt_usr": "mqtt-user-a",
                        "updated_at": "2026-03-16T00:22:31.225097+00:00",
                        "last_nc_at": "",
                        "last_mqtt_seen_at": "",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.refresh_inventory_state()
    supervisor.runtime_state.record_mqtt_connection(conn_id="dup-1", client_ip="testclient", client_port=1883)
    supervisor.runtime_state.record_mqtt_message(
        conn_id="dup-1",
        direction="c2b",
        topic="rr/d/i/1103821560705/mqtt-user-a",
        payload_preview="{}",
    )

    client = TestClient(supervisor.app)
    login = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert login.status_code == 200

    raw_runtime_health = supervisor.runtime_state.health_snapshot()
    assert len(raw_runtime_health["all_vacuums"]) == 3

    status_payload = client.get("/admin/api/status").json()
    health_vacuums = status_payload["health"]["all_vacuums"]
    assert len(health_vacuums) == 2
    assert [vac["duid"] for vac in health_vacuums] == ["cloud-q7-b", "cloud-q7-a"]

    matched = next(vac for vac in health_vacuums if vac["duid"] == "cloud-q7-a")
    assert matched["did"] == "1103821560705"
    assert matched["linked_via"] == "did"


def test_scene_update_routes_persist_name_and_zone_ranges(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    device_id = "6HL2zfniaoYYV01CkVuhkO"

    paths.inventory_path.parent.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "home": {"id": 1233716, "name": "My Home"},
                "devices": [
                    {
                        "duid": device_id,
                        "name": "Qrevo MaxV",
                        "model": "roborock.vacuum.a87",
                    }
                ],
                "scenes": [
                    {
                        "id": 4491073,
                        "name": "Old after dinner",
                        "device_id": device_id,
                        "device_name": "Qrevo MaxV",
                        "enabled": True,
                        "type": "WORKFLOW",
                        "param": json.dumps(_after_dinner_param_payload(device_id, include_ranges=False), separators=(",", ":")),
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    _seed_protocol_snapshot(paths.cloud_snapshot_path)
    _write_scene_zone_trace(paths.mqtt_jsonl_path)

    supervisor = ReleaseSupervisor(config=config, paths=paths)
    client = TestClient(supervisor.app)

    rename_response = client.put(
        "/user/scene/4491073/name",
        data={"name": "After dinner"},
        headers=_hawk_headers(
            paths.cloud_snapshot_path,
            "/user/scene/4491073/name",
            form_values={"name": "After dinner"},
        ),
    )
    assert rename_response.status_code == 200
    assert rename_response.json()["data"]["name"] == "After dinner"

    update_payload = _after_dinner_param_payload(device_id, include_ranges=False)
    update_response = client.put(
        "/user/scene/4491073/param",
        json=update_payload,
        headers=_hawk_headers(
            paths.cloud_snapshot_path,
            "/user/scene/4491073/param",
            json_values=update_payload,
        ),
    )
    assert update_response.status_code == 200

    stored_inventory = json.loads(paths.inventory_path.read_text(encoding="utf-8"))
    scene = next(scene for scene in stored_inventory["scenes"] if scene["id"] == 4491073)
    assert scene["name"] == "After dinner"

    outer = json.loads(scene["param"])
    first_item = outer["action"]["items"][0]
    second_item = outer["action"]["items"][1]
    first_step = json.loads(first_item["param"])
    second_step = json.loads(second_item["param"])
    assert first_step["params"]["data"][0]["zones"][0]["range"] == [32800, 22750, 34550, 25350]
    assert second_step["params"]["data"][0]["zones"][0]["range"] == [32550, 22650, 34550, 25200]


def test_execute_scene_hydrates_missing_zone_ranges_from_mqtt(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    device_id = "6HL2zfniaoYYV01CkVuhkO"

    paths.inventory_path.parent.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "home": {"id": 1233716, "name": "My Home"},
                "devices": [
                    {
                        "duid": device_id,
                        "name": "Qrevo MaxV",
                        "model": "roborock.vacuum.a87",
                    }
                ],
                "scenes": [
                    {
                        "id": 4491073,
                        "name": "After dinner",
                        "device_id": device_id,
                        "device_name": "Qrevo MaxV",
                        "enabled": True,
                        "type": "WORKFLOW",
                        "param": json.dumps(_after_dinner_param_payload(device_id, include_ranges=False), separators=(",", ":")),
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    _write_scene_zone_trace(paths.mqtt_jsonl_path)

    captured_scene: dict[str, object] = {}

    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.context._routine_runner = type(
        "DummyRoutineRunner",
        (),
        {
            "start_scene": lambda self, scene: (
                captured_scene.clear(),
                captured_scene.update(scene),
                {"accepted": True, "status": "started"},
            )[-1]
        },
    )()
    route_name, response_payload = resolve_route(
        rules=supervisor.endpoint_rules,
        context=supervisor.context,
        clean_path="/user/scene/4491073/execute",
        query_params={},
        body_params={},
        method="POST",
    )
    assert route_name == "execute_scene"
    assert response_payload["data"]["status"] == "started"

    executed_outer = json.loads(str(captured_scene["param"]))
    executed_step = json.loads(executed_outer["action"]["items"][0]["param"])
    assert executed_step["params"]["data"][0]["zones"][0]["range"] == [32800, 22750, 34550, 25350]

    stored_inventory = json.loads(paths.inventory_path.read_text(encoding="utf-8"))
    scene = next(scene for scene in stored_inventory["scenes"] if scene["id"] == 4491073)
    persisted_outer = json.loads(scene["param"])
    persisted_step = json.loads(persisted_outer["action"]["items"][0]["param"])
    assert persisted_step["params"]["data"][0]["zones"][0]["range"] == [32800, 22750, 34550, 25350]
