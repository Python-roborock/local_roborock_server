import json
from pathlib import Path

from fastapi.testclient import TestClient
from roborock.data import HomeData, HomeDataSchedule

from conftest import write_release_config
from roborock_local_server.backend import _build_inventory
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor
from shared.protocol_auth import ProtocolAuthStore, build_hawk_authorization


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")


def _seed_cloud_snapshot(path: Path) -> None:
    _write_json(
        path,
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
            },
            "home_data": {"id": 1233716, "name": "My Home"},
        },
    )


def _hawk_headers(snapshot_path: Path, path: str) -> dict[str, str]:
    user = ProtocolAuthStore(snapshot_path).availability().user
    assert user is not None
    return {
        "Authorization": build_hawk_authorization(
            user=user,
            path=path,
            nonce=f"nonce-{path.replace('/', '-')}",
        )
    }


def test_device_jobs_endpoint_returns_imported_schedules(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)

    device_id = "6HL2zfniaoYYV01CkVuhkO"
    schedule = {
        "id": "3878757",
        "cron": "03 13 15 12 ?",
        "repeated": "false",
        "enabled": 1,
        "type": "clean",
        "param": {
            "id": 1,
            "method": "server_scheduled_start",
            "params": [
                {
                    "repeat": 1,
                    "water_box_mode": 202,
                    "segments": "0",
                    "fan_power": 102,
                    "mop_mode": 300,
                    "clean_mop": 1,
                    "map_index": -1,
                    "name": "1765735413736",
                }
            ],
        },
    }
    _write_json(
        paths.inventory_path,
        {
            "home": {"id": 1233716, "name": "My Home"},
            "devices": [{"duid": device_id, "name": "Roborock Qrevo"}],
            "schedules": {device_id: [schedule]},
        },
    )
    _seed_cloud_snapshot(paths.cloud_snapshot_path)

    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.refresh_inventory_state()

    client = TestClient(supervisor.app)
    path = f"/user/devices/{device_id}/jobs"
    response = client.get(path, headers=_hawk_headers(paths.cloud_snapshot_path, path))
    assert response.status_code == 200

    payload = response.json()
    assert payload["success"] is True
    assert payload["data"] == payload["result"]
    # nextFireTime is computed from the cron against "now", so check its shape, not its value.
    # No timezone is configured, so the cron runs in the zone the robot is told (America/New_York):
    # 13:03 local on Dec 15 is 18:03Z.
    next_fire_time = payload["result"][0].pop("nextFireTime")
    assert next_fire_time.endswith("T18:03:00.000+00:00")
    assert payload["result"] == [
        {
            **schedule,
            "id": 3878757,
            "repeated": False,
            "enabled": True,
        }
    ]

    parsed_schedule = HomeDataSchedule.from_dict(payload["result"][0])
    assert parsed_schedule is not None
    assert parsed_schedule.id == 3878757
    assert parsed_schedule.repeated is False
    assert parsed_schedule.enabled is True


def test_cloud_inventory_build_preserves_device_schedules() -> None:
    home_data = HomeData.from_dict(
        {
            "id": 1233716,
            "name": "My Home",
            "devices": [
                {
                    "duid": "6HL2zfniaoYYV01CkVuhkO",
                    "name": "Roborock Qrevo",
                    "productId": "product-1",
                }
            ],
            "products": [
                {
                    "id": "product-1",
                    "name": "Roborock Qrevo",
                    "model": "roborock.vacuum.a87",
                    "category": "robot.vacuum.cleaner",
                }
            ],
        }
    )
    assert home_data is not None

    schedule = {
        "id": 3878757,
        "cron": "03 13 15 12 ?",
        "repeated": False,
        "enabled": True,
        "param": {"id": 1, "method": "server_scheduled_start", "params": [{"segments": "0"}]},
    }

    inventory = _build_inventory(
        home_data,
        schedules={"6HL2zfniaoYYV01CkVuhkO": [schedule], "ignored": ["not-a-dict"]},
    )

    assert inventory["schedules"] == {
        "6HL2zfniaoYYV01CkVuhkO": [schedule],
        "ignored": [],
    }


def _jobs_client(tmp_path: Path, device_id: str, schedules: list[dict[str, object]]):
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    _write_json(
        paths.inventory_path,
        {
            "home": {"id": 1233716, "name": "My Home"},
            "devices": [{"duid": device_id, "name": "Roborock Qrevo"}],
            "schedules": {device_id: schedules},
        },
    )
    _seed_cloud_snapshot(paths.cloud_snapshot_path)
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.refresh_inventory_state()
    return TestClient(supervisor.app), paths


def _signed_json(paths, path: str, body: dict[str, object]) -> tuple[bytes, dict[str, str]]:
    raw = json.dumps(body, separators=(",", ":")).encode()
    user = ProtocolAuthStore(paths.cloud_snapshot_path).availability().user
    assert user is not None
    headers = {
        # Hawk rejects replayed nonces, and _hawk_headers() uses nonce-<path> for plain requests.
        "Authorization": build_hawk_authorization(
            user=user, path=path, json_body=raw, nonce=f"write-{path.replace('/', '-')}-{len(raw)}"
        ),
        "Content-Type": "application/json",
    }
    return raw, headers


def test_jobs_can_be_created_updated_and_deleted_over_http(tmp_path: Path) -> None:
    device_id = "6HL2zfniaoYYV01CkVuhkO"
    existing = {
        "id": 3549431,
        "cron": "00 11 ? * 1,3,5",
        "timeZoneId": "America/New_York",
        "repeated": True,
        "enabled": True,
        "param": {
            "id": 1,
            "method": "server_scheduled_start",
            "params": [{"repeat": 1, "water_box_mode": 203, "segments": "0", "fan_power": 104, "mop_mode": 300}],
        },
    }
    client, paths = _jobs_client(tmp_path, device_id, [existing])
    collection = f"/user/devices/{device_id}/jobs"

    body, headers = _signed_json(paths, collection, {"cron": "30 7 * * 1,2", "enabled": True})
    created = client.post(collection, content=body, headers=headers)
    assert created.status_code == 200
    assert created.json()["success"] is True
    new_id = created.json()["result"]["id"]

    listed = client.get(collection, headers=_hawk_headers(paths.cloud_snapshot_path, collection)).json()["result"]
    assert {job["id"] for job in listed} == {3549431, new_id}
    assert all(job.get("nextFireTime") for job in listed)

    item = f"{collection}/3549431"
    body, headers = _signed_json(paths, item, {"cron": "15 9 ? * 1,3,5", "enabled": False})
    updated = client.put(item, content=body, headers=headers)
    assert updated.status_code == 200
    result = updated.json()["result"]
    assert (result["cron"], result["enabled"]) == ("15 9 ? * 1,3,5", False)
    # Vac/mop settings are untouched by a cron/enabled edit.
    assert result["param"]["params"][0]["mop_mode"] == 300

    deleted = client.delete(item, headers=_hawk_headers(paths.cloud_snapshot_path, item))
    assert deleted.status_code == 200 and deleted.json()["success"] is True
    user = ProtocolAuthStore(paths.cloud_snapshot_path).availability().user
    assert user is not None
    second_list = {"Authorization": build_hawk_authorization(user=user, path=collection, nonce="second-list")}
    remaining = client.get(collection, headers=second_list).json()["result"]
    assert [job["id"] for job in remaining] == [new_id]


def test_creating_a_job_with_a_bad_cron_is_rejected(tmp_path: Path) -> None:
    device_id = "6HL2zfniaoYYV01CkVuhkO"
    client, paths = _jobs_client(tmp_path, device_id, [])
    collection = f"/user/devices/{device_id}/jobs"
    body, headers = _signed_json(paths, collection, {"cron": "nonsense"})
    response = client.post(collection, content=body, headers=headers)
    assert response.json()["success"] is False
    assert response.json()["code"] == 400
