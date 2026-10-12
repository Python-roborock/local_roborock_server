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
    next_fire_time = payload["result"][0].pop("nextFireTime")
    assert next_fire_time.endswith("T13:03:00.000+00:00")
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
