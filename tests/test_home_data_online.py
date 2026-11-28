import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
from roborock.data import HomeData

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor
from shared.protocol_auth import ProtocolAuthStore, build_hawk_authorization


def _seed_cloud_snapshot(path: Path, home_data: dict[str, object]) -> None:
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
                },
                "home_data": home_data,
            }
        )
        + "\n",
        encoding="utf-8",
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


def test_home_data_marks_runtime_connected_device_online_via_runtime_credentials(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)

    paths.runtime_dir.mkdir(parents=True, exist_ok=True)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "home": {"id": 1233716, "name": "My Home"},
                "devices": [
                    {
                        "duid": "1OVJHS7cL6XxkYkoOGr2Hw",
                        "name": "S7",
                        "model": "roborock.vacuum.a15",
                        "product_id": "1YYW18rpgyAJTISwb1NM91",
                        "local_key": "GTWJJAA457z43dur",
                        "online": False,
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    _seed_cloud_snapshot(
        paths.cloud_snapshot_path,
        {
            "id": 1233716,
            "name": "My Home",
            "devices": [
                {
                    "duid": "1OVJHS7cL6XxkYkoOGr2Hw",
                    "name": "S7",
                    "productId": "1YYW18rpgyAJTISwb1NM91",
                }
            ],
            "products": [
                {
                    "id": "1YYW18rpgyAJTISwb1NM91",
                    "name": "S7",
                    "model": "roborock.vacuum.a15",
                    "category": "robot.vacuum.cleaner",
                }
            ],
        },
    )
    paths.runtime_credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "devices": [
                    {
                        "did": "1103811971559",
                        "duid": "1OVJHS7cL6XxkYkoOGr2Hw",
                        "name": "S7",
                        "model": "roborock.vacuum.a15",
                        "product_id": "1YYW18rpgyAJTISwb1NM91",
                        "localkey": "GTWJJAA457z43dur",
                        "local_key_source": "inventory_cloud",
                        "device_mqtt_usr": "dd211305e2d4873b",
                        "updated_at": "2026-03-17T22:50:00+00:00",
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
    supervisor.runtime_state.record_mqtt_connection(conn_id="s7-live", client_ip="testclient", client_port=1883)
    supervisor.runtime_state.record_mqtt_message(
        conn_id="s7-live",
        direction="c2b",
        topic="rr/d/i/1103811971559/dd211305e2d4873b",
        payload_preview="{}",
    )

    client = TestClient(supervisor.app)
    response = client.get("/v3/user/homes/1233716", headers=_hawk_headers(paths.cloud_snapshot_path, "/v3/user/homes/1233716"))
    assert response.status_code == 200

    home_data = response.json()["data"]
    s7 = next(device for device in home_data["devices"] if device["duid"] == "1OVJHS7cL6XxkYkoOGr2Hw")
    assert s7["online"] is True


def test_home_data_response_does_not_emit_empty_snake_case_received_devices(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)

    paths.runtime_dir.mkdir(parents=True, exist_ok=True)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "home": {"id": 1316433, "name": "My Home"},
                "received_devices": [
                    {
                        "duid": "6HL2zfniaoYYV01CkVuhkO",
                        "name": "Roborock Qrevo MaxV 2",
                        "model": "roborock.vacuum.a87",
                        "product_id": "5gUei3OIJIXVD3eD85Balg",
                        "local_key": "xPd5Dr8CGGqtdDlH",
                        "online": True,
                        "pv": "1.0",
                        "share": True,
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    _seed_cloud_snapshot(
        paths.cloud_snapshot_path,
        {
            "id": 1316433,
            "name": "My Home",
            "receivedDevices": [
                {
                    "duid": "6HL2zfniaoYYV01CkVuhkO",
                    "name": "Roborock Qrevo MaxV 2",
                    "productId": "5gUei3OIJIXVD3eD85Balg",
                    "share": True,
                }
            ],
            "products": [
                {
                    "id": "5gUei3OIJIXVD3eD85Balg",
                    "name": "Roborock Qrevo MaxV",
                    "model": "roborock.vacuum.a87",
                    "category": "robot.vacuum.cleaner",
                }
            ],
        },
    )
    paths.runtime_credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "devices": [
                    {
                        "did": "1103821560705",
                        "duid": "6HL2zfniaoYYV01CkVuhkO",
                        "name": "Roborock Qrevo MaxV 2",
                        "model": "roborock.vacuum.a87",
                        "product_id": "5gUei3OIJIXVD3eD85Balg",
                        "localkey": "xPd5Dr8CGGqtdDlH",
                        "local_key_source": "inventory_cloud",
                        "device_mqtt_usr": "c25b14ceac358d2a",
                        "updated_at": "2026-03-17T22:50:00+00:00",
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

    client = TestClient(supervisor.app)
    response = client.get("/v3/user/homes/1316433", headers=_hawk_headers(paths.cloud_snapshot_path, "/v3/user/homes/1316433"))
    assert response.status_code == 200

    payload = response.json()
    assert "received_devices" not in payload["data"]
    assert "received_devices" not in payload["result"]
    assert payload["data"]["receivedDevices"] == []
    assert [device["duid"] for device in payload["data"]["devices"]] == ["6HL2zfniaoYYV01CkVuhkO"]

    parsed_home = HomeData.from_dict(payload["result"])
    assert parsed_home is not None
    assert len(parsed_home.devices) == 1
    assert parsed_home.devices[0].duid == "6HL2zfniaoYYV01CkVuhkO"
    assert parsed_home.received_devices == []
    assert len(parsed_home.device_products) == 1
    assert "6HL2zfniaoYYV01CkVuhkO" in parsed_home.device_products


@pytest.mark.parametrize(
    ("region", "timezone", "device_timezone", "expected"),
    [
        ("eu", "", None, "Europe/Berlin"),
        ("us", "", None, "America/New_York"),
        ("eu", "Europe/Vienna", None, "Europe/Vienna"),
        ("eu", "", "Asia/Tokyo", "Asia/Tokyo"),
    ],
)
def test_device_time_zone_defaults_to_the_server_time_zone(
    tmp_path: Path,
    region: str,
    timezone: str,
    device_timezone: str | None,
    expected: str,
) -> None:
    config_file = write_release_config(tmp_path, region=region, timezone=timezone)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)

    duid = "6HL2zfniaoYYV01CkVuhkO"
    device: dict[str, object] = {
        "duid": duid,
        "name": "Roborock Qrevo MaxV",
        "model": "roborock.vacuum.a87",
        "product_id": "5gUei3OIJIXVD3eD85Balg",
        "local_key": "xPd5Dr8CGGqtdDlH",
    }
    if device_timezone is not None:
        device["timezone"] = device_timezone

    paths.runtime_dir.mkdir(parents=True, exist_ok=True)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps({"home": {"id": 1316433, "name": "My Home"}, "devices": [device]}) + "\n",
        encoding="utf-8",
    )
    _seed_cloud_snapshot(paths.cloud_snapshot_path, {"id": 1316433, "name": "My Home"})
    paths.runtime_credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "devices": [
                    {
                        "did": "1103821560705",
                        "duid": duid,
                        "name": "Roborock Qrevo MaxV",
                        "model": "roborock.vacuum.a87",
                        "product_id": "5gUei3OIJIXVD3eD85Balg",
                        "localkey": "xPd5Dr8CGGqtdDlH",
                        "local_key_source": "inventory_cloud",
                        "device_mqtt_usr": "c25b14ceac358d2a",
                        "updated_at": "2026-03-17T22:50:00+00:00",
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
    client = TestClient(supervisor.app)

    home_path = "/v3/user/homes/1316433"
    home_response = client.get(home_path, headers=_hawk_headers(paths.cloud_snapshot_path, home_path))
    assert home_response.status_code == 200
    home_devices = home_response.json()["result"]["devices"]
    assert [item["timeZoneId"] for item in home_devices] == [expected]

    detail_path = f"/user/devices/{duid}"
    detail_response = client.get(detail_path, headers=_hawk_headers(paths.cloud_snapshot_path, detail_path))
    assert detail_response.status_code == 200
    assert detail_response.json()["data"]["timeZoneId"] == expected


def test_device_detail_uses_runtime_connection_and_preserves_inventory_fields(tmp_path: Path) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)

    paths.runtime_dir.mkdir(parents=True, exist_ok=True)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "home": {"id": 1233716, "name": "My Home"},
                "devices": [
                    {
                        "duid": "6HL2zfniaoYYV01CkVuhkO",
                        "name": "Roborock Qrevo MaxV 2",
                        "model": "roborock.vacuum.a87",
                        "product_id": "5gUei3OIJIXVD3eD85Balg",
                        "local_key": "xPd5Dr8CGGqtdDlH",
                        "online": False,
                        "deviceStatus": {"121": 10, "122": 99},
                        "extra": "{\"RRMonitorPrivacyVersion\": \"1\"}",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    _seed_cloud_snapshot(
        paths.cloud_snapshot_path,
        {
            "id": 1233716,
            "name": "My Home",
            "devices": [
                {
                    "duid": "6HL2zfniaoYYV01CkVuhkO",
                    "name": "Roborock Qrevo MaxV 2",
                    "productId": "5gUei3OIJIXVD3eD85Balg",
                    "extra": "{\"RRMonitorPrivacyVersion\": \"1\"}",
                }
            ],
            "products": [
                {
                    "id": "5gUei3OIJIXVD3eD85Balg",
                    "name": "Roborock Qrevo MaxV",
                    "model": "roborock.vacuum.a87",
                    "category": "RoborockCategory.VACUUM",
                }
            ],
        },
    )
    paths.runtime_credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "devices": [
                    {
                        "did": "1103821560705",
                        "duid": "6HL2zfniaoYYV01CkVuhkO",
                        "name": "Roborock Qrevo MaxV 2",
                        "model": "roborock.vacuum.a87",
                        "product_id": "5gUei3OIJIXVD3eD85Balg",
                        "localkey": "xPd5Dr8CGGqtdDlH",
                        "local_key_source": "inventory_cloud",
                        "device_mqtt_usr": "c25b14ceac358d2a",
                        "updated_at": "2026-03-17T22:50:00+00:00",
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
    supervisor.runtime_state.record_mqtt_connection(conn_id="qrevo-live", client_ip="testclient", client_port=1883)
    supervisor.runtime_state.record_mqtt_message(
        conn_id="qrevo-live",
        direction="c2b",
        topic="rr/d/i/1103821560705/c25b14ceac358d2a",
        payload_preview="{}",
    )

    client = TestClient(supervisor.app)
    response = client.get(
        "/user/devices/6HL2zfniaoYYV01CkVuhkO",
        headers=_hawk_headers(paths.cloud_snapshot_path, "/user/devices/6HL2zfniaoYYV01CkVuhkO"),
    )
    assert response.status_code == 200

    device_data = response.json()["data"]
    assert device_data["online"] is True
    assert device_data["homeId"] == 1233716
    assert device_data["deviceStatus"] == {"121": 10, "122": 99}


@pytest.mark.parametrize("home_path", ["/v3/user/homes/1233716", "/v4/user/homes/1233716"])
def test_home_data_preserves_last_working_app_contract(tmp_path: Path, home_path: str) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)

    paths.runtime_dir.mkdir(parents=True, exist_ok=True)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "home": {"id": 1233716, "name": "My Home"},
                "devices": [
                    {
                        "duid": "6HL2zfniaoYYV01CkVuhkO",
                        "name": "Roborock Qrevo MaxV 2",
                        "model": "roborock.vacuum.a87",
                        "product_id": "5gUei3OIJIXVD3eD85Balg",
                        "local_key": "xPd5Dr8CGGqtdDlH",
                        "online": False,
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    _seed_cloud_snapshot(
        paths.cloud_snapshot_path,
        {
            "id": 1233716,
            "name": "My Home",
            "devices": [
                {
                    "duid": "6HL2zfniaoYYV01CkVuhkO",
                    "name": "Roborock Qrevo MaxV 2",
                    "productId": "5gUei3OIJIXVD3eD85Balg",
                    "extra": "{\"RRMonitorPrivacyVersion\": \"1\"}",
                    "featureSet": "2233384992473071",
                    "newFeatureSet": "7",
                    "f": False,
                    "share": False,
                    "createTime": 1712144203,
                }
            ],
            "products": [
                {
                    "id": "5gUei3OIJIXVD3eD85Balg",
                    "name": "Roborock Qrevo MaxV",
                    "model": "roborock.vacuum.a87",
                    "category": "robot.vacuum.cleaner",
                }
            ],
        },
    )
    paths.runtime_credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "devices": [
                    {
                        "did": "1103821560705",
                        "duid": "6HL2zfniaoYYV01CkVuhkO",
                        "name": "Roborock Qrevo MaxV 2",
                        "model": "roborock.vacuum.a87",
                        "product_id": "5gUei3OIJIXVD3eD85Balg",
                        "localkey": "xPd5Dr8CGGqtdDlH",
                        "local_key_source": "inventory_cloud",
                        "device_mqtt_usr": "c25b14ceac358d2a",
                        "updated_at": "2026-03-17T22:50:00+00:00",
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

    client = TestClient(supervisor.app)
    response = client.get(home_path, headers=_hawk_headers(paths.cloud_snapshot_path, home_path))
    assert response.status_code == 200

    home_data = response.json()["data"]
    assert home_data["receivedDevices"] == []

    product = home_data["products"][0]
    assert set(product) == {"id", "name", "model", "category", "code", "iconUrl"}
    assert product["code"] == "a87"
    assert product["iconUrl"] == ""

    device = home_data["devices"][0]
    assert set(device) == {
        "duid",
        "name",
        "localKey",
        "productId",
        "fv",
        "pv",
        "activeTime",
        "timeZoneId",
        "online",
        "sn",
        "extra",
        "featureSet",
        "newFeatureSet",
        "f",
        "share",
        "createTime",
    }
    assert device["localKey"] == "xPd5Dr8CGGqtdDlH"
    assert device["productId"] == "5gUei3OIJIXVD3eD85Balg"
    assert "local_key" not in device
    assert "product_id" not in device


@pytest.mark.parametrize("home_path", ["/v3/user/homes/1233716", "/v4/user/homes/1233716"])
def test_home_data_uses_firmware_version_reported_by_onboarded_device(tmp_path: Path, home_path: str) -> None:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)

    paths.runtime_dir.mkdir(parents=True, exist_ok=True)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "home": {"id": 1233716, "name": "My Home"},
                "devices": [
                    {
                        "duid": "1103844865396",
                        "did": "1103844865396",
                        "name": "Roborock Qrevo 2 Pro",
                        "model": "roborock.vacuum.a294",
                        "product_id": "local_a294",
                        "local_key": "aBcDeFgHiJkLmNoP",
                        "source": "onboarding",
                    },
                    {
                        "duid": "6HL2zfniaoYYV01CkVuhkO",
                        "name": "Roborock S7",
                        "model": "roborock.vacuum.a15",
                        "product_id": "5gUei3OIJIXVD3eD85Balg",
                        "local_key": "xPd5Dr8CGGqtdDlH",
                        "fv": "02.16.12",
                    },
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    _seed_cloud_snapshot(paths.cloud_snapshot_path, {"id": 1233716, "name": "My Home", "devices": []})

    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.refresh_inventory_state()

    assert supervisor.record_reported_firmware("1103844865396", "02.44.86") is True
    # An unchanged version is not written again, and cloud-imported records keep their own fv.
    assert supervisor.record_reported_firmware("1103844865396", "02.44.86") is False
    assert supervisor.record_reported_firmware("6HL2zfniaoYYV01CkVuhkO", "02.99.99") is False

    client = TestClient(supervisor.app)
    response = client.get(home_path, headers=_hawk_headers(paths.cloud_snapshot_path, home_path))
    assert response.status_code == 200

    firmware_by_duid = {device["duid"]: device["fv"] for device in response.json()["data"]["devices"]}
    assert firmware_by_duid["1103844865396"] == "02.44.86"
    inventory = json.loads(paths.inventory_path.read_text(encoding="utf-8"))
    assert {device["duid"]: device.get("fv") for device in inventory["devices"]} == {
        "1103844865396": "02.44.86",
        "6HL2zfniaoYYV01CkVuhkO": "02.16.12",
    }
