import json
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server.bundled_backend.import_web_inventory_from_cloud import (
    _merge_existing_inventory_mutations,
)
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor
from shared.protocol_auth import ProtocolAuthStore, build_hawk_authorization

DUID = "6HL2zfniaoYYV01CkVuhkO"
_NONCES: list[int] = []
PATH = f"/user/devices/{DUID}"


def _build(tmp_path: Path):
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
                        "duid": DUID,
                        "name": "Old Name",
                        "model": "roborock.vacuum.a87",
                        "product_id": "5gUei3OIJIXVD3eD85Balg",
                        "local_key": "xPd5Dr8CGGqtdDlH",
                        "silentOtaSwitch": False,
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    paths.cloud_snapshot_path.write_text(
        json.dumps(
            {
                "user_data": {
                    "uid": 1001,
                    "token": "t",
                    "rruid": "r",
                    "rriot": {
                        "u": "hu",
                        "s": "hs",
                        "h": "hh",
                        "k": "hk",
                        "r": {"r": "US", "a": "https://api-us.roborock.com", "m": "ssl://m:8883", "l": "https://w"},
                    },
                },
                "home_data": {
                    "id": 1233716,
                    "name": "My Home",
                    "devices": [
                        {"duid": DUID, "name": "Cloud Name", "productId": "5gUei3OIJIXVD3eD85Balg", "silentOtaSwitch": False}
                    ],
                    "products": [
                        {"id": "5gUei3OIJIXVD3eD85Balg", "name": "Q", "model": "roborock.vacuum.a87", "category": "x"}
                    ],
                },
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
                        "duid": DUID,
                        "name": "Old Name",
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
    return config, paths


def _client(config, paths) -> TestClient:
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.refresh_inventory_state()
    return TestClient(supervisor.app)


def _headers(paths, method: str, path: str, form=None) -> dict[str, str]:
    user = ProtocolAuthStore(paths.cloud_snapshot_path).availability().user
    assert user is not None
    _NONCES.append(0)
    return {"Authorization": build_hawk_authorization(user=user, path=path, form_values=form, nonce=f"n{len(_NONCES)}")}


def _put(client, paths, path, data):
    return client.put(path, data=data, headers=_headers(paths, "PUT", path, data))


def _get(client, paths, path):
    return client.get(path, headers=_headers(paths, "GET", path))


def test_put_stores_name_and_switch_and_get_shows_them(tmp_path: Path) -> None:
    config, paths = _build(tmp_path)
    client = _client(config, paths)
    assert _get(client, paths, PATH).json()["data"]["name"] == "Cloud Name"

    response = _put(client, paths, PATH, {"name": "  Kitchen Bot  "})
    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True and body["data"]["name"] == "Kitchen Bot"

    _put(client, paths, PATH, {"silentOtaSwitch": "true"})
    data = _get(client, paths, PATH).json()["data"]
    assert data["name"] == "Kitchen Bot"
    assert data["silentOtaSwitch"] is True

    _put(client, paths, PATH, {"silentOtaSwitch": "false"})
    assert _get(client, paths, PATH).json()["data"]["silentOtaSwitch"] is False


def test_put_shows_in_home_data(tmp_path: Path) -> None:
    config, paths = _build(tmp_path)
    client = _client(config, paths)
    _put(client, paths, PATH, {"name": "Kitchen Bot", "silentOtaSwitch": "true"})
    home_path = "/v3/user/homes/1233716"
    devices = _get(client, paths, home_path).json()["data"]["devices"]
    assert devices[0]["name"] == "Kitchen Bot"
    assert devices[0]["silentOtaSwitch"] is True


def test_put_rejects_bad_values_and_ignores_other_fields(tmp_path: Path) -> None:
    config, paths = _build(tmp_path)
    client = _client(config, paths)
    _put(client, paths, PATH, {"silentOtaSwitch": "yes", "name": "   ", "localKey": "evil", "online": "false"})
    data = _get(client, paths, PATH).json()["data"]
    assert data["name"] == "Cloud Name"
    assert data["silentOtaSwitch"] is False
    assert data["localKey"] != "evil"
    _put(client, paths, PATH, {"name": "x" * 500})
    assert _get(client, paths, PATH).json()["data"]["name"] == "Cloud Name"
    assert "device_overrides" not in json.loads(paths.inventory_path.read_text(encoding="utf-8"))


def test_put_unknown_duid_stores_nothing(tmp_path: Path) -> None:
    config, paths = _build(tmp_path)
    client = _client(config, paths)
    other = "/user/devices/unknownduid"
    response = _put(client, paths, other, {"name": "Ghost"})
    assert response.status_code == 200
    assert response.json()["data"]["name"] != "Ghost"
    assert "device_overrides" not in json.loads(paths.inventory_path.read_text(encoding="utf-8"))


def test_override_survives_reload_and_cloud_import(tmp_path: Path) -> None:
    config, paths = _build(tmp_path)
    client = _client(config, paths)
    _put(client, paths, PATH, {"name": "Kitchen Bot", "silentOtaSwitch": "true"})
    stored = json.loads(paths.inventory_path.read_text(encoding="utf-8"))
    assert stored["device_overrides"][DUID] == {"name": "Kitchen Bot", "silentOtaSwitch": True}

    reloaded = _client(config, paths)
    data = _get(reloaded, paths, PATH).json()["data"]
    assert data["name"] == "Kitchen Bot" and data["silentOtaSwitch"] is True

    fresh = {"devices": [{"duid": DUID, "name": "Cloud Name", "silentOtaSwitch": False}]}
    merged = _merge_existing_inventory_mutations(fresh, stored)
    assert merged["devices"][0]["name"] == "Kitchen Bot"
    assert merged["devices"][0]["silentOtaSwitch"] is True
    assert merged["device_overrides"][DUID]["name"] == "Kitchen Bot"
