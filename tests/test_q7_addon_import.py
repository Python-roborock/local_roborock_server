"""One-time Q7 import into the actual Home Assistant /data layout."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from roborock_local_server.bundled_backend.shared.runtime_credentials import RuntimeCredentialsStore
from roborock_local_server.q7_addon_import import apply_pending_q7_import


def _fixture(root: Path) -> tuple[Path, Path, Path]:
    config = root / "config"
    data = root / "data"
    runtime = data / "runtime"
    config.mkdir()
    runtime.mkdir(parents=True)
    (data / "state").mkdir()
    old_q7 = {"duid": "old", "model": "roborock.vacuum.sc05", "did": "123",
              "localkey": "old-local-key---"}
    non_q7 = {"duid": "other", "model": "roborock.vacuum.a08", "did": "456",
              "device_mqtt_usr": "other-user"}
    inventory = {"devices": [
        {"duid": "old", "model": "roborock.vacuum.sc05", "name": "Q7"},
        {"duid": "other", "model": "roborock.vacuum.a08", "name": "Other"},
    ], "received_devices": [{"duid": "old", "model": "roborock.vacuum.sc05"}]}
    credentials = {"schema_version": 2, "devices": [old_q7, non_q7]}
    (runtime / "web_api_inventory.json").write_text(json.dumps(inventory))
    (runtime / "runtime_credentials.json").write_text(json.dumps(credentials))
    pending = config / "q7-current-import.json"
    pending.write_text(json.dumps({
        "schema": "q7-cloud-identity-import-v1", "model": "roborock.vacuum.sc05",
        "duid": "current", "local_key": "current-key-1234", "sn": "serial",
        "fv": "03.01.74", "mqtt_clientid": "a" * 16, "mqtt_usr": "b" * 16,
        "mqtt_passwd": "c" * 32,
    }))
    return config, data, pending


def test_import_preserves_other_devices_and_keeps_did_unverified(tmp_path: Path) -> None:
    config, data, pending = _fixture(tmp_path)
    result = apply_pending_q7_import(config_dir=config, data_dir=data)
    assert result == {"applied": True, "duid_sha256_12": result["duid_sha256_12"],
                      "old_inventory_q7": 1, "old_runtime_q7": 1,
                      "non_q7_preserved": 1}
    assert not pending.exists()
    inventory = json.loads((data / "runtime" / "web_api_inventory.json").read_text())
    credentials = json.loads((data / "runtime" / "runtime_credentials.json").read_text())
    assert [item["duid"] for item in inventory["devices"]] == ["current", "other"]
    assert inventory["received_devices"] == []
    assert credentials["devices"][0] == {
        "duid": "other", "model": "roborock.vacuum.a08", "did": "456",
        "device_mqtt_usr": "other-user",
    }
    q7 = credentials["devices"][1]
    assert q7["duid"] == "current"
    assert q7["did"] == ""
    assert q7["localkey"] == "current-key-1234"
    assert q7["local_key_source"] == "inventory_cloud"
    assert q7["device_mqtt_pass"] == "c" * 32
    assert (data / "state" / "q7-current-import-backup" / "runtime_credentials.json").exists()
    assert apply_pending_q7_import(config_dir=config, data_dir=data) is None

    # The historical key-state DID must not be assigned before a real Q7
    # authenticates and publishes on its own rr/d/i topic.
    key_state = data / "state" / "device_key_state.json"
    key_state.write_text(json.dumps({"devices": {
        "123": {"pid": "roborock.vacuum.sc05"},
    }}))
    store = RuntimeCredentialsStore(
        data / "runtime" / "runtime_credentials.json",
        inventory_path=data / "runtime" / "web_api_inventory.json",
        key_state_file=key_state,
    )
    store.sync_inventory()
    assert store.resolve_device(duid="current")["did"] == ""
    assert store.resolve_device(duid="current")["local_key_source"] == "inventory_cloud"
    store.resolve_device_localkey(
        duid="current", model="roborock.vacuum.sc05", source="inventory_seed",
    )
    assert store.q7_migration_duids() == {"current"}
    store.ensure_device(
        did="current", device_mqtt_usr="b" * 16, device_mqtt_pass="c" * 32,
    )
    store.record_mqtt_topic(
        topic=f"rr/d/i/current/{'b' * 16}", direction="c2b",
        authenticated_username="b" * 16, device_credentials_verified=True,
    )
    assert store.verified_q7_migration_links() == {"current": "current"}
    assert len([item for item in store.devices() if item.get("did") == "current"]) == 1


def test_authenticated_q7_does_not_take_conflicting_device_topic(tmp_path: Path) -> None:
    config, data, _pending = _fixture(tmp_path)
    apply_pending_q7_import(config_dir=config, data_dir=data)
    store = RuntimeCredentialsStore(
        data / "runtime" / "runtime_credentials.json",
        inventory_path=data / "runtime" / "web_api_inventory.json",
    )
    store.sync_inventory()
    store.ensure_device(did="taken", device_mqtt_usr="other-device")
    store.record_mqtt_topic(
        topic=f"rr/d/i/taken/{'b' * 16}", direction="c2b",
        authenticated_username="b" * 16, device_credentials_verified=True,
    )
    assert store.verified_q7_migration_links() == {}
    assert store.resolve_device(did="taken")["device_mqtt_usr"] == "other-device"


def test_rejects_bad_payload_before_touching_runtime(tmp_path: Path) -> None:
    config, data, pending = _fixture(tmp_path)
    payload = json.loads(pending.read_text())
    payload["mqtt_passwd"] = "too-short"
    pending.write_text(json.dumps(payload))
    runtime = data / "runtime" / "runtime_credentials.json"
    before = runtime.read_bytes()
    with pytest.raises(ValueError, match="mqtt_passwd"):
        apply_pending_q7_import(config_dir=config, data_dir=data)
    assert runtime.read_bytes() == before
    assert pending.exists()
