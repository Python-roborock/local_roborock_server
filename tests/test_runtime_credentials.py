import json
from pathlib import Path

import pytest

from roborock_local_server.bundled_backend.shared.runtime_credentials import RuntimeCredentialsStore


def test_clear_mqtt_credentials_preserves_other_data_and_survives_reload(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"mqtt_usr": "bootstrap", "mqtt_passwd": "bootstrap-secret", "devices": [
        {"duid": "downstairs", "did": "123", "name": "Downstairs", "model": "a15", "localkey": "keep-key",
         "mqtt_usr": "old-user", "mqtt_password": "old-secret"},
        {"duid": "upstairs", "did": "456", "device_mqtt_usr": "other-user", "device_mqtt_pass": "other-secret"},
    ]}))
    store = RuntimeCredentialsStore(path)
    other = store.resolve_device(duid="upstairs")
    cleared = store.clear_device_mqtt_credentials(duid="downstairs")
    assert cleared["device_mqtt_usr"] == cleared["device_mqtt_pass"] == ""
    assert cleared["localkey"] == "keep-key"
    assert cleared["did"] == "123" and cleared["model"] == "a15"
    assert store.resolve_device(duid="upstairs") == other
    assert store.bootstrap_value("mqtt_passwd") == "bootstrap-secret"
    assert not store.verify_device_mqtt_credentials(username="old-user", password="old-secret")[0]
    assert list(tmp_path.iterdir()) == [path]  # No backup or temporary file remains.
    assert "old-secret" not in path.read_text() and "old-user" not in path.read_text()
    assert RuntimeCredentialsStore(path).resolve_device(duid="downstairs") == cleared
    with pytest.raises(KeyError):
        store.clear_device_mqtt_credentials(duid="123")  # No DID/model fallback.


def test_reset_blocks_old_topics_and_pending_pairing_but_allows_fresh_pairing(tmp_path):
    store = RuntimeCredentialsStore(tmp_path / "credentials.json")
    store.ensure_device(duid="downstairs", did="123", device_mqtt_usr="old-user", device_mqtt_pass="old-secret")
    reset = store.clear_device_mqtt_credentials(duid="downstairs")
    store = RuntimeCredentialsStore(store.path)
    store.record_mqtt_topic(topic="rr/d/i/123/old-user")
    assert store.recover_device_mqtt_password(username="old-user", password="old-secret") is None
    assert store.confirm_device_mqtt_credentials(did="123", username="old-user", password="old-secret") is None
    learned = store.confirm_device_mqtt_credentials(did="123", username="new-user", password="new-secret",
                                                   expected_reset_at=reset["device_mqtt_reset_at"])
    assert learned["device_mqtt_usr"] == "new-user"
    store.record_mqtt_topic(topic="rr/d/i/123/old-user")
    assert store.verify_device_mqtt_credentials(username="new-user", password="new-secret")[0]
    assert not store.verify_device_mqtt_credentials(username="old-user", password="old-secret")[0]


def test_reset_is_not_undone_by_merging_a_stale_did_record(tmp_path):
    store = RuntimeCredentialsStore(tmp_path / "credentials.json")
    store.ensure_device(duid="downstairs", localkey="keep-key")
    store.clear_device_mqtt_credentials(duid="downstairs")
    store.ensure_device(did="123", device_mqtt_usr="old-user", device_mqtt_pass="old-secret")
    merged = store.ensure_device(duid="downstairs", did="123", device_mqtt_usr="old-user")
    assert merged["device_mqtt_usr"] == merged["device_mqtt_pass"] == ""
    assert merged["localkey"] == "keep-key"


def test_failed_reset_preserves_disk_and_live_credentials(tmp_path, monkeypatch):
    import os
    store = RuntimeCredentialsStore(tmp_path / "credentials.json")
    before = store.ensure_device(duid="downstairs", device_mqtt_usr="user", device_mqtt_pass="secret")
    before_file = store.path.read_bytes()
    def fail_replace(*args):
        raise OSError("simulated disk failure")
    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError):
        store.clear_device_mqtt_credentials(duid="downstairs")
    assert store.resolve_device(duid="downstairs") == before
    assert store.path.read_bytes() == before_file
    assert list(tmp_path.iterdir()) == [store.path]


def test_ensure_device_merges_split_did_and_duid_records(tmp_path: Path) -> None:
    credentials_path = tmp_path / "runtime_credentials.json"
    credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "devices": [
                    {
                        "did": "1103821560705",
                        "duid": "",
                        "name": "",
                        "model": "",
                        "product_id": "",
                        "localkey": "",
                        "local_key_source": "",
                        "device_mqtt_usr": "mqtt-user-a",
                        "device_mqtt_pass": "",
                        "updated_at": "2026-03-16T00:22:31.225097+00:00",
                        "last_nc_at": "",
                        "last_mqtt_seen_at": "2026-03-16T00:22:31.225063+00:00",
                    },
                    {
                        "did": "",
                        "duid": "cloud-q7-a",
                        "name": "Q7 Upstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-a",
                        "localkey": "local-key-a",
                        "local_key_source": "inventory",
                        "device_mqtt_usr": "",
                        "device_mqtt_pass": "",
                        "updated_at": "2026-03-16T00:22:20.199941+00:00",
                        "last_nc_at": "",
                        "last_mqtt_seen_at": "",
                    },
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    store = RuntimeCredentialsStore(credentials_path)
    merged = store.ensure_device(
        did="1103821560705",
        duid="cloud-q7-a",
        device_mqtt_usr="mqtt-user-a",
        device_mqtt_pass="mqtt-pass-a",
        assign_localkey=False,
    )

    devices = store.devices()
    assert len(devices) == 1
    assert devices[0]["did"] == "1103821560705"
    assert devices[0]["duid"] == "cloud-q7-a"
    assert devices[0]["name"] == "Q7 Upstairs"
    assert devices[0]["model"] == "roborock.vacuum.sc05"
    assert devices[0]["product_id"] == "product-q7-a"
    assert devices[0]["localkey"] == "local-key-a"
    assert devices[0]["device_mqtt_usr"] == "mqtt-user-a"
    assert devices[0]["device_mqtt_pass"] == "mqtt-pass-a"
    assert merged["duid"] == "cloud-q7-a"


def test_backfill_device_mqtt_passwords_updates_only_known_usernames(tmp_path: Path) -> None:
    credentials_path = tmp_path / "runtime_credentials.json"
    credentials_path.write_text(
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
                        "device_mqtt_usr": "c25b14ceac358d2a",
                        "device_mqtt_pass": "",
                        "updated_at": "",
                        "last_nc_at": "",
                        "last_mqtt_seen_at": "",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    log_path = tmp_path / "mqtt_server.log"
    log_path.write_text(
        "\n".join(
            [
                "2026-04-17 16:20:32,393 [INFO] [conn 1670 c2b] CONNECT len=82 hex=105000044d51545404c2001e00106130313233393163623566386263393700106332356231346365616333353864326100206666383932326432346139613961663831663138663335646365653961356135",
                "2026-04-17 16:20:33,603 [INFO] [conn 1671 c2b] CONNECT len=82 hex=105000044d51545404c2001e00103664343439636537383337643366666600106464323131333035653264343837336200203762336533656138346663383333613937306464363432363032356162313436",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    store = RuntimeCredentialsStore(credentials_path)
    changed = store.backfill_device_mqtt_passwords(log_path)

    assert changed == 1
    device = store.resolve_device(duid="cloud-q7-a")
    assert device is not None
    assert device["device_mqtt_pass"] == "ff8922d24a9a9af81f18f35dcee9a5a5"
