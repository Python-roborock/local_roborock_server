"""Admin-only, dump-free Q7 MQTT credential preparation."""

import json
import hashlib
import logging
import re
from pathlib import Path

from fastapi.testclient import TestClient
import httpx

from conftest import write_release_config
from scripts import q7_migration_ota_builder, q7_owner_ota, q7_prepare_migration
from scripts.q7_migration_ota_builder import inspect
from roborock_local_server.bundled_backend.mqtt_broker_server.topic_bridge import (
    CloudTopicKey,
    DeviceTopicKey,
    MqttTopicBridge,
)
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor
from roborock_local_server.bundled_backend.mqtt_tls_proxy_server.server import MqttTlsProxy


def _client(tmp_path: Path, *, model: str = "roborock.vacuum.sc05",
            did: str = "",
            localkey: str = "0123456789abcdef",
            local_key_source: str = "inventory_cloud",
            mqtt_usr: str = "",
            split_cloud_key: str | None = None) -> tuple[TestClient, ReleaseSupervisor]:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    paths.runtime_credentials_path.parent.mkdir(parents=True, exist_ok=True)
    devices = [{
                "did": did,
                "duid": "synthetic-q7-duid",
                "model": model,
                "localkey": localkey,
                "local_key_source": local_key_source,
                "device_mqtt_usr": mqtt_usr,
            }]
    if split_cloud_key is not None:
        devices.append({
            "did": "",
            "duid": "separate-cloud-duid",
            "model": "roborock.vacuum.sc05",
            "localkey": split_cloud_key,
            "local_key_source": "inventory_cloud",
        })
    paths.runtime_credentials_path.write_text(
        json.dumps({"schema_version": 2, "devices": devices}) + "\n",
        encoding="utf-8",
    )
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    return TestClient(supervisor.app), supervisor


def _login(client: TestClient) -> None:
    response = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert response.status_code == 200


def _publish_packet(topic: str) -> bytes:
    encoded = topic.encode("ascii")
    body = len(encoded).to_bytes(2, "big") + encoded + b"{}"
    assert len(body) < 128
    return bytes((0x30, len(body))) + body


def test_no_dump_owner_handoff_formats_agree_across_server_and_tools(tmp_path: Path, monkeypatch) -> None:
    """One synthetic owner can prepare, build, and preflight a URL update."""
    app_client, _supervisor = _client(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        response = app_client.request(
            request.method, request.url.path, content=request.content,
            headers={"content-type": "application/json"},
        )
        return httpx.Response(response.status_code, content=response.content, headers=response.headers)

    original_client = httpx.Client
    monkeypatch.setattr(
        q7_prepare_migration.httpx, "Client",
        lambda **kwargs: original_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    config_path = tmp_path / "private" / "migration.json"
    q7_prepare_migration.prepare(
        server="https://local.test:555", duid="synthetic-q7-duid",
        api_url="https://local.test:555", mqtt_url="ssl://local.test:8881",
        out=config_path, admin_password="correct horse battery staple",
    )
    config = json.loads(config_path.read_text(encoding="utf-8"))
    profile = tmp_path / "profile"
    profile.mkdir()
    blobs = {
        "ota-key.bin": b"synthetic-key-12",
        "return.sh": b"#!/bin/sh\necho normal-boot\n",
        "editor.sh": b"#!/bin/sh\necho edit-existing-iot\n",
    }
    hashes = {name: hashlib.sha256(blob).hexdigest() for name, blob in blobs.items()}
    for name, blob in blobs.items():
        (profile / name).write_bytes(blob)
    (profile / "manifest.json").write_text(json.dumps({
        "schema": q7_migration_ota_builder.PROFILE_030180_SCHEMA,
        "model": "roborock.vacuum.sc05",
        "firmware_version": "03.01.80",
        "file_sha256": hashes,
    }))
    monkeypatch.setattr(q7_migration_ota_builder, "PROFILE_030180_HASHES", hashes)
    artifact = tmp_path / "candidate"
    metadata = q7_migration_ota_builder.build(config, profile, artifact)
    migration = inspect(artifact)[1]
    assert migration["target_firmware"] == "03.01.80"
    assert metadata["preflight"] == migration["preflight"]
    assert q7_owner_ota.cloud_key_matches_server_import(
        migration["preflight"], duid="synthetic-q7-duid", local_key="0123456789abcdef"
    )
    assert not q7_owner_ota.cloud_key_matches_server_import(
        migration["preflight"], duid="synthetic-q7-duid", local_key="fedcba9876543210"
    )


def test_q7_migration_credentials_are_admin_only_idempotent_and_persisted(tmp_path: Path, monkeypatch) -> None:
    client, supervisor = _client(tmp_path)
    route = "/admin/api/q7/migration-credentials"
    request = {"duid": "synthetic-q7-duid"}
    assert client.post(route, json=request).status_code == 401
    _login(client)

    first = client.post(route, json=request)
    assert first.status_code == 200
    body = first.json()
    assert body["did"] == "" and body["duid"] == request["duid"]
    assert "localkey" not in body
    assert body["local_key_sha256"] == hashlib.sha256(b"0123456789abcdef").hexdigest()
    for key, size in (("mqtt_clientid", 16), ("mqtt_usr", 16), ("mqtt_passwd", 32)):
        assert re.fullmatch(rf"[0-9a-f]{{{size}}}", body[key])

    second = client.post(route, json=request)
    assert second.status_code == 200
    assert {key: second.json()[key] for key in ("mqtt_clientid", "mqtt_usr", "mqtt_passwd")} == {
        key: body[key] for key in ("mqtt_clientid", "mqtt_usr", "mqtt_passwd")
    }
    stored = supervisor.runtime_credentials.resolve_device(duid=request["duid"])
    assert stored is not None
    assert stored["migration_mqtt_clientid"] == body["mqtt_clientid"]
    assert stored["device_mqtt_usr"] == body["mqtt_usr"]
    assert stored["device_mqtt_pass"] == body["mqtt_passwd"]
    authorized, reason, _device = supervisor.runtime_credentials.verify_device_mqtt_credentials(
        username=body["mqtt_usr"], password=body["mqtt_passwd"]
    )
    assert authorized and reason == "device_mqtt_user"

    bridge = MqttTopicBridge(
        host="127.0.0.1", port=1883,
        logger=logging.getLogger("test.q7_migration_bridge"),
        runtime_credentials=supervisor.runtime_credentials,
        runtime_state=supervisor.runtime_state,
        inventory_path=supervisor.paths.inventory_path,
    )
    supervisor.paths.inventory_path.write_text(
        json.dumps({"devices": [{"duid": request["duid"], "model": "roborock.vacuum.sc05"}]}),
        encoding="utf-8",
    )
    # Merely opening the admin vacuum list must not erase the cloud key's
    # provenance and silently disable migration routing.
    assert client.get("/admin/api/vacuums").status_code == 200
    assert supervisor.runtime_credentials.resolve_device(duid=request["duid"])["local_key_source"] == "inventory_cloud"
    monkeypatch.setattr(supervisor.runtime_state, "key_models_by_did", lambda: {
        "incorrect-model-inferred-did": "roborock.vacuum.sc05"
    })
    other_device = DeviceTopicKey(did="unrelated-did", mqtt_usr="unrelated-user")
    migrated_device = DeviceTopicKey(did="1234567890123", mqtt_usr=body["mqtt_usr"])
    cloud_topic = CloudTopicKey(rriot_u="app-user", mqtt_username="app-mqtt-user", duid=request["duid"])
    bridge._remember_device_seen(other_device)
    bridge._remember_device_seen(migrated_device)
    assert bridge._resolve_device_for_cloud(cloud_topic) is None
    assert request["duid"] not in bridge._duid_to_did

    supervisor.runtime_credentials.record_mqtt_topic(topic=migrated_device.topic_out, direction="b2c")
    assert supervisor.runtime_credentials.resolve_device(duid=request["duid"])["did"] == ""
    supervisor.runtime_credentials.record_mqtt_topic(topic=migrated_device.topic_in, direction="c2b")
    assert supervisor.runtime_credentials.resolve_device(duid=request["duid"])["did"] == ""
    supervisor.runtime_credentials.record_mqtt_topic(
        topic=migrated_device.topic_in,
        direction="c2b",
        authenticated_username="another-device",
        device_credentials_verified=True,
    )
    assert supervisor.runtime_credentials.resolve_device(duid=request["duid"])["did"] == ""
    supervisor.runtime_credentials.record_mqtt_topic(
        topic=migrated_device.topic_in,
        direction="c2b",
        authenticated_username=body["mqtt_usr"],
        device_credentials_verified=True,
    )
    linked = supervisor.runtime_credentials.resolve_device(duid=request["duid"])
    assert linked is not None and linked["did"] == migrated_device.did
    assert linked["migration_did_verified"] == "1"
    bridge._last_duid_map_refresh_monotonic = 0.0
    assert bridge._resolve_device_for_cloud(cloud_topic) == migrated_device
    assert len([item for item in supervisor.runtime_credentials.devices() if item["did"] == migrated_device.did]) == 1
    monkeypatch.setattr(supervisor.runtime_credentials, "_load_key_models_by_did", lambda: {
        "incorrect-model-inferred-did": "roborock.vacuum.sc05"
    })
    supervisor.runtime_credentials.sync_inventory()
    assert supervisor.runtime_credentials.resolve_device(duid=request["duid"])["did"] == migrated_device.did


def test_q7_migration_credentials_reject_wrong_identity_or_existing_credentials(tmp_path: Path) -> None:
    client, _supervisor = _client(tmp_path, mqtt_usr="existing-device-user")
    _login(client)
    route = "/admin/api/q7/migration-credentials"
    assert client.post(route, json={"duid": "wrong-duid"}).status_code == 404
    assert client.post(route, json={"did": "unknown", "duid": "synthetic-q7-duid"}).status_code == 400
    blocked = client.post(route, json={"duid": "synthetic-q7-duid"})
    assert blocked.status_code == 400
    assert "non-migration" in blocked.json()["error"]


def test_q7_authenticated_duid_topic_replaces_stale_numeric_did(tmp_path: Path) -> None:
    client, supervisor = _client(tmp_path, did="1234567890123")
    _login(client)
    response = client.post("/admin/api/q7/migration-credentials", json={"duid": "synthetic-q7-duid"})
    assert response.status_code == 200
    username = response.json()["mqtt_usr"]
    store = supervisor.runtime_credentials

    def publish(did: str) -> None:
        store.record_mqtt_topic(
            topic=f"rr/d/i/{did}/{username}", direction="c2b",
            authenticated_username=username, device_credentials_verified=True,
        )

    publish("1234567890123")
    assert store.verified_q7_migration_links() == {"synthetic-q7-duid": "1234567890123"}
    publish("unrelated-topic-id")
    assert store.verified_q7_migration_links() == {"synthetic-q7-duid": "1234567890123"}
    # Recover records written by releases where an admin inventory read
    # downgraded source provenance after the migration was reserved.
    store._devices[0]["local_key_source"] = "inventory"
    store._save_locked()
    publish("synthetic-q7-duid")
    assert store.verified_q7_migration_links() == {"synthetic-q7-duid": "synthetic-q7-duid"}
    assert store.resolve_device(duid="synthetic-q7-duid")["local_key_source"] == "inventory_cloud"

    bridge = MqttTopicBridge(
        host="127.0.0.1", port=1883, logger=logging.getLogger("test.q7_duid_rebind"),
        runtime_credentials=store, runtime_state=supervisor.runtime_state,
        inventory_path=supervisor.paths.inventory_path,
    )
    observed = DeviceTopicKey(did="synthetic-q7-duid", mqtt_usr=username)
    cloud = CloudTopicKey(rriot_u="owner", mqtt_username="owner-mqtt", duid="synthetic-q7-duid")
    bridge._remember_device_seen(observed)
    assert bridge._resolve_device_for_cloud(cloud) == observed


def test_q7_migration_credentials_require_model_and_cloud_key(tmp_path: Path) -> None:
    route = "/admin/api/q7/migration-credentials"
    request = {"duid": "synthetic-q7-duid"}
    for model, localkey, source in (
        ("roborock.vacuum.a15", "0123456789abcdef", "inventory_cloud"),
        ("roborock.vacuum.sc05", "short", "inventory_cloud"),
        ("roborock.vacuum.sc05", "0123456789abcdef", "server_assigned"),
    ):
        case = tmp_path / (model.rsplit(".", 1)[-1] + "-" + localkey + "-" + source)
        case.mkdir()
        client, _supervisor = _client(case, model=model, localkey=localkey, local_key_source=source)
        _login(client)
        expected = 400 if localkey == "short" else 404
        assert client.post(route, json=request).status_code == expected


def test_q7_migration_credentials_accept_unique_split_cloud_record(tmp_path: Path) -> None:
    client, _supervisor = _client(
        tmp_path,
        model="",
        did="1234567890123",
        local_key_source="b01_nc",
        split_cloud_key="0123456789abcdef",
    )
    _login(client)
    response = client.post(
        "/admin/api/q7/migration-credentials",
        json={"duid": "separate-cloud-duid"},
    )
    assert response.status_code == 200
    assert len(response.json()["mqtt_usr"]) == 16


def test_q7_migration_credentials_reject_unmatched_split_cloud_key(tmp_path: Path) -> None:
    client, _supervisor = _client(
        tmp_path,
        model="",
        did="1234567890123",
        local_key_source="b01_nc",
        split_cloud_key="fedcba9876543210",
    )
    _login(client)
    response = client.post(
        "/admin/api/q7/migration-credentials",
        json={"did": "1234567890123", "duid": "separate-cloud-duid"},
    )
    assert response.status_code == 400
    assert "not linked" in response.json()["error"]


def test_q7_proxy_links_only_the_authenticated_device_topic(tmp_path: Path) -> None:
    client, supervisor = _client(tmp_path)
    _login(client)
    response = client.post(
        "/admin/api/q7/migration-credentials",
        json={"duid": "synthetic-q7-duid"},
    )
    assert response.status_code == 200
    username = response.json()["mqtt_usr"]
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "cert.pem",
        key_file=tmp_path / "key.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="0123456789abcdef",
        logger=logging.getLogger("test.q7_proxy_auth"),
        decoded_jsonl=tmp_path / "mqtt.jsonl",
        runtime_credentials=supervisor.runtime_credentials,
    )
    topic = f"rr/d/i/1234567890123/{username}"
    packet = _publish_packet(topic)
    proxy._trace_packet("1", "b2c", packet, username, True)
    proxy._trace_packet("1", "c2b", packet, "other-user", True)
    proxy._trace_packet("1", "c2b", packet, username, False)
    assert supervisor.runtime_credentials.verified_q7_migration_links() == {}
    proxy._trace_packet("1", "c2b", packet, username, True)
    assert supervisor.runtime_credentials.verified_q7_migration_links() == {
        "synthetic-q7-duid": "1234567890123"
    }
