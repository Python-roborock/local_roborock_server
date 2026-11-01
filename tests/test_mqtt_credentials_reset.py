"""Credential reset exercises persistence, authenticated API and live proxy state."""

import json
import logging
import socket

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server.backend import MqttTlsProxy
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor
from shared.runtime_credentials import RuntimeCredentialsStore
from shared.runtime_state import RuntimeState
from test_mqtt_tls_proxy import _build_connect_packet, _build_publish_packet


def test_admin_reset_requires_login_and_same_origin_and_preserves_data(tmp_path, monkeypatch):
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    credentials = supervisor.runtime_credentials
    credentials.ensure_device(duid="downstairs", did="123", localkey="keep-key",
                              device_mqtt_usr="old-user", device_mqtt_pass="old-password")
    other = credentials.ensure_device(duid="upstairs", did="456", device_mqtt_usr="other-user",
                                      device_mqtt_pass="other-password")
    supervisor.protocol_auth.issue_local_session({"rruid": "test-user", "rriot": {
        "u": "app-id", "s": "app-session", "h": "app-hawk", "k": "app-mqtt"}}, source="test")
    sessions = supervisor.protocol_auth.persisted_sessions()
    paths.inventory_path.write_text(json.dumps({"devices": [{"duid": "downstairs"}],
        "server_scheduled_start": {"downstairs": [{"id": "job-1", "enabled": True}]}}))
    inventory = paths.inventory_path.read_bytes()
    key_path = supervisor.runtime_state.key_state_file
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(json.dumps({"devices": {"123": {"modulus": "123456789"}}}))
    keys = key_path.read_bytes()
    supervisor.runtime_state.start_onboarding_session(target_duid="downstairs", target_did="123")
    client = TestClient(supervisor.app)
    url = "/admin/api/vacuums/downstairs/mqtt-credentials"
    assert client.delete(url).status_code == 401
    assert client.post("/admin/api/login", json={"password": "correct horse battery staple"}).status_code == 200
    assert client.delete(url, headers={"Origin": "https://other.example"}).status_code == 403
    assert client.delete("/admin/api/vacuums/missing/mqtt-credentials").status_code == 404
    response = client.delete(url, headers={"Origin": "http://testserver"})
    assert response.status_code == 200
    assert response.json()["mqtt_credentials"]["saved"] is False
    assert "old-password" not in response.text and "keep-key" not in response.text
    assert credentials.resolve_device(duid="downstairs")["localkey"] == "keep-key"
    assert credentials.resolve_device(duid="upstairs") == other
    assert supervisor.protocol_auth.persisted_sessions() == sessions
    assert paths.inventory_path.read_bytes() == inventory
    assert key_path.read_bytes() == keys
    assert not supervisor.runtime_state.onboarding_session_snapshot()["active"]
    # A second reset is safe and does not touch another device's pairing.
    supervisor.runtime_state.start_onboarding_session(target_duid="upstairs", target_did="456")
    assert client.delete(url).status_code == 200
    assert supervisor.runtime_state.onboarding_session_snapshot()["target"]["duid"] == "upstairs"
    def fail_save():
        raise OSError("private filesystem detail")
    monkeypatch.setattr(credentials, "_save_locked", fail_save)
    response = client.delete(url)
    assert response.status_code == 500
    assert "private filesystem detail" not in response.text


def test_live_reset_disconnects_only_target_and_blocks_queued_or_inflight_old_login(tmp_path):
    credentials = RuntimeCredentialsStore(tmp_path / "credentials.json")
    credentials.ensure_device(duid="downstairs", did="123", localkey="keep-key",
                              device_mqtt_usr="old-user", device_mqtt_pass="old-password")
    credentials.ensure_device(duid="upstairs", did="456", device_mqtt_usr="other-user",
                              device_mqtt_pass="other-password")
    state = RuntimeState(log_dir=tmp_path, key_state_file=None, runtime_credentials=credentials)
    proxy = MqttTlsProxy(cert_file=None, key_file=None, tls_enabled=False, listen_host="127.0.0.1",
        listen_port=0, backend_host="127.0.0.1", backend_port=1883, localkey="keep-key",
        logger=logging.getLogger("test.reset"), decoded_jsonl=tmp_path / "decoded.jsonl",
        runtime_state=state, runtime_credentials=credentials)
    old_packet = _build_connect_packet(client_id="robot", username="old-user", password="old-password")
    other_packet = _build_connect_packet(client_id="other", username="other-user", password="other-password")
    assert proxy._authorize_client_connect("1", old_packet, client_ip="192.0.2.1")[0]
    assert proxy._authorize_client_connect("2", other_packet, client_ip="192.0.2.2")[0]
    assert proxy._authorize_client_connect("3", old_packet, client_ip="192.0.2.1")[0]
    sockets = [sock for _ in range(3) for sock in socket.socketpair()]
    try:
        assert proxy._register_conn_endpoints("1", sockets[0], sockets[2])
        assert proxy._register_conn_endpoints("2", sockets[4], sockets[5])
        proxy.clear_device_mqtt_credentials(duid="downstairs")
        sockets[1].settimeout(1)
        sockets[3].settimeout(1)
        assert sockets[1].recv(1) == sockets[3].recv(1) == b""
        assert sockets[4].fileno() != -1 and sockets[5].fileno() != -1
        assert not proxy._register_conn_endpoints("3", sockets[1], sockets[3])
        proxy._trace_packet("1", "c2b", _build_publish_packet(topic="rr/d/i/123/old-user"))
        assert credentials.resolve_device(duid="downstairs")["device_mqtt_usr"] == ""
        assert not proxy._authorize_connect_packet(old_packet)[0]
        assert proxy._authorize_connect_packet(other_packet)[0]
        assert not (tmp_path / "decoded.jsonl").exists()
    finally:
        for sock in sockets:
            sock.close()


def test_reset_status_stays_offline_until_new_credentials_are_confirmed(tmp_path):
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    supervisor = ReleaseSupervisor(config=config, paths=resolve_paths(config_file, config))
    supervisor.runtime_credentials.ensure_device(duid="downstairs", did="123", name="Downstairs",
        device_mqtt_usr="old-user", device_mqtt_pass="old-password")
    supervisor.refresh_inventory_state()
    supervisor.clear_device_mqtt_credentials(duid="downstairs")
    # An app's request on rr/m is not evidence that a cleared robot has re-paired.
    supervisor.runtime_state.record_mqtt_message(conn_id="app", direction="c2b",
        topic="rr/m/i/app/user/downstairs", payload_preview="request")
    vacuum = next(vac for vac in supervisor._vacuums_payload()["vacuums"] if vac["duid"] == "downstairs")
    assert vacuum["connected"] is False
    assert vacuum["mqtt_credentials"]["saved"] is False
