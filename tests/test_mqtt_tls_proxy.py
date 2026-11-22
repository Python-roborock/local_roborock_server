import json
import logging
import socket
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest
from roborock.protocol import create_mqtt_encoder
from roborock.roborock_message import RoborockMessage

from roborock_local_server.backend import MqttTlsProxy
from roborock_local_server.bundled_backend.shared.runtime_credentials import RuntimeCredentialsStore
from roborock_local_server.bundled_backend.shared.runtime_state import RuntimeState


class _FakeSourceSocket:
    def __init__(self, *chunks: bytes) -> None:
        self._chunks = list(chunks)
        self.sent: list[bytes] = []
        self.closed = False
        self.recv_calls = 0

    def recv(self, _size: int) -> bytes:
        self.recv_calls += 1
        if self._chunks:
            return self._chunks.pop(0)
        return b""

    def sendall(self, chunk: bytes) -> None:
        self.sent.append(chunk)

    def close(self) -> None:
        self.closed = True


class _FakeDestinationSocket:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.send_event = threading.Event()
        self.closed = False

    def sendall(self, chunk: bytes) -> None:
        self.sent.append(chunk)
        self.send_event.set()

    def close(self) -> None:
        self.closed = True


class _FakeBackendSocket(_FakeDestinationSocket):
    def __init__(self) -> None:
        super().__init__()
        self.connected_to: tuple[str, int] | None = None

    def connect(self, addr: tuple[str, int]) -> None:
        self.connected_to = addr

    def recv(self, _size: int) -> bytes:
        return b""


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _seed_cloud_snapshot(path: Path) -> None:
    _write_json(
        path,
        {
            "user_data": {
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
        },
    )


def _seed_protocol_sessions(path: Path) -> None:
    _write_json(
        path,
        {
            "version": 1,
            "sessions": [
                {
                    "source": "test_sync",
                    "updated_at_utc": "2026-04-17T17:00:00+00:00",
                    "user_data": {
                        "token": "real-cloud-token-999",
                        "rruid": "real-cloud-rruid-999",
                        "rriot": {
                            "u": "real-cloud-hawk-user",
                            "s": "real-cloud-hawk-session",
                            "h": "real-cloud-hawk-secret",
                            "k": "real-cloud-mqtt-key",
                        },
                    },
                }
            ],
        },
    )


def _seed_key_state(path: Path, *, did: str) -> None:
    _write_json(
        path,
        {
            "devices": {
                did: {
                    "modulus_hex": "ab",
                }
            }
        },
    )


def _build_connect_packet(*, client_id: str, username: str, password: str, protocol_level: int = 4) -> bytes:
    protocol_name = b"MQTT"
    variable_header = (
        len(protocol_name).to_bytes(2, "big")
        + protocol_name
        + bytes([protocol_level, 0xC2])  # clean session + username + password
        + (60).to_bytes(2, "big")
    )
    if protocol_level == 5:
        variable_header += b"\x00"
    payload = (
        len(client_id.encode()).to_bytes(2, "big")
        + client_id.encode()
        + len(username.encode()).to_bytes(2, "big")
        + username.encode()
        + len(password.encode()).to_bytes(2, "big")
        + password.encode()
    )
    remaining = variable_header + payload
    return bytes([0x10, len(remaining)]) + remaining


def _encode_remaining_length(length: int) -> bytes:
    encoded = bytearray()
    while True:
        byte, length = length % 128, length // 128
        encoded.append(byte | 0x80 if length else byte)
        if not length:
            return bytes(encoded)


def _build_publish_packet(*, topic: str, payload: bytes = b"{}") -> bytes:
    topic_bytes = topic.encode()
    remaining = len(topic_bytes).to_bytes(2, "big") + topic_bytes + payload
    return bytes([0x30]) + _encode_remaining_length(len(remaining)) + remaining


def test_relay_forwards_chunk_before_slow_packet_tracing_finishes(tmp_path, monkeypatch) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
    )
    trace_started = threading.Event()
    trace_finished = threading.Event()

    def fake_extract_packets(frame_buf: bytearray) -> list[bytes]:
        if not frame_buf:
            return []
        data = bytes(frame_buf)
        frame_buf.clear()
        return [data]

    def slow_trace_packet(conn_id: str, direction: str, packet: bytes) -> None:
        assert conn_id == "1"
        assert direction == "c2b"
        assert packet == b"packet-bytes"
        trace_started.set()
        time.sleep(0.25)
        trace_finished.set()

    monkeypatch.setattr(proxy, "_extract_packets", fake_extract_packets)
    monkeypatch.setattr(proxy, "_trace_packet", slow_trace_packet)

    src = _FakeSourceSocket(b"packet-bytes")
    dst = _FakeDestinationSocket()
    proxy._running = True

    started_at = time.perf_counter()
    proxy._relay(src, dst, "1", "c2b", bytearray())
    elapsed = time.perf_counter() - started_at

    assert dst.sent == [b"packet-bytes"]
    assert dst.send_event.is_set()
    assert trace_started.wait(0.1)
    assert elapsed < 0.15
    assert trace_finished.wait(1.0)
    assert src.closed is True
    assert dst.closed is True

    proxy.stop()


def test_authorize_connect_accepts_native_user_hash_credentials(tmp_path) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    runtime_credentials_path = tmp_path / "runtime_credentials.json"
    _write_json(
        runtime_credentials_path,
        {
            "schema_version": 2,
            "mqtt_usr": "bootstrap-user",
            "mqtt_passwd": "bootstrap-pass",
            "mqtt_clientid": "bootstrap-client",
            "devices": [],
        },
    )
    from shared.runtime_credentials import RuntimeCredentialsStore

    runtime_credentials = RuntimeCredentialsStore(runtime_credentials_path)
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
        runtime_credentials=runtime_credentials,
    )

    packet = _build_connect_packet(
        client_id="ha-client",
        username="52359d04",
        password="cb5af78c8d901feb",
    )
    authorized, reason, info = proxy._authorize_connect_packet(packet)

    assert authorized is True
    assert reason == "user_hash"
    assert info is not None
    assert info["client_id"] == "ha-client"


def test_authorize_connect_accepts_bootstrap_credentials_and_rejects_wrong_password(tmp_path) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    runtime_credentials_path = tmp_path / "runtime_credentials.json"
    _write_json(
        runtime_credentials_path,
        {
            "schema_version": 2,
            "mqtt_usr": "bootstrap-user",
            "mqtt_passwd": "bootstrap-pass",
            "mqtt_clientid": "bootstrap-client",
            "devices": [],
        },
    )
    from shared.runtime_credentials import RuntimeCredentialsStore

    runtime_credentials = RuntimeCredentialsStore(runtime_credentials_path)
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
        runtime_credentials=runtime_credentials,
    )

    bootstrap_packet = _build_connect_packet(
        client_id="bootstrap-client",
        username="bootstrap-user",
        password="bootstrap-pass",
    )
    authorized, reason, _info = proxy._authorize_connect_packet(bootstrap_packet)
    assert authorized is True
    assert reason == "bootstrap"

    wrong_password_packet = _build_connect_packet(
        client_id="bootstrap-client",
        username="bootstrap-user",
        password="wrong-pass",
    )
    rejected, reject_reason, _info = proxy._authorize_connect_packet(wrong_password_packet)
    assert rejected is False
    assert reject_reason == "invalid_mqtt_credentials"


def test_authorize_connect_accepts_known_device_mqtt_user(tmp_path) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    runtime_credentials_path = tmp_path / "runtime_credentials.json"
    _write_json(
        runtime_credentials_path,
        {
            "schema_version": 2,
            "mqtt_usr": "bootstrap-user",
            "mqtt_passwd": "bootstrap-pass",
            "mqtt_clientid": "bootstrap-client",
            "devices": [
                {
                    "did": "1103821560705",
                    "duid": "6HL2zfniaoYYV01CkVuhkO",
                    "name": "Roborock Qrevo MaxV 2",
                    "model": "roborock.vacuum.a87",
                    "product_id": "5gUei3OIJIXVD3eD85Balg",
                    "localkey": "xPd5Dr8CGGqtdDlH",
                    "local_key_source": "inventory",
                    "device_mqtt_usr": "c25b14ceac358d2a",
                    "device_mqtt_pass": "ff8922d24a9a9af81f18f35dcee9a5a5",
                    "updated_at": "2026-04-17T17:00:00+00:00",
                    "last_nc_at": "",
                    "last_mqtt_seen_at": "",
                }
            ],
        },
    )
    from shared.runtime_credentials import RuntimeCredentialsStore

    runtime_credentials = RuntimeCredentialsStore(runtime_credentials_path)
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
        runtime_credentials=runtime_credentials,
    )

    packet = _build_connect_packet(
        client_id="a012391cb5f8bc97",
        username="c25b14ceac358d2a",
        password="ff8922d24a9a9af81f18f35dcee9a5a5",
    )
    authorized, reason, info = proxy._authorize_connect_packet(packet)

    assert authorized is True
    assert reason == "device_mqtt_user"
    assert info is not None
    assert info["client_id"] == "a012391cb5f8bc97"


def test_authorize_connect_recovers_missing_known_device_mqtt_password(tmp_path) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    runtime_credentials_path = tmp_path / "runtime_credentials.json"
    _write_json(
        runtime_credentials_path,
        {
            "schema_version": 2,
            "mqtt_usr": "bootstrap-user",
            "mqtt_passwd": "bootstrap-pass",
            "mqtt_clientid": "bootstrap-client",
            "devices": [
                {
                    "did": "1103821560705",
                    "duid": "6HL2zfniaoYYV01CkVuhkO",
                    "name": "Roborock Qrevo MaxV 2",
                    "model": "roborock.vacuum.a87",
                    "product_id": "5gUei3OIJIXVD3eD85Balg",
                    "localkey": "xPd5Dr8CGGqtdDlH",
                    "local_key_source": "inventory",
                    "device_mqtt_usr": "c25b14ceac358d2a",
                    "device_mqtt_pass": "",
                    "updated_at": "2026-04-17T17:00:00+00:00",
                    "last_nc_at": "",
                    "last_mqtt_seen_at": "",
                }
            ],
        },
    )
    from shared.runtime_credentials import RuntimeCredentialsStore

    runtime_credentials = RuntimeCredentialsStore(runtime_credentials_path)
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
        runtime_credentials=runtime_credentials,
    )

    packet = _build_connect_packet(
        client_id="a012391cb5f8bc97",
        username="c25b14ceac358d2a",
        password="ff8922d24a9a9af81f18f35dcee9a5a5",
    )
    authorized, reason, info = proxy._authorize_connect_packet(packet)

    assert authorized is True
    assert reason == "device_mqtt_recovered"
    assert info is not None

    recovered_device = runtime_credentials.resolve_device(duid="6HL2zfniaoYYV01CkVuhkO")
    assert recovered_device is not None
    assert recovered_device["device_mqtt_pass"] == "ff8922d24a9a9af81f18f35dcee9a5a5"

    rejected, reject_reason, _info = proxy._authorize_connect_packet(
        _build_connect_packet(
            client_id="a012391cb5f8bc97",
            username="c25b14ceac358d2a",
            password="wrong-pass",
        )
    )
    assert rejected is False
    assert reject_reason == "invalid_mqtt_credentials"


def test_authorize_connect_accepts_unknown_device_credentials_only_for_matching_onboarding_session(tmp_path) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    key_state_path = tmp_path / "device_key_state.json"
    _seed_key_state(key_state_path, did="1103821560705")
    runtime_credentials_path = tmp_path / "runtime_credentials.json"
    _write_json(
        runtime_credentials_path,
        {
            "schema_version": 2,
            "mqtt_usr": "bootstrap-user",
            "mqtt_passwd": "bootstrap-pass",
            "mqtt_clientid": "bootstrap-client",
            "devices": [
                {
                    "did": "1103821560705",
                    "duid": "6HL2zfniaoYYV01CkVuhkO",
                    "name": "Roborock Qrevo MaxV 2",
                    "model": "roborock.vacuum.a87",
                    "product_id": "5gUei3OIJIXVD3eD85Balg",
                    "localkey": "xPd5Dr8CGGqtdDlH",
                    "local_key_source": "inventory",
                    "device_mqtt_usr": "",
                    "device_mqtt_pass": "",
                    "updated_at": "2026-04-17T17:00:00+00:00",
                    "last_nc_at": "",
                    "last_mqtt_seen_at": "",
                }
            ],
        },
    )
    runtime_credentials = RuntimeCredentialsStore(runtime_credentials_path)
    runtime_state = RuntimeState(log_dir=tmp_path, key_state_file=key_state_path, runtime_credentials=runtime_credentials)
    runtime_state.upsert_vacuum("6HL2zfniaoYYV01CkVuhkO", name="Roborock Qrevo MaxV 2", id_kind="duid")
    runtime_state.start_onboarding_session(target_duid="6HL2zfniaoYYV01CkVuhkO", target_name="Roborock Qrevo MaxV 2")
    event_time = datetime.now(timezone.utc).isoformat()
    for route_name, path_name in (("region", "/region"), ("nc_prepare", "/nc")):
        runtime_state.record_http_event(
            event_time=event_time,
            route_name=route_name,
            clean_path=path_name,
            raw_path=path_name,
            method="GET",
            host="api-roborock.example.com",
            remote="192.168.8.10:54321",
            did="1103821560705",
        )
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
        runtime_state=runtime_state,
        runtime_credentials=runtime_credentials,
    )

    packet = _build_connect_packet(
        client_id="a012391cb5f8bc97",
        username="c25b14ceac358d2a",
        password="ff8922d24a9a9af81f18f35dcee9a5a5",
    )
    authorized, reason, info, candidate = proxy._authorize_connect_packet_for_client(
        packet,
        client_ip="192.168.8.10",
    )

    assert authorized is True
    assert reason == "device_mqtt_onboarding_pending"
    assert info is not None
    assert candidate is not None
    assert candidate["did"] == "1103821560705"
    persisted = runtime_credentials.resolve_device(did="1103821560705")
    assert persisted is not None
    assert persisted["device_mqtt_usr"] == ""
    assert persisted["device_mqtt_pass"] == ""

    rejected, reject_reason, _info, rejected_candidate = proxy._authorize_connect_packet_for_client(
        packet,
        client_ip="192.168.8.11",
    )
    assert rejected is False
    assert reject_reason == "invalid_mqtt_credentials"
    assert rejected_candidate is None


def test_authorize_connect_rejects_onboarding_candidate_when_new_connections_disabled(tmp_path) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    key_state_path = tmp_path / "device_key_state.json"
    _seed_key_state(key_state_path, did="1103821560705")
    runtime_credentials_path = tmp_path / "runtime_credentials.json"
    _write_json(
        runtime_credentials_path,
        {
            "schema_version": 2,
            "mqtt_usr": "bootstrap-user",
            "mqtt_passwd": "bootstrap-pass",
            "mqtt_clientid": "bootstrap-client",
            "devices": [
                {
                    "did": "1103821560705",
                    "duid": "6HL2zfniaoYYV01CkVuhkO",
                    "name": "Roborock Qrevo MaxV 2",
                    "model": "roborock.vacuum.a87",
                    "product_id": "5gUei3OIJIXVD3eD85Balg",
                    "localkey": "xPd5Dr8CGGqtdDlH",
                    "local_key_source": "inventory",
                    "device_mqtt_usr": "",
                    "device_mqtt_pass": "",
                    "updated_at": "2026-04-17T17:00:00+00:00",
                    "last_nc_at": "",
                    "last_mqtt_seen_at": "",
                }
            ],
        },
    )
    runtime_credentials = RuntimeCredentialsStore(runtime_credentials_path)
    runtime_state = RuntimeState(log_dir=tmp_path, key_state_file=key_state_path, runtime_credentials=runtime_credentials)
    runtime_state.upsert_vacuum("6HL2zfniaoYYV01CkVuhkO", name="Roborock Qrevo MaxV 2", id_kind="duid")
    runtime_state.start_onboarding_session(target_duid="6HL2zfniaoYYV01CkVuhkO", target_name="Roborock Qrevo MaxV 2")
    event_time = datetime.now(timezone.utc).isoformat()
    for route_name, path_name in (("region", "/region"), ("nc_prepare", "/nc")):
        runtime_state.record_http_event(
            event_time=event_time,
            route_name=route_name,
            clean_path=path_name,
            raw_path=path_name,
            method="GET",
            host="api-roborock.example.com",
            remote="192.168.8.10:54321",
            did="1103821560705",
        )
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
        runtime_state=runtime_state,
        runtime_credentials=runtime_credentials,
        new_connections_enabled=lambda: False,
    )

    packet = _build_connect_packet(
        client_id="a012391cb5f8bc97",
        username="c25b14ceac358d2a",
        password="ff8922d24a9a9af81f18f35dcee9a5a5",
    )
    authorized, reason, info, candidate = proxy._authorize_connect_packet_for_client(
        packet,
        client_ip="192.168.8.10",
    )

    assert authorized is False
    assert reason == "new_connections_disabled"
    assert info is not None
    assert candidate is None


def test_trace_packet_persists_confirmed_onboarding_device_mqtt_credentials(tmp_path) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    runtime_credentials_path = tmp_path / "runtime_credentials.json"
    _write_json(
        runtime_credentials_path,
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
                    "local_key_source": "inventory",
                    "device_mqtt_usr": "",
                    "device_mqtt_pass": "",
                    "updated_at": "2026-04-17T17:00:00+00:00",
                    "last_nc_at": "",
                    "last_mqtt_seen_at": "",
                }
            ],
        },
    )
    runtime_credentials = RuntimeCredentialsStore(runtime_credentials_path)
    learned_callbacks: list[None] = []
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
        runtime_credentials=runtime_credentials,
        on_onboarding_credentials_learned=lambda: learned_callbacks.append(None),
    )
    proxy._set_pending_onboarding_auth(
        "1",
        {
            "did": "1103821560705",
            "duid": "6HL2zfniaoYYV01CkVuhkO",
            "name": "Roborock Qrevo MaxV 2",
            "username": "c25b14ceac358d2a",
            "password": "ff8922d24a9a9af81f18f35dcee9a5a5",
            "client_ip": "192.168.8.10",
        },
    )
    proxy._register_conn_endpoints("1", _FakeSourceSocket(), _FakeBackendSocket())

    proxy._trace_packet("1", "c2b", _build_publish_packet(topic="rr/d/i/1103821560705/c25b14ceac358d2a"))

    persisted = runtime_credentials.resolve_device(did="1103821560705")
    assert persisted is not None
    assert persisted["device_mqtt_usr"] == "c25b14ceac358d2a"
    assert persisted["device_mqtt_pass"] == "ff8922d24a9a9af81f18f35dcee9a5a5"
    assert proxy._get_pending_onboarding_auth("1") is None
    assert proxy._get_conn_device_topic("1") == "rr/d/i/1103821560705/c25b14ceac358d2a"
    assert len(learned_callbacks) == 1


def _firmware_report_payload(local_key: str) -> bytes:
    return create_mqtt_encoder(local_key)(
        RoborockMessage(
            protocol=203,
            payload=b'{"mqttOtaData":{"mqttOtaFirmwareVersion":{"version":"02.44.86"}}}',
        )
    )


def test_trace_packet_reports_firmware_version_published_by_device(tmp_path) -> None:
    local_key = "xPd5Dr8CGGqtdDlH"
    device_topic = "rr/d/i/1103844865396/c25b14ceac358d2a"
    reports: list[tuple[str, str]] = []
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey=local_key,
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        on_device_firmware_reported=lambda device_id, version: reports.append((device_id, version)),
    )
    payload = _firmware_report_payload(local_key)
    proxy._set_conn_device_topic("1", device_topic)
    proxy._set_conn_device_topic("3", "rr/d/i/1103821560705/0f9e8d7c6b5a4f3e")

    proxy._trace_packet("1", "c2b", _build_publish_packet(topic=device_topic, payload=payload))
    # Only the vacuum's own login, publishing on its own topic, reports its firmware.
    proxy._trace_packet("1", "b2c", _build_publish_packet(topic=device_topic, payload=payload))
    proxy._trace_packet("2", "c2b", _build_publish_packet(topic=device_topic, payload=payload))
    proxy._trace_packet("3", "c2b", _build_publish_packet(topic=device_topic, payload=payload))
    proxy._trace_packet("2", "c2b", _build_publish_packet(topic="rr/m/i/hawk-user/6485d8e9/1103844865396", payload=payload))

    assert reports == [("1103844865396", "02.44.86")]


@pytest.mark.parametrize(
    ("username", "password", "expected_reports"),
    [
        # The vacuum's own device MQTT login.
        ("c25b14ceac358d2a", "ff8922d24a9a9af81f18f35dcee9a5a5", [("1103844865396", "02.44.86")]),
        # An app login that knows the vacuum's localKey from home data.
        ("52359d04", "cb5af78c8d901feb", []),
    ],
)
def test_handle_client_takes_firmware_reports_only_from_the_vacuums_own_login(
    tmp_path,
    monkeypatch,
    username: str,
    password: str,
    expected_reports: list[tuple[str, str]],
) -> None:
    local_key = "xPd5Dr8CGGqtdDlH"
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    runtime_credentials_path = tmp_path / "runtime_credentials.json"
    _write_json(
        runtime_credentials_path,
        {
            "schema_version": 2,
            "devices": [
                {
                    "did": "1103844865396",
                    "duid": "4kQ2xZf9mWnB7cVd1LpRt8",
                    "name": "Roborock Qrevo 2 Pro",
                    "model": "roborock.vacuum.a294",
                    "product_id": "",
                    "localkey": local_key,
                    "local_key_source": "inventory",
                    "device_mqtt_usr": "c25b14ceac358d2a",
                    "device_mqtt_pass": "ff8922d24a9a9af81f18f35dcee9a5a5",
                    "updated_at": "2026-11-19T17:00:00+00:00",
                    "last_nc_at": "",
                    "last_mqtt_seen_at": "",
                }
            ],
        },
    )
    reports: list[tuple[str, str]] = []
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
        runtime_credentials=RuntimeCredentialsStore(runtime_credentials_path),
        on_device_firmware_reported=lambda device_id, version: reports.append((device_id, version)),
    )
    connect_packet = _build_connect_packet(client_id="client-1", username=username, password=password)
    publish_packet = _build_publish_packet(
        topic="rr/d/i/1103844865396/c25b14ceac358d2a",
        payload=_firmware_report_payload(local_key),
    )
    tls_conn = _FakeSourceSocket(connect_packet + publish_packet)
    backend = _FakeBackendSocket()

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: backend)
    monkeypatch.setattr(proxy, "_queue_trace_packet", proxy._trace_packet)

    proxy._running = True
    proxy._handle_client(tls_conn, ("127.0.0.1", 4321))

    assert backend.connected_to == ("127.0.0.1", 1883)
    assert reports == expected_reports
    proxy.stop()  # The trace worker forgets the binding after the connection's packets.
    assert proxy._get_conn_device_topic("1") is None


_VACUUM_A = {
    "did": "1103844865396",
    "duid": "4kQ2xZf9mWnB7cVd1LpRt8",
    "name": "Roborock Qrevo 2 Pro",
    "model": "roborock.vacuum.a294",
    "product_id": "",
    "localkey": "xPd5Dr8CGGqtdDlH",
    "local_key_source": "inventory",
    "device_mqtt_usr": "c25b14ceac358d2a",
    "device_mqtt_pass": "ff8922d24a9a9af81f18f35dcee9a5a5",
    "updated_at": "2026-11-19T17:00:00+00:00",
    "last_nc_at": "",
    "last_mqtt_seen_at": "",
}


def _hold_tracing(proxy: MqttTlsProxy, monkeypatch: pytest.MonkeyPatch) -> threading.Event:
    """Hold the trace worker until the returned event is set."""
    release = threading.Event()
    trace_packet = proxy._trace_packet

    def held_trace_packet(conn_id: str, direction: str, packet: bytes) -> None:
        release.wait(5.0)
        trace_packet(conn_id, direction, packet)

    monkeypatch.setattr(proxy, "_trace_packet", held_trace_packet)
    return release


def _build_vacuum_a_proxy(
    tmp_path: Path,
    *,
    device: dict[str, str],
    reports: list[tuple[str, str]] | None = None,
) -> tuple[MqttTlsProxy, RuntimeCredentialsStore]:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    runtime_credentials_path = tmp_path / "runtime_credentials.json"
    _write_json(runtime_credentials_path, {"schema_version": 2, "devices": [device]})
    runtime_credentials = RuntimeCredentialsStore(runtime_credentials_path)
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
        runtime_credentials=runtime_credentials,
        on_device_firmware_reported=(
            (lambda device_id, version: reports.append((device_id, version))) if reports is not None else None
        ),
    )
    return proxy, runtime_credentials


def test_handle_client_keeps_the_vacuums_binding_until_its_queued_packets_are_traced(tmp_path, monkeypatch) -> None:
    reports: list[tuple[str, str]] = []
    proxy, runtime_credentials = _build_vacuum_a_proxy(tmp_path, device=dict(_VACUUM_A), reports=reports)
    release_tracing = _hold_tracing(proxy, monkeypatch)
    tls_conn = _FakeSourceSocket(
        _build_connect_packet(
            client_id="vacuum-a",
            username=_VACUUM_A["device_mqtt_usr"],
            password=_VACUUM_A["device_mqtt_pass"],
        )
        + _build_publish_packet(
            topic=f"rr/d/i/{_VACUUM_A['did']}/{_VACUUM_A['device_mqtt_usr']}",
            payload=_firmware_report_payload(_VACUUM_A["localkey"]),
        )
    )
    backend = _FakeBackendSocket()
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: backend)

    # The vacuum disconnects before the trace worker reaches its packets.
    proxy._running = True
    proxy._handle_client(tls_conn, ("127.0.0.1", 4321))
    release_tracing.set()
    proxy.stop()  # Returns once the trace worker has finished the queue.

    assert reports == [(_VACUUM_A["did"], "02.44.86")]
    vacuum_a = runtime_credentials.resolve_device(did=_VACUUM_A["did"])
    assert vacuum_a is not None
    assert vacuum_a["last_mqtt_seen_at"] != ""
    assert proxy._get_conn_device_topic("1") is None


def test_handle_client_keeps_the_onboarding_candidate_until_its_queued_packets_are_traced(
    tmp_path,
    monkeypatch,
) -> None:
    proxy, runtime_credentials = _build_vacuum_a_proxy(
        tmp_path,
        device={**_VACUUM_A, "device_mqtt_usr": "", "device_mqtt_pass": ""},
    )
    candidate = {
        "did": _VACUUM_A["did"],
        "duid": _VACUUM_A["duid"],
        "name": _VACUUM_A["name"],
        "username": _VACUUM_A["device_mqtt_usr"],
        "password": _VACUUM_A["device_mqtt_pass"],
        "client_ip": "127.0.0.1",
    }
    monkeypatch.setattr(
        proxy,
        "_authorize_connect_packet_for_client",
        lambda _packet, *, client_ip: (
            True,
            "device_mqtt_onboarding_pending",
            {"protocol_level": 4, "username": candidate["username"]},
            dict(candidate),
        ),
    )
    release_tracing = _hold_tracing(proxy, monkeypatch)
    tls_conn = _FakeSourceSocket(
        _build_connect_packet(
            client_id="vacuum-a",
            username=candidate["username"],
            password=candidate["password"],
        )
        + _build_publish_packet(topic=f"rr/d/i/{_VACUUM_A['did']}/{candidate['username']}")
    )
    backend = _FakeBackendSocket()
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: backend)

    # The vacuum disconnects before the trace worker reaches its first publish.
    proxy._running = True
    proxy._handle_client(tls_conn, ("127.0.0.1", 4321))
    release_tracing.set()
    proxy.stop()  # Returns once the trace worker has finished the queue.

    vacuum_a = runtime_credentials.resolve_device(did=_VACUUM_A["did"])
    assert vacuum_a is not None
    assert vacuum_a["device_mqtt_usr"] == candidate["username"]
    assert vacuum_a["device_mqtt_pass"] == candidate["password"]
    assert vacuum_a["last_mqtt_seen_at"] != ""
    assert proxy._get_pending_onboarding_auth("1") is None
    assert proxy._get_conn_device_topic("1") is None


_VACUUM_B = {
    "did": "1103821560705",
    "duid": "6HL2zfniaoYYV01CkVuhkO",
    "name": "Roborock Qrevo MaxV 2",
    "model": "roborock.vacuum.a87",
    "product_id": "",
    "localkey": "Qm3vT9sLx2Wc8RkA",
    "local_key_source": "inventory",
    "device_mqtt_usr": "0f9e8d7c6b5a4f3e",
    "device_mqtt_pass": "0123456789abcdef0123456789abcdef",
    "updated_at": "2026-11-19T17:00:00+00:00",
    "last_nc_at": "",
    "last_mqtt_seen_at": "",
}


def _run_client_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    client_id: str,
    username: str,
    password: str,
    publish_topics: list[str],
) -> tuple[MqttTlsProxy, RuntimeCredentialsStore]:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    runtime_credentials_path = tmp_path / "runtime_credentials.json"
    _write_json(
        runtime_credentials_path,
        {
            "schema_version": 2,
            "mqtt_usr": "bootstrap-user",
            "mqtt_passwd": "bootstrap-pass",
            "mqtt_clientid": "bootstrap-client",
            "devices": [dict(_VACUUM_A), dict(_VACUUM_B)],
        },
    )
    runtime_credentials = RuntimeCredentialsStore(runtime_credentials_path)
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
        runtime_credentials=runtime_credentials,
    )
    packets = _build_connect_packet(client_id=client_id, username=username, password=password)
    for topic in publish_topics:
        packets += _build_publish_packet(topic=topic)
    tls_conn = _FakeSourceSocket(packets)
    backend = _FakeBackendSocket()

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: backend)
    monkeypatch.setattr(proxy, "_queue_trace_packet", proxy._trace_packet)

    proxy._running = True
    proxy._handle_client(tls_conn, ("127.0.0.1", 4321))

    assert backend.connected_to == ("127.0.0.1", 1883)
    return proxy, runtime_credentials


@pytest.mark.parametrize(
    ("client_id", "username", "password"),
    [
        # An app login (protocol auth).
        ("ha-client", "52359d04", "cb5af78c8d901feb"),
        # The bootstrap login.
        ("bootstrap-client", "bootstrap-user", "bootstrap-pass"),
        # Another vacuum's own device login.
        ("vacuum-b", _VACUUM_B["device_mqtt_usr"], _VACUUM_B["device_mqtt_pass"]),
    ],
)
def test_handle_client_ignores_device_topics_published_by_other_logins(
    tmp_path,
    monkeypatch,
    client_id: str,
    username: str,
    password: str,
) -> None:
    proxy, runtime_credentials = _run_client_session(
        tmp_path,
        monkeypatch,
        client_id=client_id,
        username=username,
        password=password,
        publish_topics=[
            f"rr/d/i/{_VACUUM_A['did']}/spoofed-user",
            "rr/d/i/2000000000001/spoofed-user",
        ],
    )

    vacuum_a = runtime_credentials.resolve_device(did=_VACUUM_A["did"])
    assert vacuum_a is not None
    assert vacuum_a["device_mqtt_usr"] == _VACUUM_A["device_mqtt_usr"]
    assert vacuum_a["last_mqtt_seen_at"] == ""
    assert runtime_credentials.resolve_device(did="2000000000001") is None
    assert len(runtime_credentials.devices()) == 2

    # Vacuum A can still log in with its own credentials.
    authorized, reason, _info = proxy._authorize_connect_packet(
        _build_connect_packet(
            client_id="vacuum-a",
            username=_VACUUM_A["device_mqtt_usr"],
            password=_VACUUM_A["device_mqtt_pass"],
        )
    )
    assert (authorized, reason) == (True, "device_mqtt_user")


def test_handle_client_records_activity_from_the_vacuums_own_login(tmp_path, monkeypatch) -> None:
    _proxy, runtime_credentials = _run_client_session(
        tmp_path,
        monkeypatch,
        client_id="vacuum-a",
        username=_VACUUM_A["device_mqtt_usr"],
        password=_VACUUM_A["device_mqtt_pass"],
        publish_topics=[f"rr/d/i/{_VACUUM_A['did']}/{_VACUUM_A['device_mqtt_usr']}"],
    )

    vacuum_a = runtime_credentials.resolve_device(did=_VACUUM_A["did"])
    assert vacuum_a is not None
    assert vacuum_a["device_mqtt_usr"] == _VACUUM_A["device_mqtt_usr"]
    assert vacuum_a["last_mqtt_seen_at"] != ""
    assert len(runtime_credentials.devices()) == 2


def test_trace_packet_closes_provisional_onboarding_session_when_first_publish_topic_mismatches(tmp_path) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    runtime_credentials_path = tmp_path / "runtime_credentials.json"
    _write_json(
        runtime_credentials_path,
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
                    "local_key_source": "inventory",
                    "device_mqtt_usr": "",
                    "device_mqtt_pass": "",
                    "updated_at": "2026-04-17T17:00:00+00:00",
                    "last_nc_at": "",
                    "last_mqtt_seen_at": "",
                }
            ],
        },
    )
    runtime_credentials = RuntimeCredentialsStore(runtime_credentials_path)
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
        runtime_credentials=runtime_credentials,
    )
    client_sock = _FakeSourceSocket()
    backend_sock = _FakeBackendSocket()
    proxy._set_pending_onboarding_auth(
        "1",
        {
            "did": "1103821560705",
            "duid": "6HL2zfniaoYYV01CkVuhkO",
            "name": "Roborock Qrevo MaxV 2",
            "username": "c25b14ceac358d2a",
            "password": "ff8922d24a9a9af81f18f35dcee9a5a5",
            "client_ip": "192.168.8.10",
        },
    )
    proxy._register_conn_endpoints("1", client_sock, backend_sock)

    proxy._trace_packet("1", "c2b", _build_publish_packet(topic="rr/d/i/9999999999999/c25b14ceac358d2a"))

    persisted = runtime_credentials.resolve_device(did="1103821560705")
    assert persisted is not None
    assert persisted["device_mqtt_usr"] == ""
    assert persisted["device_mqtt_pass"] == ""
    assert client_sock.closed is True
    assert backend_sock.closed is True
    assert proxy._get_pending_onboarding_auth("1") is None


def test_authorize_connect_accepts_persisted_synced_user_hash_credentials(tmp_path) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    protocol_sessions_path = tmp_path / "protocol_sessions.json"
    _seed_protocol_sessions(protocol_sessions_path)
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
        protocol_auth_sessions_path=protocol_sessions_path,
    )

    packet = _build_connect_packet(
        client_id="ios-app-client",
        username="7ad5ebc1",
        password="558d41e0cece0ee7",
    )
    authorized, reason, info = proxy._authorize_connect_packet(packet)

    assert authorized is True
    assert reason == "user_hash"
    assert info is not None
    assert info["client_id"] == "ios-app-client"


def test_authorize_connect_rejects_protocol_user_hash_when_protocol_auth_disabled(tmp_path) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    protocol_sessions_path = tmp_path / "protocol_sessions.json"
    _seed_protocol_sessions(protocol_sessions_path)
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
        protocol_auth_sessions_path=protocol_sessions_path,
        protocol_auth_enabled=lambda: False,
    )

    packet = _build_connect_packet(
        client_id="ios-app-client",
        username="7ad5ebc1",
        password="558d41e0cece0ee7",
    )
    authorized, reason, info = proxy._authorize_connect_packet(packet)

    assert authorized is False
    assert reason == "invalid_mqtt_credentials"
    assert info is not None
    assert info["client_id"] == "ios-app-client"


def test_read_first_packet_rejects_invalid_remaining_length() -> None:
    src = _FakeSourceSocket(b"\x10\xff\xff\xff\xff")

    with pytest.raises(ValueError, match="remaining length"):
        MqttTlsProxy._read_first_packet(src)

    assert src.recv_calls == 1


def test_accept_client_connection_returns_raw_socket_when_tls_disabled(tmp_path) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    proxy = MqttTlsProxy(
        cert_file=None,
        key_file=None,
        listen_host="127.0.0.1",
        listen_port=18883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
        tls_enabled=False,
    )
    raw_conn = _FakeSourceSocket()

    accepted = proxy._accept_client_connection(raw_conn=raw_conn, addr=("127.0.0.1", 4321), tls_ctx=None)

    assert accepted is raw_conn
    assert raw_conn.closed is False


def test_build_tls_context_requires_cert_paths_when_tls_enabled(tmp_path) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    proxy = MqttTlsProxy(
        cert_file=None,
        key_file=None,
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
    )

    with pytest.raises(RuntimeError, match="requires cert_file and key_file"):
        proxy._build_tls_context()


def test_handle_client_traces_packets_already_buffered_before_relay(tmp_path, monkeypatch) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
    )
    backend = _FakeBackendSocket()
    traced: list[tuple[str, str, bytes]] = []
    connect_packet = _build_connect_packet(
        client_id="ha-client",
        username="52359d04",
        password="cb5af78c8d901feb",
    )
    tls_conn = _FakeSourceSocket(connect_packet + b"\xc0\x00")

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: backend)
    monkeypatch.setattr(proxy, "_queue_trace_packet", lambda conn_id, direction, packet: traced.append((conn_id, direction, packet)))

    proxy._running = True
    proxy._handle_client(tls_conn, ("127.0.0.1", 4321))

    assert backend.connected_to == ("127.0.0.1", 1883)
    assert backend.sent == [connect_packet + b"\xc0\x00"]
    assert traced == [
        ("1", "c2b", connect_packet),
        ("1", "c2b", b"\xc0\x00"),
    ]


def test_handle_client_closes_tls_conn_when_client_closes_before_connect(tmp_path) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
    )
    tls_conn = _FakeSourceSocket()

    proxy._running = True
    proxy._handle_client(tls_conn, ("127.0.0.1", 4321))

    assert tls_conn.closed is True


def test_handle_client_closes_tls_conn_when_connect_is_rejected(tmp_path, monkeypatch) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
    )
    tls_conn = _FakeSourceSocket(
        _build_connect_packet(
            client_id="bad-client",
            username="unknown-user",
            password="unknown-pass",
        )
    )

    def _unexpected_backend(*args, **kwargs):
        raise AssertionError("backend socket should not be created for rejected MQTT CONNECT")

    monkeypatch.setattr(socket, "socket", _unexpected_backend)

    proxy._running = True
    proxy._handle_client(tls_conn, ("127.0.0.1", 4321))

    assert tls_conn.sent == [b"\x20\x02\x00\x05"]
    assert tls_conn.closed is True


def test_handle_client_returns_mqtt5_not_authorized_connack_on_rejected_connect(tmp_path, monkeypatch) -> None:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
    )
    tls_conn = _FakeSourceSocket(
        _build_connect_packet(
            client_id="bad-client",
            username="unknown-user",
            password="unknown-pass",
            protocol_level=5,
        )
    )

    def _unexpected_backend(*args, **kwargs):
        raise AssertionError("backend socket should not be created for rejected MQTT CONNECT")

    monkeypatch.setattr(socket, "socket", _unexpected_backend)

    proxy._running = True
    proxy._handle_client(tls_conn, ("127.0.0.1", 4321))

    assert tls_conn.sent == [b"\x20\x03\x00\x87\x00"]
    assert tls_conn.closed is True


def _build_reverse_proxy_onboarding(
    tmp_path: Path,
    *,
    trusted_proxies: tuple[str, ...],
    steps: tuple[tuple[str, str], ...] = (("region", "/region"), ("nc_prepare", "/nc")),
) -> tuple[MqttTlsProxy, RuntimeCredentialsStore, bytes]:
    cloud_snapshot_path = tmp_path / "cloud_snapshot.json"
    _seed_cloud_snapshot(cloud_snapshot_path)
    key_state_path = tmp_path / "device_key_state.json"
    _seed_key_state(key_state_path, did="1103821560705")
    runtime_credentials_path = tmp_path / "runtime_credentials.json"
    _write_json(
        runtime_credentials_path,
        {
            "schema_version": 2,
            "devices": [
                {
                    "did": "1103821560705",
                    "duid": "6HL2zfniaoYYV01CkVuhkO",
                    "name": "Roborock Qrevo MaxV 2",
                    "model": "roborock.vacuum.a87",
                    "localkey": "xPd5Dr8CGGqtdDlH",
                    "device_mqtt_usr": "",
                    "device_mqtt_pass": "",
                }
            ],
        },
    )
    runtime_credentials = RuntimeCredentialsStore(runtime_credentials_path)
    runtime_state = RuntimeState(
        log_dir=tmp_path,
        key_state_file=key_state_path,
        runtime_credentials=runtime_credentials,
        trusted_proxies=trusted_proxies,
    )
    runtime_state.upsert_vacuum("6HL2zfniaoYYV01CkVuhkO", name="Roborock Qrevo MaxV 2", id_kind="duid")
    runtime_state.start_onboarding_session(target_duid="6HL2zfniaoYYV01CkVuhkO", target_name="Roborock Qrevo MaxV 2")
    # HTTP arrives through a trusted reverse proxy, so the recorded remote is the vacuum's real LAN IP.
    event_time = datetime.now(timezone.utc).isoformat()
    for route_name, path_name in steps:
        runtime_state.record_http_event(
            event_time=event_time,
            route_name=route_name,
            clean_path=path_name,
            raw_path=path_name,
            method="GET",
            host="api-roborock.example.com",
            remote="10.1.6.170:0",
            did="1103821560705",
        )
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        cloud_snapshot_path=cloud_snapshot_path,
        runtime_state=runtime_state,
        runtime_credentials=runtime_credentials,
    )
    packet = _build_connect_packet(
        client_id="a012391cb5f8bc97",
        username="c25b14ceac358d2a",
        password="ff8922d24a9a9af81f18f35dcee9a5a5",
    )
    return proxy, runtime_credentials, packet


def test_onboarding_candidate_accepts_mqtt_from_trusted_stream_proxy(tmp_path) -> None:
    # MQTT is SNAT'd by a stream proxy / ServiceLB (10.1.1.10), so it never shows the vacuum's IP.
    proxy, runtime_credentials, packet = _build_reverse_proxy_onboarding(tmp_path, trusted_proxies=("10.1.1.0/24",))

    authorized, reason, _info, candidate = proxy._authorize_connect_packet_for_client(packet, client_ip="10.1.1.10")

    assert authorized is True
    assert reason == "device_mqtt_onboarding_pending"
    assert candidate is not None
    assert candidate["did"] == "1103821560705"
    assert candidate["client_ip"] == "10.1.1.10"

    proxy._set_pending_onboarding_auth("proxied-conn", candidate)
    proxy._register_conn_endpoints("proxied-conn", _FakeSourceSocket(), _FakeBackendSocket())
    proxy._trace_packet("proxied-conn", "c2b", _build_publish_packet(topic="rr/d/i/1103821560705/c25b14ceac358d2a"))

    confirmed = runtime_credentials.resolve_device(did="1103821560705")
    assert confirmed is not None
    assert confirmed["device_mqtt_usr"] == "c25b14ceac358d2a"


def test_onboarding_candidate_rejects_mqtt_from_untrusted_mismatched_ip(tmp_path) -> None:
    proxy, runtime_credentials, packet = _build_reverse_proxy_onboarding(tmp_path, trusted_proxies=("10.1.1.0/24",))

    authorized, reason, _info, candidate = proxy._authorize_connect_packet_for_client(packet, client_ip="10.1.6.99")

    assert authorized is False
    assert reason == "invalid_mqtt_credentials"
    assert candidate is None
    device = runtime_credentials.resolve_device(did="1103821560705")
    assert device is not None
    assert device["device_mqtt_usr"] == ""


def test_onboarding_candidate_from_trusted_proxy_still_requires_region_and_nc(tmp_path) -> None:
    proxy, _runtime_credentials, packet = _build_reverse_proxy_onboarding(
        tmp_path,
        trusted_proxies=("10.1.1.0/24",),
        steps=(("region", "/region"),),
    )

    authorized, reason, _info, candidate = proxy._authorize_connect_packet_for_client(packet, client_ip="10.1.1.10")

    assert authorized is False
    assert reason == "invalid_mqtt_credentials"
    assert candidate is None


def _write_self_signed_cert(cert_file: Path, key_file: Path) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mqtt.example.com")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )
    cert_file.write_bytes(certificate.public_bytes(encoding=serialization.Encoding.PEM))
    key_file.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture
def start_tls_proxy(tmp_path):
    cert_file = tmp_path / "fullchain.pem"
    key_file = tmp_path / "privkey.pem"
    _write_self_signed_cert(cert_file, key_file)
    started: list[MqttTlsProxy] = []

    def start(handshake_timeout_seconds: float) -> MqttTlsProxy:
        proxy = MqttTlsProxy(
            cert_file=cert_file,
            key_file=key_file,
            listen_host="127.0.0.1",
            listen_port=_free_port(),
            backend_host="127.0.0.1",
            backend_port=1883,
            localkey="test-local-key",
            logger=logging.getLogger("test.mqtt_tls_proxy"),
            decoded_jsonl=tmp_path / "decoded.jsonl",
        )
        proxy._TLS_HANDSHAKE_TIMEOUT_SECONDS = handshake_timeout_seconds
        proxy.start()
        started.append(proxy)
        deadline = time.monotonic() + 5
        while not proxy._running and time.monotonic() < deadline:
            time.sleep(0.01)
        return proxy

    yield start
    for proxy in started:
        proxy.stop()


def _tls_handshake(port: int) -> None:
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
        with client_ctx.wrap_socket(raw, server_hostname="mqtt.example.com"):
            pass


def test_stalled_tls_handshake_does_not_block_new_connections(start_tls_proxy) -> None:
    # The stalled client must outlast the healthy client's 2 s deadline,
    # otherwise serialized handshakes would pass once the stall times out.
    proxy = start_tls_proxy(handshake_timeout_seconds=10)
    with socket.create_connection(("127.0.0.1", proxy.listen_port), timeout=2):
        time.sleep(0.1)

        _tls_handshake(proxy.listen_port)


def test_stalled_tls_handshake_is_closed_after_timeout(start_tls_proxy) -> None:
    proxy = start_tls_proxy(handshake_timeout_seconds=0.5)
    with socket.create_connection(("127.0.0.1", proxy.listen_port), timeout=5) as stalled:
        assert stalled.recv(1) == b""


class _FakeCredentials:
    def resolve_device(self, *, did: str = "", duid: str = "", model: str = "") -> dict[str, str] | None:
        return {"duid": "DUID1"} if did == "did-test-1" else None


def _snapshot_proxy(tmp_path):
    from roborock_local_server.bundled_backend.shared.device_snapshot_store import DeviceSnapshotStore

    store = DeviceSnapshotStore(tmp_path, flush_interval_s=0.0, map_interval_s=0.0)
    proxy = MqttTlsProxy(
        cert_file=tmp_path / "fullchain.pem",
        key_file=tmp_path / "privkey.pem",
        listen_host="127.0.0.1",
        listen_port=8883,
        backend_host="127.0.0.1",
        backend_port=1883,
        localkey="test-local-key",
        logger=logging.getLogger("test.mqtt_tls_proxy"),
        decoded_jsonl=tmp_path / "decoded.jsonl",
        runtime_credentials=_FakeCredentials(),
        snapshot_store=store,
    )
    return proxy, store


def test_robot_status_push_updates_the_snapshot_and_remembers_the_connection(tmp_path) -> None:
    proxy, store = _snapshot_proxy(tmp_path)
    proxy._set_conn_device_topic("7", "rr/d/i/did-test-1/abc")

    proxy._observe_snapshot(
        "7", "c2b", "rr/d/i/did-test-1/abc", 102, {"payload_utf8": '{"t":1,"dps":{"122":5}}'}, b"",
    )

    assert store.get("DUID1")["status"]["battery"] == 5
    assert proxy._conn_duids["7"] == {"DUID1"}


def test_get_status_answer_updates_the_snapshot(tmp_path) -> None:
    proxy, store = _snapshot_proxy(tmp_path)
    proxy._set_conn_device_topic("7", "rr/d/i/did-test-1/abc")

    proxy._observe_snapshot(
        "7",
        "c2b",
        "rr/d/i/did-test-1/abc",
        102,
        {"response_to": {"request_method": "get_status", "error": None, "result": [{"state": 8, "battery": 100}]}},
        b"",
    )

    assert store.get("DUID1")["status"]["state"] == 8


def test_frames_that_are_not_from_the_robot_do_not_mark_it_seen(tmp_path) -> None:
    proxy, store = _snapshot_proxy(tmp_path)

    # An app's request travels on rr/m/i; the broker's copy toward the robot is rr/d/o.
    proxy._observe_snapshot(
        "9", "c2b", "rr/m/i/user/abcd1234/DUID1", 102, {"payload_utf8": '{"dps":{"122":5}}'}, b"",
    )
    proxy._observe_snapshot(
        "9", "b2c", "rr/d/o/did-test-1/abc", 102, {"payload_utf8": '{"dps":{"122":5}}'}, b"",
    )

    assert store.get("DUID1") is None
    assert "9" not in proxy._conn_duids


def test_a_request_with_a_nonce_is_remembered_for_its_map_reply(tmp_path) -> None:
    proxy, store = _snapshot_proxy(tmp_path)
    payload = '{"dps":{"101":"{\\"security\\":{\\"endpoint\\":\\"testep01\\",\\"nonce\\":\\"00ff\\"}}"}}'

    proxy._observe_snapshot("9", "c2b", "rr/m/i/user/abcd1234/DUID1", 101, {"payload_utf8": payload}, b"")

    assert store._nonces["DUID1"] == {"testep01": "00ff"}


ROBOT_TOPIC = "rr/d/i/did-test-1/abc"
PUSH = {"payload_utf8": '{"t":1,"dps":{"122":5}}'}


def test_a_publish_from_a_login_not_bound_to_the_robot_topic_is_not_the_robot_speaking(tmp_path) -> None:
    proxy, store = _snapshot_proxy(tmp_path)
    proxy._set_conn_device_topic("8", "rr/d/i/did-test-2/other")

    proxy._observe_snapshot("9", "c2b", ROBOT_TOPIC, 102, PUSH, b"")
    proxy._observe_snapshot("8", "c2b", ROBOT_TOPIC, 102, PUSH, b"")

    assert store.get("DUID1") is None


def test_closing_an_old_connection_does_not_mark_a_reconnected_robot_offline(tmp_path) -> None:
    proxy, store = _snapshot_proxy(tmp_path)
    proxy._set_conn_device_topic("1", ROBOT_TOPIC)
    proxy._set_conn_device_topic("2", ROBOT_TOPIC)
    proxy._observe_snapshot("1", "c2b", ROBOT_TOPIC, 102, PUSH, b"")
    proxy._observe_snapshot("2", "c2b", ROBOT_TOPIC, 102, PUSH, b"")

    proxy._forget_conn_trace_state("1")

    assert store.get("DUID1")["offline_at"] is None
    proxy._forget_conn_trace_state("2")
    assert store.get("DUID1")["offline_at"]


def test_queued_packets_of_a_closed_connection_cannot_clear_its_offline_mark(tmp_path) -> None:
    from roborock_local_server.bundled_backend.mqtt_tls_proxy_server import server as proxy_module

    proxy, store = _snapshot_proxy(tmp_path)
    proxy._set_conn_device_topic("1", ROBOT_TOPIC)
    proxy._trace_packet = lambda conn_id, direction, packet: proxy._observe_snapshot(  # type: ignore[method-assign]
        conn_id, direction, ROBOT_TOPIC, 102, PUSH, packet
    )
    proxy._trace_queue.put(("1", "c2b", b"queued"))
    proxy._trace_queue.put(("1", proxy_module._CONN_CLOSED, b""))
    proxy._trace_queue.put(None)

    proxy._run_trace_worker()

    assert store.get("DUID1")["offline_at"]
    assert "1" not in proxy._conn_duids


def test_mower_pushes_do_not_fill_the_vacuum_status_fields(tmp_path) -> None:
    proxy, store = _snapshot_proxy(tmp_path)
    proxy.runtime_credentials = type(
        "Mower", (), {"resolve_device": lambda self, **kw: {"duid": "DUID1", "model": "roborock.mower.a1"}}
    )()
    proxy._set_conn_device_topic("7", ROBOT_TOPIC)

    proxy._observe_snapshot("7", "c2b", ROBOT_TOPIC, 102, PUSH, b"")

    entry = store.get("DUID1")
    assert entry["last_seen_at"]
    assert entry["status"] == {}
