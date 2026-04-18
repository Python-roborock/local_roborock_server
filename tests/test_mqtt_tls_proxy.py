import json
import logging
import socket
import threading
import time
from pathlib import Path

import pytest

from roborock_local_server.backend import MqttTlsProxy


class _FakeSourceSocket:
    def __init__(self, *chunks: bytes) -> None:
        self._chunks = list(chunks)
        self.closed = False
        self.recv_calls = 0

    def recv(self, _size: int) -> bytes:
        self.recv_calls += 1
        if self._chunks:
            return self._chunks.pop(0)
        return b""

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


def _build_connect_packet(*, client_id: str, username: str, password: str) -> bytes:
    protocol_name = b"MQTT"
    variable_header = (
        len(protocol_name).to_bytes(2, "big")
        + protocol_name
        + bytes([4, 0xC2])  # MQTT 3.1.1 + clean session + username + password
        + (60).to_bytes(2, "big")
    )
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
