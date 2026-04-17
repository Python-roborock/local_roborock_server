import json
import logging
import threading
import time
from pathlib import Path

from roborock_local_server.backend import MqttTlsProxy


class _FakeSourceSocket:
    def __init__(self, *chunks: bytes) -> None:
        self._chunks = list(chunks)
        self.closed = False

    def recv(self, _size: int) -> bytes:
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
