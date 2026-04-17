"""TLS MQTT proxy with Roborock payload decoding."""

from __future__ import annotations

import binascii
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import queue
import socket
import ssl
import threading
from typing import Any

from shared.constants import MQTT_TYPES
from shared.decoder import build_decoder
from shared.io_utils import append_jsonl, payload_preview
from shared.protocol_auth import ProtocolAuthStore
from shared.runtime_credentials import RuntimeCredentialsStore
from shared.runtime_state import RuntimeState
from shared.zone_ranges_store import ZoneRangesStore

from .command_handlers import RpcCommandRegistry

class MqttTlsProxy:
    def __init__(
        self,
        *,
        cert_file: Path,
        key_file: Path,
        listen_host: str,
        listen_port: int,
        backend_host: str,
        backend_port: int,
        localkey: str,
        logger: logging.Logger,
        decoded_jsonl: Path,
        cloud_snapshot_path: Path | None = None,
        protocol_auth_sessions_path: Path | None = None,
        runtime_state: RuntimeState | None = None,
        runtime_credentials: RuntimeCredentialsStore | None = None,
        zone_ranges_store: ZoneRangesStore | None = None,
    ) -> None:
        self.cert_file = cert_file
        self.key_file = key_file
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.localkey = localkey
        self.logger = logger
        self.decoded_jsonl = decoded_jsonl
        self.cloud_snapshot_path = cloud_snapshot_path
        self.runtime_state = runtime_state
        self.runtime_credentials = runtime_credentials
        self.zone_ranges_store = zone_ranges_store
        self._server_socket: socket.socket | None = None
        self._running = False
        self._counter = 0
        self._lock = threading.Lock()
        self._conn_protocol_levels: dict[str, int] = {}
        self._trace_queue: queue.Queue[tuple[str, str, bytes] | None] = queue.Queue()
        self._trace_thread: threading.Thread | None = None
        self._protocol_auth = (
            ProtocolAuthStore(
                cloud_snapshot_path,
                session_store_path=protocol_auth_sessions_path,
            )
            if cloud_snapshot_path is not None
            else None
        )
        default_decoder, self._protocol_names = build_decoder(localkey)
        self._decoder_cache: dict[str, Any] = {localkey: default_decoder}
        self._command_registry = RpcCommandRegistry()

    def _next_conn(self) -> str:
        with self._lock:
            self._counter += 1
            return str(self._counter)

    @staticmethod
    def _decode_remaining_length(data: bytes, start: int) -> tuple[int | None, int]:
        multiplier = 1
        value = 0
        consumed = 0
        idx = start
        while idx < len(data):
            byte_val = data[idx]
            consumed += 1
            value += (byte_val & 0x7F) * multiplier
            if (byte_val & 0x80) == 0:
                return value, consumed
            multiplier *= 128
            idx += 1
            if consumed >= 4:
                break
        return None, 0

    def _extract_packets(self, frame_buf: bytearray) -> list[bytes]:
        packets: list[bytes] = []
        offset = 0
        data = bytes(frame_buf)
        while True:
            if len(data) - offset < 2:
                break
            remaining_len, remaining_len_bytes = self._decode_remaining_length(data, offset + 1)
            if remaining_len is None or remaining_len_bytes == 0:
                break
            packet_len = 1 + remaining_len_bytes + remaining_len
            if len(data) - offset < packet_len:
                break
            packets.append(data[offset : offset + packet_len])
            offset += packet_len
        if offset:
            del frame_buf[:offset]
        return packets

    @classmethod
    def _extract_connect_protocol_level(cls, packet: bytes) -> int | None:
        if len(packet) < 8:
            return None
        remaining_len, remaining_len_bytes = cls._decode_remaining_length(packet, 1)
        if remaining_len is None or remaining_len_bytes == 0:
            return None
        start = 1 + remaining_len_bytes
        if start + 2 > len(packet):
            return None
        protocol_name_len = int.from_bytes(packet[start : start + 2], "big")
        protocol_level_idx = start + 2 + protocol_name_len
        if protocol_level_idx >= len(packet):
            return None
        return packet[protocol_level_idx]

    @staticmethod
    def _decode_mqtt_string(packet: bytes, cursor: int) -> tuple[str | None, int]:
        if cursor + 2 > len(packet):
            return None, cursor
        length = int.from_bytes(packet[cursor : cursor + 2], "big")
        start = cursor + 2
        end = start + length
        if end > len(packet):
            return None, cursor
        return packet[start:end].decode("utf-8", errors="replace"), end

    @staticmethod
    def _decode_mqtt_binary(packet: bytes, cursor: int) -> tuple[bytes | None, int]:
        if cursor + 2 > len(packet):
            return None, cursor
        length = int.from_bytes(packet[cursor : cursor + 2], "big")
        start = cursor + 2
        end = start + length
        if end > len(packet):
            return None, cursor
        return packet[start:end], end

    @classmethod
    def _parse_connect_packet(cls, packet: bytes) -> dict[str, Any] | None:
        if not packet or (packet[0] >> 4) != 1:
            return None
        remaining_len, remaining_len_bytes = cls._decode_remaining_length(packet, 1)
        if remaining_len is None or remaining_len_bytes == 0:
            return None
        cursor = 1 + remaining_len_bytes
        protocol_name, cursor = cls._decode_mqtt_string(packet, cursor)
        if protocol_name is None or cursor + 4 > len(packet):
            return None
        protocol_level = packet[cursor]
        connect_flags = packet[cursor + 1]
        cursor += 4  # protocol_level + connect_flags + keepalive(2)
        if protocol_level == 5:
            property_len, property_len_bytes = cls._decode_remaining_length(packet, cursor)
            if property_len is None or property_len_bytes == 0:
                return None
            cursor += property_len_bytes + property_len
        client_id, cursor = cls._decode_mqtt_string(packet, cursor)
        if client_id is None:
            return None

        will_flag = (connect_flags & 0x04) != 0
        username_flag = (connect_flags & 0x80) != 0
        password_flag = (connect_flags & 0x40) != 0
        if will_flag:
            if protocol_level == 5:
                property_len, property_len_bytes = cls._decode_remaining_length(packet, cursor)
                if property_len is None or property_len_bytes == 0:
                    return None
                cursor += property_len_bytes + property_len
            _, cursor = cls._decode_mqtt_string(packet, cursor)
            _, cursor = cls._decode_mqtt_binary(packet, cursor)
            if cursor > len(packet):
                return None

        username = ""
        password = ""
        if username_flag:
            decoded_username, cursor = cls._decode_mqtt_string(packet, cursor)
            if decoded_username is None:
                return None
            username = decoded_username
        if password_flag:
            decoded_password, cursor = cls._decode_mqtt_binary(packet, cursor)
            if decoded_password is None:
                return None
            password = decoded_password.decode("utf-8", errors="replace")

        return {
            "protocol_name": protocol_name,
            "protocol_level": protocol_level,
            "client_id": client_id,
            "username": username,
            "password": password,
        }

    @classmethod
    def _read_first_packet(cls, conn: socket.socket) -> tuple[bytes, bytes] | None:
        buffer = bytearray()
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            buffer.extend(chunk)
            if len(buffer) < 2:
                continue
            remaining_len, remaining_len_bytes = cls._decode_remaining_length(buffer, 1)
            if remaining_len is None or remaining_len_bytes == 0:
                continue
            total_len = 1 + remaining_len_bytes + remaining_len
            if len(buffer) < total_len:
                continue
            return bytes(buffer[:total_len]), bytes(buffer[total_len:])

    def _expected_bootstrap_credentials(self) -> tuple[str, str, str] | None:
        if self.runtime_credentials is None:
            return None
        username = str(self.runtime_credentials.bootstrap_value("mqtt_usr", "") or "").strip()
        password = str(self.runtime_credentials.bootstrap_value("mqtt_passwd", "") or "").strip()
        client_id = str(self.runtime_credentials.bootstrap_value("mqtt_clientid", "") or "").strip()
        if not username or not password:
            return None
        return username, password, client_id

    def _authorize_connect_packet(self, packet: bytes) -> tuple[bool, str, dict[str, Any] | None]:
        info = self._parse_connect_packet(packet)
        if info is None:
            return False, "invalid_connect_packet", None

        username = str(info.get("username") or "").strip()
        password = str(info.get("password") or "").strip()
        client_id = str(info.get("client_id") or "").strip()
        if not username or not password:
            return False, "missing_mqtt_credentials", info

        if self._protocol_auth is not None:
            authorized, auth_reason, _matched_user = self._protocol_auth.verify_user_mqtt_credentials(username, password)
            if authorized:
                return True, auth_reason, info

        bootstrap_credentials = self._expected_bootstrap_credentials()
        if bootstrap_credentials is not None:
            expected_username, expected_password, expected_client_id = bootstrap_credentials
            if username == expected_username and password == expected_password:
                if expected_client_id and client_id and client_id != expected_client_id:
                    return False, "invalid_bootstrap_client_id", info
                return True, "bootstrap", info

        return False, "invalid_mqtt_credentials", info

    @classmethod
    def _extract_publish(cls, packet: bytes, protocol_level: int | None = None) -> tuple[str | None, bytes | None]:
        if len(packet) < 4:
            return None, None
        flags = packet[0] & 0x0F
        qos = (flags >> 1) & 0x03
        remaining_len, remaining_len_bytes = cls._decode_remaining_length(packet, 1)
        if remaining_len is None or remaining_len_bytes == 0:
            return None, None
        start = 1 + remaining_len_bytes
        if start + 2 > len(packet):
            return None, None
        topic_len = int.from_bytes(packet[start : start + 2], "big")
        topic_start = start + 2
        topic_end = topic_start + topic_len
        if topic_end > len(packet):
            return None, None
        topic = packet[topic_start:topic_end].decode("utf-8", errors="replace")
        cursor = topic_end + (2 if qos > 0 else 0)
        if cursor > len(packet):
            return None, None
        if protocol_level == 5:
            property_len, property_len_bytes = cls._decode_remaining_length(packet, cursor)
            if property_len is None or property_len_bytes == 0:
                return None, None
            payload_start = cursor + property_len_bytes + property_len
        else:
            payload_start = cursor
        if payload_start > len(packet):
            return None, None
        return topic, packet[payload_start:]

    def _set_conn_protocol_level(self, conn_id: str, protocol_level: int) -> None:
        with self._lock:
            self._conn_protocol_levels[conn_id] = protocol_level

    def _get_conn_protocol_level(self, conn_id: str) -> int | None:
        with self._lock:
            return self._conn_protocol_levels.get(conn_id)

    @staticmethod
    def _candidate_payloads(payload: bytes) -> list[tuple[str, bytes]]:
        out: list[tuple[str, bytes]] = [("raw", payload)]
        seen = {payload}

        versions = (b"1.0", b"A01", b"B01", b"L01")
        max_prefix = min(8, max(0, len(payload) - 3))
        for idx in range(1, max_prefix + 1):
            if payload[idx : idx + 3] in versions:
                candidate = payload[idx:]
                if candidate not in seen:
                    seen.add(candidate)
                    out.append((f"offset+{idx}", candidate))

        if len(payload) >= 19:
            declared_len = int.from_bytes(payload[17:19], "big")
            nominal = 19 + declared_len
            if len(payload) == nominal:
                crc = binascii.crc32(payload) & 0xFFFFFFFF
                candidate = payload + crc.to_bytes(4, "big")
                if candidate not in seen:
                    out.append(("raw+crc32", candidate))

        return out

    @staticmethod
    def _decode_payload_bytes(payload: bytes | None) -> dict[str, Any]:
        if payload is None:
            return {"payload_utf8": None}
        if not payload:
            return {"payload_utf8": ""}
        try:
            text = payload.decode("utf-8")
            return {"payload_utf8": text}
        except UnicodeDecodeError:
            return {"payload_utf8": None, "payload_hex": payload.hex()}

    def _get_decoder(self, localkey: str) -> Any:
        normalized_key = str(localkey or "").strip() or self.localkey
        with self._lock:
            cached = self._decoder_cache.get(normalized_key)
        if cached is not None:
            return cached
        decoder, protocol_names = build_decoder(normalized_key)
        with self._lock:
            cached = self._decoder_cache.setdefault(normalized_key, decoder)
            if not self._protocol_names:
                self._protocol_names = protocol_names
        return cached

    def _candidate_localkeys(self, topic: str) -> list[tuple[str, str]]:
        candidates: list[tuple[str, str]] = []
        if self.runtime_credentials is not None:
            topic_key = self.runtime_credentials.localkey_for_topic(topic)
            if topic_key:
                candidates.append(("topic", topic_key))
        default_key = str(self.localkey or "").strip()
        if default_key and all(candidate_key != default_key for _, candidate_key in candidates):
            candidates.append(("default", default_key))
        return candidates

    def _decode_mqtt_payload(self, topic: str, payload: bytes) -> tuple[list[Any], str, str, str]:
        errors: list[str] = []
        for key_source, localkey in self._candidate_localkeys(topic):
            decoder = self._get_decoder(localkey)
            for variant, candidate in self._candidate_payloads(payload):
                try:
                    messages = decoder(candidate)
                except Exception as exc:
                    errors.append(f"{key_source}/{variant}: {exc}")
                    continue
                if messages:
                    return messages, variant, "", key_source
                errors.append(f"{key_source}/{variant}: decoder returned 0 messages")
        return [], "none", "; ".join(errors[:6]), ""

    @staticmethod
    def _parse_v1_rpc_payload(payload_utf8: str | None, protocol_value: int) -> dict[str, Any] | None:
        if not payload_utf8:
            return None
        try:
            payload_obj = json.loads(payload_utf8)
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(payload_obj, dict):
            return None
        datapoints = payload_obj.get("dps")
        if not isinstance(datapoints, dict):
            return None
        dps_key = "101" if protocol_value == 101 else "102" if protocol_value == 102 else None
        if dps_key is None:
            return None
        raw_rpc = datapoints.get(dps_key)
        if raw_rpc is None:
            return None
        if isinstance(raw_rpc, str):
            try:
                rpc_obj = json.loads(raw_rpc)
            except json.JSONDecodeError:
                return None
        elif isinstance(raw_rpc, dict):
            rpc_obj = raw_rpc
        else:
            return None
        if not isinstance(rpc_obj, dict):
            return None

        parsed: dict[str, Any] = {"id": rpc_obj.get("id")}
        if protocol_value == 101:
            parsed["method"] = rpc_obj.get("method")
            parsed["params"] = rpc_obj.get("params")
        else:
            parsed["result"] = rpc_obj.get("result")
            parsed["error"] = rpc_obj.get("error")
        return parsed

    def _trace_packet(self, conn_id: str, direction: str, packet: bytes) -> None:
        packet_type = packet[0] >> 4
        if packet_type in (12, 13):  # PINGREQ, PINGRESP
            return
        packet_name = MQTT_TYPES.get(packet_type, f"TYPE_{packet_type}")
        preview = packet[:96].hex()
        self.logger.info("[conn %s %s] %s len=%d hex=%s", conn_id, direction, packet_name, len(packet), preview)

        if packet_type == 1 and direction == "c2b":
            protocol_level = self._extract_connect_protocol_level(packet)
            if protocol_level is not None:
                self._set_conn_protocol_level(conn_id, protocol_level)
                self.logger.info(
                    "[conn %s %s] CONNECT protocol_level=%s",
                    conn_id,
                    direction,
                    protocol_level,
                )

        if packet_type != 3:
            return

        topic, payload = self._extract_publish(packet, self._get_conn_protocol_level(conn_id))
        if topic is None or payload is None:
            return
        if self.runtime_state is not None:
            self.runtime_state.record_mqtt_message(
                conn_id=conn_id,
                direction=direction,
                topic=topic,
                payload_preview=payload_preview(payload),
            )
        if self.runtime_credentials is not None:
            self.runtime_credentials.record_mqtt_topic(topic=topic)

        messages, variant, decode_error, decode_key_source = self._decode_mqtt_payload(topic, payload)
        entry: dict[str, Any] = {
            "time": datetime.now(timezone.utc).isoformat(),
            "conn": conn_id,
            "direction": direction,
            "topic": topic,
            "payload_hex": payload[:4096].hex(),
            "payload_preview": payload_preview(payload),
            "decoder_variant": variant,
        }
        if decode_key_source:
            entry["decode_key_source"] = decode_key_source
        if not messages:
            entry["decode_error"] = decode_error or "python-roborock returned no messages"
            append_jsonl(self.decoded_jsonl, entry)
            self.logger.info(
                "[conn %s %s] PUBLISH topic=%s decode_error=%s key_source=%s",
                conn_id,
                direction,
                topic,
                entry["decode_error"],
                decode_key_source or "none",
            )
            return

        decoded_messages: list[dict[str, Any]] = []
        for message in messages:
            proto_value = int(getattr(message.protocol, "value", message.protocol))
            proto_name = self._protocol_names.get(proto_value, f"P{proto_value}")
            version = (
                message.version.decode("utf-8", "replace")
                if isinstance(message.version, (bytes, bytearray))
                else str(message.version)
            )
            payload_bytes = message.payload if isinstance(message.payload, bytes) else b""
            payload_data = self._decode_payload_bytes(payload_bytes)
            payload_compact = payload_data.get("payload_utf8")
            if isinstance(payload_compact, str):
                try:
                    payload_compact = json.dumps(
                        json.loads(payload_compact), ensure_ascii=True, separators=(",", ":")
                    )
                except json.JSONDecodeError:
                    pass
            preview = payload_preview(
                payload_compact.encode("utf-8")
                if isinstance(payload_compact, str)
                else payload_bytes
            )
            decoded_entry: dict[str, Any] = {
                "protocol": proto_name,
                "protocol_value": proto_value,
                "version": version,
                "seq": getattr(message, "seq", None),
                "timestamp": getattr(message, "timestamp", None),
                **payload_data,
            }
            rpc_data = self._parse_v1_rpc_payload(
                payload_data.get("payload_utf8") if isinstance(payload_data.get("payload_utf8"), str) else None,
                proto_value,
            )
            if rpc_data is not None:
                decoded_entry["rpc"] = rpc_data
                if proto_value == 101:
                    handled = self._command_registry.handle_request(rpc_data)
                    if handled is not None:
                        decoded_entry["handled"] = handled
                        self.logger.info(
                            "[conn %s %s] handled method=%s request_id=%s details=%s",
                            conn_id,
                            direction,
                            rpc_data.get("method"),
                            rpc_data.get("id"),
                            handled,
                        )
                    if (
                        self.zone_ranges_store is not None
                        and str(rpc_data.get("method") or "").strip() == "set_scenes_zones"
                    ):
                        self.zone_ranges_store.merge_set_scenes_zones_request(
                            rpc_data.get("params"),
                        )
                elif proto_value == 102:
                    response_to = self._command_registry.handle_response(rpc_data)
                    if response_to is not None:
                        decoded_entry["response_to"] = response_to
                        if (
                            self.zone_ranges_store is not None
                            and str(response_to.get("request_method") or "").strip() == "set_scenes_zones"
                            and response_to.get("error") is None
                        ):
                            self.zone_ranges_store.merge_set_scenes_zones_response(
                                request_params=response_to.get("request_params"),
                                result=response_to.get("result"),
                            )
                        self.logger.info(
                            "[conn %s %s] rpc_response request_id=%s method=%s error=%s",
                            conn_id,
                            direction,
                            response_to.get("request_id"),
                            response_to.get("request_method"),
                            response_to.get("error"),
                        )
            decoded_messages.append(decoded_entry)
            self.logger.info(
                "[conn %s %s] PUBLISH topic=%s proto=%s(%d) ver=%s seq=%s key_source=%s payload=%s",
                conn_id,
                direction,
                topic,
                proto_name,
                proto_value,
                version,
                getattr(message, "seq", None),
                decode_key_source or "default",
                preview,
            )
        state = self._command_registry.state
        if state:
            entry["command_state"] = state
        entry["decoded_messages"] = decoded_messages
        append_jsonl(self.decoded_jsonl, entry)

    def _run_trace_worker(self) -> None:
        while True:
            item = self._trace_queue.get()
            if item is None:
                return
            conn_id, direction, packet = item
            try:
                self._trace_packet(conn_id, direction, packet)
            except Exception:
                self.logger.exception(
                    "[conn %s %s] tracing failed",
                    conn_id,
                    direction,
                )

    def _ensure_trace_worker(self) -> None:
        with self._lock:
            if self._trace_thread is not None and self._trace_thread.is_alive():
                return
            self._trace_thread = threading.Thread(
                target=self._run_trace_worker,
                daemon=True,
                name="mqtt-tls-proxy-trace",
            )
            self._trace_thread.start()

    def _queue_trace_packet(self, conn_id: str, direction: str, packet: bytes) -> None:
        self._ensure_trace_worker()
        self._trace_queue.put((conn_id, direction, packet))

    def _relay(self, src: socket.socket, dst: socket.socket, conn_id: str, direction: str, frame_buf: bytearray) -> None:
        try:
            while self._running:
                chunk = src.recv(4096)
                if not chunk:
                    break
                frame_buf.extend(chunk)
                for packet in self._extract_packets(frame_buf):
                    self._queue_trace_packet(conn_id, direction, packet)
                dst.sendall(chunk)
        except (OSError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            for endpoint in (src, dst):
                try:
                    endpoint.close()
                except OSError:
                    pass

    def _handle_client(self, tls_conn: ssl.SSLSocket, addr: tuple[str, int]) -> None:
        conn_id = self._next_conn()
        self.logger.info(
            "[conn %s] backend connect %s:%d from %s:%d",
            conn_id,
            self.backend_host,
            self.backend_port,
            addr[0],
            addr[1],
        )
        if self.runtime_state is not None:
            self.runtime_state.record_mqtt_connection(conn_id=conn_id, client_ip=addr[0], client_port=addr[1])
        try:
            first_packet = self._read_first_packet(tls_conn)
            if first_packet is None:
                self.logger.warning("[conn %s] client closed before MQTT CONNECT", conn_id)
                return
            connect_packet, initial_remainder = first_packet
            authorized, auth_reason, connect_info = self._authorize_connect_packet(connect_packet)
            if connect_info is not None:
                protocol_level = connect_info.get("protocol_level")
                if isinstance(protocol_level, int):
                    self._set_conn_protocol_level(conn_id, protocol_level)
            self._queue_trace_packet(conn_id, "c2b", connect_packet)
            if not authorized:
                self.logger.warning(
                    "[conn %s] rejected MQTT CONNECT reason=%s client_id=%s username=%s",
                    conn_id,
                    auth_reason,
                    str((connect_info or {}).get("client_id") or ""),
                    str((connect_info or {}).get("username") or ""),
                )
                return

            backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend.connect((self.backend_host, self.backend_port))
            backend.sendall(connect_packet + initial_remainder)
            c2b = threading.Thread(
                target=self._relay,
                args=(tls_conn, backend, conn_id, "c2b", bytearray(initial_remainder)),
                daemon=True,
            )
            b2c = threading.Thread(target=self._relay, args=(backend, tls_conn, conn_id, "b2c", bytearray()), daemon=True)
            c2b.start()
            b2c.start()
            c2b.join()
            b2c.join()
        except Exception as exc:
            self.logger.error("[conn %s] connection error: %s", conn_id, exc)
        finally:
            if self.runtime_state is not None:
                self.runtime_state.record_mqtt_disconnect(conn_id=conn_id)
            with self._lock:
                self._conn_protocol_levels.pop(conn_id, None)
            self.logger.info("[conn %s] closed", conn_id)

    def start(self) -> threading.Thread:
        self._ensure_trace_worker()
        thread = threading.Thread(target=self._run, daemon=True, name="mqtt-tls-proxy")
        thread.start()
        return thread

    def _run(self) -> None:
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        # Older Roborock firmware MQTT clients negotiate TLSv1.0/1.1.
        if hasattr(ssl, "TLSVersion"):
            try:
                tls_ctx.minimum_version = ssl.TLSVersion.TLSv1  # type: ignore[attr-defined]
            except Exception:
                pass
        for opt_name in ("OP_NO_TLSv1", "OP_NO_TLSv1_1"):
            opt_value = getattr(ssl, opt_name, None)
            if opt_value is not None:
                tls_ctx.options &= ~opt_value
        tls_ctx.load_cert_chain(str(self.cert_file), str(self.key_file))
        tls_ctx.check_hostname = False
        tls_ctx.verify_mode = ssl.CERT_NONE

        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.listen_host, self.listen_port))
        self._server_socket.listen(10)
        self._running = True
        self.logger.info(
            "TLS MQTT proxy listening on %s:%d -> %s:%d",
            self.listen_host,
            self.listen_port,
            self.backend_host,
            self.backend_port,
        )

        while self._running:
            try:
                raw_conn, addr = self._server_socket.accept()
                try:
                    tls_conn = tls_ctx.wrap_socket(raw_conn, server_side=True)
                    self.logger.info("TLS handshake ok from %s:%d (%s)", addr[0], addr[1], tls_conn.version())
                except (ssl.SSLError, ConnectionResetError, OSError) as exc:
                    self.logger.warning("TLS handshake failed from %s:%d: %s", addr[0], addr[1], exc)
                    raw_conn.close()
                    continue
                threading.Thread(target=self._handle_client, args=(tls_conn, addr), daemon=True).start()
            except OSError as exc:
                if not self._running:
                    break
                # Keep serving if a single accept call fails transiently.
                self.logger.warning("accept() failed: %s", exc)
                continue

    def stop(self) -> None:
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass
        trace_thread: threading.Thread | None = None
        with self._lock:
            trace_thread = self._trace_thread
            self._trace_thread = None
        if trace_thread is not None and trace_thread.is_alive():
            self._trace_queue.put(None)
            trace_thread.join(timeout=2.0)
        self.logger.info("TLS MQTT proxy stopped")
