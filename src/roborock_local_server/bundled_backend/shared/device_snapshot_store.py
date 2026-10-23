"""Persistent last-known state of each robot the server manages.

A robot that dies, loses Wi-Fi or gets stuck stops answering, and from then on nothing
can say where it was or what it last reported. This store keeps, per device, the last
status, battery and error the robot sent, its last position on the map and the map it
was drawn on, and when it last spoke or went offline. It survives a server restart.

It is fed from the MQTT proxy: status pushes (``dps`` 120/121/122), ``get_status``
answers, and the ``get_map_v1`` reply, which is decrypted with the nonce of the request
that asked for it. Position needs that map; nothing else in the protocol carries it.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import struct
import threading
import time
from pathlib import Path
from collections.abc import Callable
from typing import Any

from roborock_local_server.log_retention import iter_log_lines

from .data_helpers import utcnow_iso

logger = logging.getLogger(__name__)

_DIR_NAME = "device_snapshots"
_MAX_NONCES_PER_DEVICE = 16
_SAFE_DUID = re.compile(r"^[A-Za-z0-9_-]+$")

# dps keys the robot pushes on its own.
_DPS_ERROR = "120"
_DPS_STATE = "121"
_DPS_BATTERY = "122"

_SECURITY_RE = re.compile(r'"endpoint\\?":\s*\\?"(\w+)\\?",\s*\\?"nonce\\?":\s*\\?"([0-9a-fA-F]+)')


def _bytes_from_hex(value: Any) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _point(point: Any) -> dict[str, int] | None:
    if point is None:
        return None
    try:
        return {"x": int(point.x), "y": int(point.y), "angle": int(getattr(point, "a", 0) or 0)}
    except (AttributeError, TypeError, ValueError):
        return None


def _parse_map(map_bytes: bytes) -> tuple[dict[str, int] | None, dict[str, int] | None]:
    """(robot position, charger position) in robot millimetres, or Nones if it will not parse."""
    from roborock.map.map_parser import MapParser, MapParserConfig

    parsed = MapParser(MapParserConfig()).parse(map_bytes)
    map_data = parsed.map_data if parsed is not None else None
    if map_data is None:
        return None, None
    return _point(map_data.vacuum_position), _point(map_data.charger)


def _dps_update(payload_utf8: str | None) -> dict[str, int]:
    """The status a push carries: ``{"dps": {"122": 5}}`` -> ``{"battery": 5}``."""
    if not payload_utf8:
        return {}
    try:
        payload = json.loads(payload_utf8)
    except (TypeError, json.JSONDecodeError):
        return {}
    dps = payload.get("dps") if isinstance(payload, dict) else None
    if not isinstance(dps, dict):
        return {}
    update: dict[str, int] = {}
    for key, name in ((_DPS_STATE, "state"), (_DPS_BATTERY, "battery"), (_DPS_ERROR, "error_code")):
        value = _int_or_none(dps.get(key))
        if value is not None:
            update[name] = value
    return update


def _status_update(result: Any) -> dict[str, int]:
    """The status a ``get_status`` answer carries: a one-item list holding the status object."""
    status = result[0] if isinstance(result, list) and result else result
    if not isinstance(status, dict):
        return {}
    update: dict[str, int] = {}
    for key in ("state", "battery", "error_code", "clean_percent"):
        value = _int_or_none(status.get(key))
        if value is not None:
            update[key] = value
    return update


def _security_of(payload_utf8: str | None) -> tuple[str, str] | None:
    """(endpoint, nonce) from a request that asked for a map, or None."""
    if not payload_utf8 or "security" not in payload_utf8:
        return None
    found = _SECURITY_RE.search(payload_utf8)
    return (found.group(1), found.group(2)) if found else None


def _decode_map(payload: bytes, nonce: str) -> tuple[bytes, dict[str, int] | None, dict[str, int] | None]:
    """Decrypt a map reply: (the map bytes, robot position, charger position)."""
    from roborock.protocol import Utils

    # 24-byte header (endpoint, request id), then the gzipped map encrypted with the nonce.
    map_bytes = Utils.decompress(Utils.decrypt_cbc(payload[24:], bytes.fromhex(nonce)))
    position, charger = _parse_map(map_bytes)
    return map_bytes, position, charger


class DeviceSnapshotStore:
    """Thread-safe, file-backed last-known state per device, keyed by duid."""

    def __init__(self, directory: Path, *, flush_interval_s: float = 30.0, map_interval_s: float = 60.0) -> None:
        self._dir = directory / _DIR_NAME
        self._flush_interval_s = flush_interval_s
        self._map_interval_s = map_interval_s
        self._lock = threading.RLock()
        self._data: dict[str, dict[str, Any]] = {}
        self._maps: dict[str, bytes] = {}
        self._nonces: dict[str, dict[str, str]] = {}
        self._dirty: set[str] = set()
        self._dirty_maps: set[str] = set()
        self._last_flush = 0.0
        self._last_map_at: dict[str, float] = {}
        self._load()

    # ---- persistence -------------------------------------------------------------

    def _load(self) -> None:
        try:
            files = sorted(self._dir.glob("*.json"))
        except OSError:
            return
        for path in files:
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            duid = str(raw.get("duid") or path.stem) if isinstance(raw, dict) else ""
            if not isinstance(raw, dict) or not duid or not _SAFE_DUID.match(duid):
                continue
            self._data[duid] = raw
            map_path = self._dir / f"{duid}.map"
            if map_path.exists():
                try:
                    self._maps[duid] = map_path.read_bytes()
                except OSError:
                    pass

    def flush(self) -> None:
        """Write everything changed since the last flush."""
        with self._lock:
            dirty, dirty_maps = set(self._dirty), set(self._dirty_maps)
            if not dirty and not dirty_maps:
                return
            try:
                self._dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                return
            for duid in dirty:
                self._write(self._dir / f"{duid}.json", json.dumps(self._data[duid], separators=(",", ":")).encode())
            for duid in dirty_maps:
                if duid in self._maps:
                    self._write(self._dir / f"{duid}.map", self._maps[duid])
            self._dirty.clear()
            self._dirty_maps.clear()
            self._last_flush = time.monotonic()

    @staticmethod
    def _write(path: Path, content: bytes) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        try:
            tmp.write_bytes(content)
            tmp.replace(path)
        except OSError:
            logger.warning("Could not write %s", path)

    def _touch(self, duid: str, *, force_flush: bool = False) -> None:
        self._dirty.add(duid)
        if force_flush or time.monotonic() - self._last_flush >= self._flush_interval_s:
            self.flush()

    # ---- recording ---------------------------------------------------------------

    def _entry(self, duid: str) -> dict[str, Any]:
        entry = self._data.get(duid)
        if entry is None:
            entry = {"duid": duid, "last_seen_at": None, "offline_at": None, "status": {}, "position": None}
            self._data[duid] = entry
        return entry

    def mark_seen(self, duid: str) -> None:
        """The robot spoke: it is online, so any earlier offline mark is cleared."""
        if not _SAFE_DUID.match(duid or ""):
            return
        with self._lock:
            entry = self._entry(duid)
            entry["last_seen_at"] = utcnow_iso()
            if entry.get("offline_at"):
                entry["offline_at"] = None
                self._touch(duid, force_flush=True)
            else:
                self._touch(duid)

    def mark_offline(self, duid: str) -> None:
        """The robot's connection closed. Written at once, since the next restart may lose the rest."""
        if not _SAFE_DUID.match(duid or ""):
            return
        with self._lock:
            entry = self._entry(duid)
            if not entry.get("offline_at"):
                entry["offline_at"] = utcnow_iso()
            self._touch(duid, force_flush=True)

    def record_dps(self, duid: str, payload_utf8: str | None) -> None:
        """A status push, ``{"dps": {"122": 5}}``."""
        update = _dps_update(payload_utf8)
        if update and _SAFE_DUID.match(duid or ""):
            self._update_status(duid, update)

    def record_status_result(self, duid: str, result: Any) -> None:
        """The answer to ``get_status``."""
        update = _status_update(result)
        if update and _SAFE_DUID.match(duid or ""):
            self._update_status(duid, update)

    def _update_status(self, duid: str, update: dict[str, int]) -> None:
        with self._lock:
            entry = self._entry(duid)
            status = entry.setdefault("status", {})
            status.update(update)
            status["updated_at"] = utcnow_iso()
            self._touch(duid)

    def note_request(self, duid: str, payload_utf8: str | None) -> None:
        """Remember the nonce a client sent with a request, so its map reply can be decrypted."""
        security = _security_of(payload_utf8)
        if security is None or not _SAFE_DUID.match(duid or ""):
            return
        endpoint, nonce = security
        with self._lock:
            nonces = self._nonces.setdefault(duid, {})
            nonces.pop(endpoint, None)
            nonces[endpoint] = nonce
            while len(nonces) > _MAX_NONCES_PER_DEVICE:
                nonces.pop(next(iter(nonces)))

    def record_map(self, duid: str, payload: bytes) -> None:
        """A ``get_map_v1`` reply (protocol 301): decrypt, keep the map, and read the robot's position."""
        if not payload or len(payload) < 24 or not _SAFE_DUID.match(duid or ""):
            return
        now = time.monotonic()
        with self._lock:
            if now - self._last_map_at.get(duid, 0.0) < self._map_interval_s:
                return
            endpoint = struct.unpack("<8s", payload[:8])[0].decode("ascii", "replace")
            nonce = self._nonces.get(duid, {}).get(endpoint)
        if nonce is None:
            return
        try:
            map_bytes, position, charger = _decode_map(payload, nonce)
        except Exception:
            logger.debug("Could not decode a map reply for %s", duid, exc_info=True)
            return
        with self._lock:
            self._last_map_at[duid] = now
            entry = self._entry(duid)
            self._maps[duid] = map_bytes
            self._dirty_maps.add(duid)
            entry["position"] = {
                "robot": position,
                "charger": charger,
                "map_updated_at": utcnow_iso(),
            }
            self._touch(duid)

    # ---- backfill ----------------------------------------------------------------

    @staticmethod
    def _duid_in_topic(topic: str, resolve_duid: Callable[[str], str]) -> str:
        parts = topic.split("/")
        if topic.startswith("rr/m/") and len(parts) >= 6:
            return parts[5]
        if topic.startswith("rr/d/") and len(parts) >= 5:
            return resolve_duid(parts[3])
        return ""

    def seed_from_mqtt_jsonl(self, mqtt_jsonl: Path, resolve_duid: Callable[[str], str]) -> int:
        """Fill in devices the store knows nothing about from the decoded MQTT log.

        The log holds what each robot last said, so a robot that stopped answering before this
        store existed still gets its last status and map. A device that already has a snapshot is
        left alone. ``resolve_duid`` turns the short id in a robot's topic into its duid. Returns
        how many devices were added; it can take a while on a large log, so run it off the main
        thread.
        """
        with self._lock:
            known = set(self._data)
        nonces: dict[str, dict[str, str]] = {}
        seen: dict[str, dict[str, Any]] = {}
        for line in iter_log_lines(mqtt_jsonl):
            # Most lines are neither a robot's own frame nor a map request; skip them unparsed.
            if "rr/d/i/" not in line and "security" not in line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            topic = str(entry.get("topic") or "")
            at = str(entry.get("time") or "")
            duid = self._duid_in_topic(topic, resolve_duid)
            if not duid or duid in known or not _SAFE_DUID.match(duid):
                continue
            from_robot = topic.startswith("rr/d/i/") and entry.get("direction") == "c2b"
            for message in entry.get("decoded_messages") or []:
                if not isinstance(message, dict):
                    continue
                payload_utf8 = message.get("payload_utf8")
                payload_utf8 = payload_utf8 if isinstance(payload_utf8, str) else None
                proto = message.get("protocol_value")
                if proto == 101:
                    security = _security_of(payload_utf8)
                    if security is not None:
                        nonces.setdefault(duid, {})[security[0]] = security[1]
                    continue
                if not from_robot:
                    continue
                acc = seen.setdefault(duid, {"status": {}, "status_at": None, "map": None})
                acc["last_seen_at"] = at
                if proto == 301:
                    raw = _bytes_from_hex(message.get("payload_hex"))
                    if raw is not None and len(raw) >= 24:
                        nonce = nonces.get(duid, {}).get(raw[:8].decode("ascii", "replace"))
                        if nonce:
                            acc["map"] = (at, raw, nonce)
                elif proto == 102:
                    response_to = message.get("response_to")
                    if isinstance(response_to, dict):
                        update = (
                            _status_update(response_to.get("result"))
                            if response_to.get("request_method") == "get_status" and response_to.get("error") is None
                            else {}
                        )
                    else:
                        update = _dps_update(payload_utf8)
                    if update:
                        acc["status"].update(update)
                        acc["status_at"] = at

        added = 0
        for duid, acc in seen.items():
            map_bytes = position = charger = None
            if acc["map"] is not None:
                try:
                    map_bytes, position, charger = _decode_map(acc["map"][1], acc["map"][2])
                except Exception:
                    logger.debug("Could not decode the last logged map for %s", duid, exc_info=True)
            with self._lock:
                if duid in self._data:
                    continue
                entry = self._entry(duid)
                entry["last_seen_at"] = acc.get("last_seen_at")
                if acc["status"]:
                    entry["status"] = {**acc["status"], "updated_at": acc["status_at"]}
                if map_bytes is not None:
                    self._maps[duid] = map_bytes
                    self._dirty_maps.add(duid)
                    entry["position"] = {"robot": position, "charger": charger, "map_updated_at": acc["map"][0]}
                self._dirty.add(duid)
                added += 1
        if added:
            self.flush()
        return added

    # ---- reading -----------------------------------------------------------------

    def get(self, duid: str, *, include_map: bool = False) -> dict[str, Any] | None:
        with self._lock:
            entry = self._data.get(duid)
            if entry is None:
                return None
            result = json.loads(json.dumps(entry))
            map_bytes = self._maps.get(duid)
        result["has_map"] = map_bytes is not None
        if include_map and map_bytes is not None:
            result["map"] = base64.b64encode(map_bytes).decode("ascii")
        return result
