"""Persistent store for scene zone range coordinates.

Zone ranges map (tid, zid) -> [x1, y1, x2, y2].  The app never includes
range coordinates in scene creation requests — it relies on the server
to remember them from previous ``set_scenes_zones`` MQTT exchanges.

This module provides a lightweight JSON-backed store that is updated when
the MQTT proxy observes ``set_scenes_zones`` traffic and when the routine
runner sends zone sync commands.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any


_ZONE_RANGES_FILE = "zone_ranges.json"


def _key(tid: str, zid: int) -> str:
    return f"{tid}:{zid}"


def _parse_key(key: str) -> tuple[str, int] | None:
    parts = key.rsplit(":", 1)
    if len(parts) != 2:
        return None
    try:
        return parts[0], int(parts[1])
    except (TypeError, ValueError):
        return None


class ZoneRangesStore:
    """Thread-safe, JSON-backed cache of zone range coordinates."""

    def __init__(self, directory: Path) -> None:
        self._path = directory / _ZONE_RANGES_FILE
        self._lock = threading.Lock()
        self._data: dict[str, list[int]] = self._load()

    def _load(self) -> dict[str, list[int]]:
        if not self._path.exists():
            return {}
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
        if not isinstance(raw, dict):
            return {}
        return {k: v for k, v in raw.items() if isinstance(v, list) and len(v) >= 4}

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(self._data, ensure_ascii=False, separators=(",", ":")),
                encoding="utf-8",
            )
        except OSError:
            pass

    def get(self, tid: str, zid: int) -> list[int] | None:
        with self._lock:
            value = self._data.get(_key(tid, zid))
            if isinstance(value, list) and len(value) >= 4:
                return list(value)
            return None

    def get_all(self, tids: set[str] | None = None) -> dict[tuple[str, int], list[int]]:
        with self._lock:
            result: dict[tuple[str, int], list[int]] = {}
            for k, v in self._data.items():
                parsed = _parse_key(k)
                if parsed is None:
                    continue
                if tids is not None and parsed[0] not in tids:
                    continue
                result[parsed] = list(v)
            return result

    def put(self, tid: str, zid: int, range_coords: list[int]) -> None:
        if not tid or zid < 0 or not isinstance(range_coords, list) or len(range_coords) < 4:
            return
        coords = [int(v) for v in range_coords[:4]]
        k = _key(tid, zid)
        with self._lock:
            if self._data.get(k) == coords:
                return
            self._data[k] = coords
            self._save()

    def merge_set_scenes_zones_request(self, params: Any) -> None:
        """Extract and store ranges from a set_scenes_zones RPC request."""
        if not isinstance(params, dict):
            return
        data = params.get("data")
        if not isinstance(data, list):
            return
        for entry in data:
            if not isinstance(entry, dict):
                continue
            tid = str(entry.get("tid") or "").strip()
            for zone in entry.get("zones") or []:
                if not isinstance(zone, dict):
                    continue
                zid = zone.get("zid")
                range_value = zone.get("range")
                if tid and isinstance(zid, int) and isinstance(range_value, list) and len(range_value) >= 4:
                    self.put(tid, zid, range_value)

    def seed_from_mqtt_jsonl(self, mqtt_jsonl: Path) -> int:
        """Populate the store from an existing MQTT JSONL log file.

        Returns the number of new entries added.
        """
        if not mqtt_jsonl.exists():
            return 0
        count_before = len(self._data)
        try:
            with mqtt_jsonl.open("r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    decoded_messages = entry.get("decoded_messages")
                    if not isinstance(decoded_messages, list):
                        continue
                    for decoded in decoded_messages:
                        if not isinstance(decoded, dict):
                            continue
                        rpc = decoded.get("rpc")
                        if isinstance(rpc, dict) and str(rpc.get("method") or "").strip() == "set_scenes_zones":
                            self.merge_set_scenes_zones_request(rpc.get("params"))
                        response_to = decoded.get("response_to")
                        if isinstance(response_to, dict) and str(response_to.get("request_method") or "").strip() == "set_scenes_zones":
                            self.merge_set_scenes_zones_response(
                                request_params=response_to.get("request_params"),
                                result=response_to.get("result"),
                            )
        except OSError:
            pass
        return len(self._data) - count_before

    def merge_set_scenes_zones_response(
        self,
        request_params: Any,
        result: Any,
    ) -> None:
        """Extract and store ranges from a set_scenes_zones RPC response.

        The response's ``result`` provides the device-assigned ``tid`` and
        ``zid`` while the request's ``params`` contains the ``range`` values.
        """
        if not isinstance(request_params, dict) or not isinstance(result, list):
            return
        request_data = request_params.get("data")
        if not isinstance(request_data, list):
            return
        for req_entry, res_entry in zip(request_data, result):
            if not isinstance(req_entry, dict) or not isinstance(res_entry, dict):
                continue
            tid = str(res_entry.get("tid") or req_entry.get("tid") or "").strip()
            if not tid:
                continue
            req_zones = req_entry.get("zones") or []
            res_zones = res_entry.get("zones") or []
            for idx, req_zone in enumerate(req_zones):
                if not isinstance(req_zone, dict):
                    continue
                res_zone = res_zones[idx] if idx < len(res_zones) and isinstance(res_zones[idx], dict) else {}
                zid = res_zone.get("zid", req_zone.get("zid"))
                range_value = req_zone.get("range")
                if isinstance(zid, int) and isinstance(range_value, list) and len(range_value) >= 4:
                    self.put(tid, zid, range_value)
