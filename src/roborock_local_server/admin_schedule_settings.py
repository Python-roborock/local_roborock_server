"""Cleaning choices and live map/room validation for the dashboard scheduler."""

from __future__ import annotations

import asyncio
import copy
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import logging
from typing import Any

# V1 values shared with LocalRock's VacuumStatus.kt. Keep advanced, imported
# model values intact instead of offering options a model may not support.
CHOICES = {
    "fan_power": [(101, "Quiet"), (102, "Balanced"), (103, "Turbo"), (104, "Max"), (105, "Off / mop only"), (106, "Room settings")],
    "water_box_mode": [(200, "Off"), (201, "Low"), (202, "Medium"), (203, "High"), (204, "Room settings")],
    "mop_mode": [(300, "Standard"), (301, "Deep"), (302, "Room settings")],
    "repeat": [(1, "1 pass"), (2, "2 passes"), (3, "3 passes")],
}
EXTRA_LABELS = {
    "fan_power": {105: "Mop only / gentle suction", 106: "Room settings", 108: "Max+", 110: "Smart mode"},
    "water_box_mode": {204: "Room settings", 207: "Custom water flow", 208: "Extreme", 209: "Smart mode",
                       221: "Very low", 225: "Low", 230: "Gentle", 235: "Medium", 240: "Moderate", 245: "High", 250: "Extreme"},
    "mop_mode": {302: "Room settings", 303: "Deep+", 304: "Fast", 305: "Deep+", 306: "Smart mode"},
}
EDITABLE_SETTINGS = frozenset({*CHOICES, "segments", "map_index"})


class RoomCatalogError(ValueError):
    pass


class ReadCommand(StrEnum):
    STATUS = "get_status"
    MAPS = "get_multi_maps_list"
    ROOMS = "get_room_mapping"
    LOAD_MAP = "load_multi_map"


def setting_choices(settings: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    result = {}
    for key, choices in CHOICES.items():
        options = [{"value": value, "label": label} for value, label in choices]
        current = settings.get(key)
        if type(current) is int and current not in {value for value, _ in choices}:
            options.append({"value": current, "label": EXTRA_LABELS.get(key, {}).get(current, f"Saved custom option ({current})")})
        result[key] = options
    return result


def schedule_param(job: dict[str, Any]) -> dict[str, Any] | None:
    param = job.get("param")
    if isinstance(param, str):
        try:
            param = json.loads(param)
        except ValueError:
            return None
    if not isinstance(param, dict) or param.get("method") != "server_scheduled_start":
        return None
    params = param.get("params")
    if not isinstance(params, list) or len(params) != 1 or not isinstance(params[0], dict):
        return None
    # Native starts carry the complete map and cleaning payload through to the
    # robot. Legacy fallbacks can omit map bindings, so keep those read-only.
    if not isinstance(params[0].get("name"), str) or not params[0]["name"].strip():
        return None
    return copy.deepcopy(param)


def segment_ids(value: Any) -> list[int]:
    if isinstance(value, str):
        value = value.replace(";", ",").split(",")
    if not isinstance(value, list) or not value or len(value) > 255:
        raise ValueError("Choose whole home or at least one room.")
    ids = []
    for item in value:
        if isinstance(item, str) and item.strip().isdigit():
            item = int(item.strip())
        if type(item) is not int or not 0 <= item <= 255:
            raise ValueError("Choose rooms from the loaded map.")
        ids.append(item)
    if ids == [0]:
        return []
    if 0 in ids or len(set(ids)) != len(ids):
        raise ValueError("Choose either whole home or distinct rooms.")
    return ids


def merge_settings(job: dict[str, Any], changes: Any) -> tuple[dict[str, Any], bool]:
    param = schedule_param(job)
    if param is None:
        raise ValueError("Cleaning settings are read-only for this schedule format.")
    if not isinstance(changes, dict) or not changes or set(changes) - EDITABLE_SETTINGS:
        raise ValueError("Choose supported room and cleaning settings.")
    entry = param["params"][0]
    original = copy.deepcopy(entry)
    choices = setting_choices(original)
    for key, value in changes.items():
        if key == "segments":
            ids = segment_ids(value)
            value = ",".join(map(str, ids)) if ids else "0"
        elif key == "map_index":
            if type(value) is not int or not 0 <= value < 63:
                raise ValueError("Choose a saved map reported by this vacuum.")
        elif type(value) is not int or value not in {option["value"] for option in choices[key]}:
            raise ValueError("Choose an available cleaning option.")
        entry[key] = value
    needs_rooms = any(key in changes and original.get(key) != entry.get(key) for key in ("segments", "map_index"))
    return param, needs_rooms


def _object(value: Any) -> dict[str, Any]:
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if not isinstance(value, dict):
        raise RoomCatalogError("The vacuum did not report a usable map. Open its saved map in LocalRock and refresh rooms.")
    return value


def _map_flag(status: Any) -> int:
    value = _object(status).get("map_status")
    if type(value) is not int or value < 0 or value >> 2 >= 63 or not value & 1:
        raise RoomCatalogError("Load a saved map in LocalRock, then refresh rooms here.")
    return value >> 2


def build_room_catalog(before: Any, maps: Any, mapping: Any, after: Any, inventory: dict[str, Any]) -> dict[str, Any]:
    flag = _map_flag(before)
    if flag != _map_flag(after):
        raise RoomCatalogError("The loaded map changed while reading rooms. Refresh rooms and try again.")
    names = {}
    home = inventory.get("home") if isinstance(inventory.get("home"), dict) else {}
    inventory_rooms = inventory.get("rooms") or home.get("rooms") or []
    if not isinstance(inventory_rooms, list):
        inventory_rooms = []
    for room in inventory_rooms:
        if isinstance(room, dict) and room.get("id") is not None and isinstance(room.get("name"), str):
            names[str(room["id"])] = room["name"]
    if not isinstance(mapping, list):
        raise RoomCatalogError("The vacuum could not supply its room list. Refresh rooms after opening the map in LocalRock.")
    rooms = []
    seen = set()
    for entry in mapping:
        if not isinstance(entry, list) or len(entry) < 2 or type(entry[0]) is not int or not 1 <= entry[0] <= 255 or entry[0] in seen:
            raise RoomCatalogError("The vacuum reported an ambiguous room list. Refresh rooms before editing.")
        seen.add(entry[0])
        room_id = str(entry[1])
        rooms.append({"id": entry[0], "room_id": room_id, "name": names.get(room_id) or f"Room {entry[0]}"})
    saved_maps = []
    map_info = _object(maps).get("map_info", [])
    if not isinstance(map_info, list):
        raise RoomCatalogError("The vacuum did not report its saved maps. Refresh rooms and try again.")
    for item in map_info:
        if isinstance(item, dict) and type(item.get("mapFlag")) is int and 0 <= item["mapFlag"] < 63:
            saved_maps.append({"id": item["mapFlag"], "name": str(item.get("name") or f"Map {item['mapFlag'] + 1}")})
    if not any(item["id"] == flag for item in saved_maps):
        saved_maps.append({"id": flag, "name": f"Map {flag + 1}"})
    catalog = {"map_index": flag, "maps": sorted(saved_maps, key=lambda item: item["id"]), "rooms": sorted(rooms, key=lambda item: item["id"])}
    catalog["revision"] = hashlib.sha256(json.dumps(catalog, sort_keys=True).encode()).hexdigest()
    catalog["checked_at"] = datetime.now(timezone.utc).isoformat()
    return catalog


async def read_room_catalog(supervisor: Any, duid: str, *, load_map: int | None = None) -> dict[str, Any]:
    from shared.routine_runner import _RoutineMqttClient

    device = supervisor.runtime_credentials.resolve_device(duid=duid)
    if device is None or not device.get("localkey"):
        raise KeyError(duid)
    client = None
    try:
        async with asyncio.timeout(30):
            client = _RoutineMqttClient(supervisor.context, device, logging.getLogger(__name__))
            await client.connect()
            before = await client.send_command(ReadCommand.STATUS, [])
            maps = await client.send_command(ReadCommand.MAPS, [])
            # Opening the editor is read-only. Loading a floor requires a
            # separate, explicit POST action and a fresh idle-state check.
            if load_map is not None:
                status = _object(before)
                if status.get("state") not in (3, 8, 100) or status.get("in_cleaning", 0) not in (0, None):
                    raise RoomCatalogError("Wait until the vacuum is idle or docked with no unfinished clean before loading another map.")
                available = _object(maps).get("map_info")
                if not isinstance(available, list) or not any(isinstance(item, dict) and item.get("mapFlag") == load_map for item in available):
                    raise RoomCatalogError("This saved map is no longer available. Refresh rooms and choose a map.")
                try:
                    await client.send_command(ReadCommand.LOAD_MAP, [load_map])
                except Exception as exc:
                    payload = exc.args[0] if exc.args and isinstance(exc.args[0], dict) else {}
                    if payload.get("code", getattr(exc, "code", None)) != -10005:
                        raise
                    # Newer firmware can require the data/need_retry envelope.
                    await client.send_command(ReadCommand.LOAD_MAP, {"data": [load_map], "need_retry": 1})
                # Some models acknowledge with ["retry"]. The fresh status,
                # rather than an acknowledgement alone, confirms the floor.
                for _ in range(16):
                    before = await client.send_command(ReadCommand.STATUS, [])
                    try:
                        if _map_flag(before) == load_map:
                            break
                    except RoomCatalogError:
                        pass
                    await asyncio.sleep(0.5)
                else:
                    raise RoomCatalogError("The map is still loading. Wait a moment, then Refresh rooms.")
            mapping = await client.send_command(ReadCommand.ROOMS, [])
            after = await client.send_command(ReadCommand.STATUS, [])
            inventory = json.loads(supervisor.paths.inventory_path.read_text())
            return build_room_catalog(before, maps, mapping, after, inventory)
    except RoomCatalogError:
        raise
    except Exception as exc:
        raise RoomCatalogError("Could not read rooms from this vacuum. Make sure it is connected locally, then try Refresh rooms.") from exc
    finally:
        if client is not None:
            try:
                await client.close()
            except Exception:
                logging.getLogger(__name__).warning("Unable to close schedule room-query connection")


def validate_rooms(param: dict[str, Any], catalog: dict[str, Any], revision: Any) -> None:
    if not isinstance(revision, str) or revision != catalog["revision"]:
        raise RoomCatalogError("The map or room list changed. Refresh rooms and review your selection before saving.")
    entry = param["params"][0]
    selected = segment_ids(entry.get("segments", "0"))
    if not selected:
        if entry.get("map_index") not in {item["id"] for item in catalog["maps"]}:
            raise RoomCatalogError("The selected map is no longer available. Refresh rooms and choose a map.")
        return
    if entry.get("map_index") != catalog["map_index"]:
        raise RoomCatalogError("Load the selected map in LocalRock and refresh rooms before saving.")
    if not set(selected) <= {room["id"] for room in catalog["rooms"]}:
        raise RoomCatalogError("A selected room is no longer on this map. Refresh rooms and choose again.")
