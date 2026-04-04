"""Shared scene-state services for /user/scene endpoints."""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Sequence

from shared.context import ServerContext
from shared.data_helpers import as_bool, as_int, default_home_id, get_value, stable_int
from shared.inventory_io import WEB_API_INVENTORY_FILE, load_inventory, write_inventory
from shared.routine_runner import RoutineExecutionError, RoutineRunner

_LOGGER = logging.getLogger(__name__)


def _first_non_empty(values: Sequence[str]) -> str:
    for value in values:
        if value:
            return value
    return ""


def _scene_state(ctx: ServerContext) -> dict[str, Any]:
    inventory = load_inventory(ctx)
    home_value = inventory.get("home")
    home = home_value if isinstance(home_value, dict) else {}
    home_id = as_int(
        get_value(home, "rr_home_id", "rrHomeId", "home_id", "id", default=default_home_id(ctx)),
        default_home_id(ctx),
    )
    scenes_value = inventory.get("scenes")
    scenes = scenes_value if isinstance(scenes_value, list) else []
    scene_order_value = inventory.get("scene_order")
    scene_order = scene_order_value if isinstance(scene_order_value, list) else []
    return {"home_id": home_id, "scenes": scenes, "scene_order": scene_order}


def _parse_json_body_params(body_params: dict[str, list[str]]) -> dict[str, Any]:
    raw_candidates = list(body_params.get("__json") or [])
    if not raw_candidates and len(body_params) == 1:
        raw_key, raw_values = next(iter(body_params.items()))
        if raw_values == [""] and str(raw_key).lstrip().startswith(("{", "[")):
            raw_candidates.append(str(raw_key))

    for raw_candidate in raw_candidates:
        try:
            parsed = json.loads(raw_candidate)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def scene_request_from_body(body_params: dict[str, list[str]]) -> dict[str, Any]:
    scene_request = _parse_json_body_params(body_params)
    if scene_request:
        return scene_request
    return {
        key: values[0] if len(values) == 1 else list(values)
        for key, values in body_params.items()
        if not key.startswith("__") and values != [""]
    }


def _scene_param_json_string(param_payload: dict[str, Any]) -> str:
    return json.dumps(param_payload, ensure_ascii=False, separators=(",", ":"))


def _scene_param_payload(scene_request: dict[str, Any]) -> dict[str, Any]:
    if isinstance(scene_request, dict) and isinstance(scene_request.get("action"), dict):
        return scene_request
    param_value = get_value(scene_request, "param", default={})
    if isinstance(param_value, dict):
        return param_value
    if isinstance(param_value, str) and param_value.strip():
        try:
            parsed = json.loads(param_value)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def _scene_zone_key(tid: str, zid: int) -> tuple[str, int] | None:
    normalized_tid = str(tid or "").strip()
    if not normalized_tid or zid < 0:
        return None
    return normalized_tid, zid


def _scene_zone_range(raw_zone: dict[str, Any]) -> list[int] | None:
    range_value = raw_zone.get("range")
    if not isinstance(range_value, list) or len(range_value) < 4:
        return None
    return [as_int(value, 0) for value in range_value[:4]]


def _merge_scene_zone_ranges_from_request(
    zone_ranges: dict[tuple[str, int], list[int]],
    *,
    params: Any,
    tids_filter: set[str] | None,
) -> None:
    if not isinstance(params, dict):
        return
    data = params.get("data")
    if not isinstance(data, list):
        return
    for entry in data:
        if not isinstance(entry, dict):
            continue
        tid = str(entry.get("tid") or "").strip()
        if tids_filter and tid not in tids_filter:
            continue
        zones = entry.get("zones")
        if not isinstance(zones, list):
            continue
        for zone in zones:
            if not isinstance(zone, dict):
                continue
            range_value = _scene_zone_range(zone)
            key = _scene_zone_key(tid, as_int(zone.get("zid"), -1))
            if key is None or range_value is None:
                continue
            zone_ranges[key] = range_value


def _merge_scene_zone_ranges_from_response(
    zone_ranges: dict[tuple[str, int], list[int]],
    *,
    request_params: Any,
    result: Any,
    tids_filter: set[str] | None,
) -> None:
    if not isinstance(request_params, dict) or not isinstance(result, list):
        return
    request_data = request_params.get("data")
    if not isinstance(request_data, list):
        return
    for request_entry, result_entry in zip(request_data, result):
        if not isinstance(request_entry, dict) or not isinstance(result_entry, dict):
            continue
        tid = str(result_entry.get("tid") or request_entry.get("tid") or "").strip()
        if tids_filter and tid not in tids_filter:
            continue
        request_zones = request_entry.get("zones")
        result_zones = result_entry.get("zones")
        if not isinstance(request_zones, list) or not isinstance(result_zones, list):
            continue
        for index, request_zone in enumerate(request_zones):
            if not isinstance(request_zone, dict):
                continue
            result_zone = result_zones[index] if index < len(result_zones) and isinstance(result_zones[index], dict) else {}
            range_value = _scene_zone_range(request_zone)
            key = _scene_zone_key(tid, as_int(result_zone.get("zid", request_zone.get("zid")), -1))
            if key is None or range_value is None:
                continue
            zone_ranges[key] = range_value


def _scene_zone_ranges_from_mqtt(
    ctx: ServerContext,
    *,
    tids_filter: set[str] | None = None,
) -> dict[tuple[str, int], list[int]]:
    path = ctx.mqtt_jsonl
    if not path.exists():
        return {}
    zone_ranges: dict[tuple[str, int], list[int]] = {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            lines = handle.readlines()
        for line in reversed(lines):
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
                    _merge_scene_zone_ranges_from_request(
                        zone_ranges,
                        params=rpc.get("params"),
                        tids_filter=tids_filter,
                    )
                response_to = decoded.get("response_to")
                if isinstance(response_to, dict) and str(response_to.get("request_method") or "").strip() == "set_scenes_zones":
                    _merge_scene_zone_ranges_from_response(
                        zone_ranges,
                        request_params=response_to.get("request_params"),
                        result=response_to.get("result"),
                        tids_filter=tids_filter,
                    )
            if tids_filter and all(
                any(key[0] == tid for key in zone_ranges) for tid in tids_filter
            ):
                break
    except OSError:
        return {}
    return zone_ranges


def _scene_zone_tids(param_payload: dict[str, Any]) -> set[str]:
    action = param_payload.get("action")
    items = action.get("items") if isinstance(action, dict) else []
    tids: set[str] = set()
    if not isinstance(items, list):
        return tids
    for item in items:
        if not isinstance(item, dict):
            continue
        raw_param = item.get("param")
        if isinstance(raw_param, str):
            try:
                inner = json.loads(raw_param)
            except json.JSONDecodeError:
                continue
        elif isinstance(raw_param, dict):
            inner = raw_param
        else:
            continue
        if not isinstance(inner, dict) or str(inner.get("method") or "").strip() != "do_scenes_zones":
            continue
        params = inner.get("params")
        data = params.get("data") if isinstance(params, dict) else []
        if not isinstance(data, list):
            continue
        for entry in data:
            if not isinstance(entry, dict):
                continue
            tid = str(entry.get("tid") or "").strip()
            if tid:
                tids.add(tid)
    return tids


def _scene_zone_ranges_from_store(
    ctx: ServerContext,
    *,
    tids_filter: set[str] | None = None,
) -> dict[tuple[str, int], list[int]]:
    if ctx.zone_ranges_store is None:
        return {}
    return ctx.zone_ranges_store.get_all(tids=tids_filter)


def _hydrate_scene_param_with_zone_ranges(
    ctx: ServerContext,
    param_payload: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    tids = _scene_zone_tids(param_payload)
    if not tids:
        return param_payload, False
    zone_ranges = _scene_zone_ranges_from_store(ctx, tids_filter=tids)
    if not zone_ranges:
        zone_ranges = _scene_zone_ranges_from_mqtt(ctx, tids_filter=tids)
    if not zone_ranges:
        return param_payload, False
    try:
        hydrated_payload = json.loads(_scene_param_json_string(param_payload))
    except (TypeError, ValueError):
        return param_payload, False

    changed = False
    action = hydrated_payload.get("action")
    items = action.get("items") if isinstance(action, dict) else []
    if not isinstance(items, list):
        return param_payload, False
    for item in items:
        if not isinstance(item, dict):
            continue
        raw_param = item.get("param")
        nested_as_string = isinstance(raw_param, str)
        if nested_as_string:
            try:
                nested = json.loads(raw_param)
            except json.JSONDecodeError:
                continue
        elif isinstance(raw_param, dict):
            nested = dict(raw_param)
        else:
            continue
        if not isinstance(nested, dict) or str(nested.get("method") or "").strip() != "do_scenes_zones":
            continue
        params = nested.get("params")
        data = params.get("data") if isinstance(params, dict) else []
        if not isinstance(data, list):
            continue

        item_changed = False
        new_data: list[Any] = []
        for entry in data:
            if not isinstance(entry, dict):
                new_data.append(entry)
                continue
            tid = str(entry.get("tid") or "").strip()
            zones = entry.get("zones")
            if not isinstance(zones, list):
                new_data.append(entry)
                continue
            new_entry = dict(entry)
            new_zones: list[Any] = []
            entry_changed = False
            for zone in zones:
                if not isinstance(zone, dict):
                    new_zones.append(zone)
                    continue
                range_value = zone_ranges.get((tid, as_int(zone.get("zid"), -1)))
                if range_value is None:
                    new_zones.append(zone)
                    continue
                new_zone = dict(zone)
                if new_zone.get("range") != range_value:
                    new_zone["range"] = list(range_value)
                    entry_changed = True
                new_zones.append(new_zone)
            if entry_changed:
                new_entry["zones"] = new_zones
                item_changed = True
            new_data.append(new_entry)
        if not item_changed:
            continue
        new_params = dict(params)
        new_params["data"] = new_data
        nested["params"] = new_params
        item["param"] = _scene_param_json_string(nested) if nested_as_string else nested
        changed = True
    return (hydrated_payload if changed else param_payload), changed


def build_scene_payload(
    scene: dict[str, Any],
    *,
    home_id: int | None,
    include_device_context: bool,
) -> dict[str, Any]:
    scene_id = as_int(get_value(scene, "id", default=0), 0)
    payload: dict[str, Any] = {
        "id": scene_id,
        "name": str(get_value(scene, "name", default=f"Routine {scene_id}" if scene_id else "Routine")),
        "enabled": as_bool(get_value(scene, "enabled", default=True), True),
        "type": str(get_value(scene, "type", default="WORKFLOW")),
    }
    if home_id is not None:
        payload["homeId"] = home_id
    if include_device_context:
        scene_device = str(get_value(scene, "device_id", "deviceId", "duid", default="")).strip()
        if scene_device:
            payload["deviceId"] = scene_device
        scene_device_name = str(get_value(scene, "device_name", "deviceName", default="")).strip()
        if scene_device_name:
            payload["deviceName"] = scene_device_name
    param = get_value(scene, "param")
    if param is not None or "param" in scene:
        payload["param"] = param
    extra = scene.get("extra") if "extra" in scene else get_value(scene, "extra")
    if extra is not None or "extra" in scene:
        payload["extra"] = extra
    tag_id = get_value(scene, "tagId", "tag_id")
    if tag_id is not None:
        payload["tagId"] = str(tag_id)
    return payload


def _inventory_home_id(ctx: ServerContext, inventory: dict[str, Any]) -> int:
    home_value = inventory.get("home")
    home = home_value if isinstance(home_value, dict) else {}
    return as_int(
        get_value(home, "id", "home_id", "rrHomeId", "rr_home_id", default=default_home_id(ctx)),
        default_home_id(ctx),
    )


def _scene_device_id(scene_request: dict[str, Any], inventory: dict[str, Any], ctx: ServerContext) -> str:
    explicit_device_id = str(get_value(scene_request, "deviceId", "device_id", default="")).strip()
    if explicit_device_id:
        return explicit_device_id

    param_payload = _scene_param_payload(scene_request)
    action_payload = param_payload.get("action")
    items = action_payload.get("items") if isinstance(action_payload, dict) else []
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            entity_id = str(get_value(item, "entityId", "entity_id", default="")).strip()
            if entity_id:
                return entity_id

    for collection_key in ("devices", "received_devices", "receivedDevices"):
        devices_value = inventory.get(collection_key)
        devices = devices_value if isinstance(devices_value, list) else []
        for device in devices:
            if not isinstance(device, dict):
                continue
            candidate = str(get_value(device, "duid", "did", "device_id", "deviceId", default="")).strip()
            if candidate:
                return candidate
    return ctx.duid


def _scene_device_name(inventory: dict[str, Any], device_id: str) -> str:
    normalized_device_id = str(device_id).strip()
    for collection_key in ("devices", "received_devices", "receivedDevices"):
        devices_value = inventory.get(collection_key)
        devices = devices_value if isinstance(devices_value, list) else []
        for device in devices:
            if not isinstance(device, dict):
                continue
            candidate = str(get_value(device, "duid", "did", "device_id", "deviceId", default="")).strip()
            if candidate != normalized_device_id:
                continue
            name = str(get_value(device, "name", "device_name", default="")).strip()
            if name:
                return name
    return ""


def _replace_inventory_scene(
    ctx: ServerContext,
    *,
    scene_id: int,
    scene_updater: Callable[[dict[str, Any], dict[str, Any]], None],
) -> tuple[dict[str, Any], int]:
    inventory = load_inventory(ctx)
    if not isinstance(inventory, dict):
        inventory = {}

    scenes_source = inventory.get("scenes")
    scenes = [dict(scene) for scene in scenes_source if isinstance(scene, dict)] if isinstance(scenes_source, list) else []
    updated_scene: dict[str, Any] | None = None
    for index, scene in enumerate(scenes):
        if as_int(get_value(scene, "id", default=0), 0) != scene_id:
            continue
        candidate = dict(scene)
        scene_updater(candidate, inventory)
        scenes[index] = candidate
        updated_scene = candidate
        break

    if updated_scene is None:
        raise RoutineExecutionError(f"Scene {scene_id} not found")

    inventory["scenes"] = scenes
    home_id = _inventory_home_id(ctx, inventory)
    inventory["home_scenes"] = [
        build_scene_payload(scene, home_id=home_id, include_device_context=True)
        for scene in scenes
        if isinstance(scene, dict)
    ]
    write_inventory(ctx, inventory)
    return updated_scene, home_id


def _hydrate_inventory_scene_ranges(ctx: ServerContext, scene: dict[str, Any]) -> dict[str, Any]:
    scene_id = as_int(get_value(scene, "id", default=0), 0)
    if scene_id <= 0:
        return scene
    param_payload = _scene_param_payload(scene)
    tids = _scene_zone_tids(param_payload)
    hydrated_payload, changed = _hydrate_scene_param_with_zone_ranges(ctx, param_payload)
    if not changed:
        if tids:
            _LOGGER.warning(
                "Scene %s has zone tids %s but no range data was hydrated from MQTT log",
                scene_id,
                tids,
            )
        return scene

    _LOGGER.info("Scene %s: hydrated zone ranges for tids %s from MQTT log", scene_id, tids)

    def apply_update(updated_scene: dict[str, Any], inventory: dict[str, Any]) -> None:
        _ = inventory
        updated_scene["param"] = _scene_param_json_string(hydrated_payload)

    updated_scene, _ = _replace_inventory_scene(ctx, scene_id=scene_id, scene_updater=apply_update)
    return updated_scene


def _create_inventory_scene(ctx: ServerContext, scene_request: dict[str, Any]) -> dict[str, Any]:
    inventory = load_inventory(ctx)
    if not isinstance(inventory, dict):
        inventory = {}

    scenes_source = inventory.get("scenes")
    scenes = [dict(scene) for scene in scenes_source if isinstance(scene, dict)] if isinstance(scenes_source, list) else []

    home_id = as_int(get_value(scene_request, "homeId", default=default_home_id(ctx)), default_home_id(ctx))
    scene_name = str(get_value(scene_request, "name", default=f"Routine {len(scenes) + 1}")).strip() or f"Routine {len(scenes) + 1}"
    scene_id = max((as_int(get_value(scene, "id", default=0), 0) for scene in scenes), default=0) + 1
    if scene_id <= 0:
        scene_id = (stable_int(f"{home_id}:{scene_name}") % 9_000_000) + 1_000_000

    param_payload = _scene_param_payload(scene_request)
    param_payload, _ = _hydrate_scene_param_with_zone_ranges(ctx, param_payload)
    device_id = _scene_device_id(scene_request, inventory, ctx)
    device_name = _scene_device_name(inventory, device_id)
    tag_id = get_value(scene_request, "tagId", default=get_value(param_payload, "tagId"))

    scene_record: dict[str, Any] = {
        "id": scene_id,
        "name": scene_name,
        "param": _scene_param_json_string(param_payload),
        "enabled": as_bool(get_value(scene_request, "enabled", default=True), True),
        "extra": scene_request.get("extra") if isinstance(scene_request, dict) and "extra" in scene_request else None,
        "type": str(get_value(scene_request, "type", default="WORKFLOW")),
        "device_id": device_id,
        "device_name": device_name,
    }
    if tag_id is not None:
        scene_record["tagId"] = str(tag_id)

    scenes.append(scene_record)
    inventory["scenes"] = scenes

    scene_order_value = inventory.get("scene_order")
    if isinstance(scene_order_value, list):
        scene_order = [as_int(value, 0) for value in scene_order_value if as_int(value, 0) > 0]
    else:
        scene_order = [as_int(get_value(scene, "id", default=0), 0) for scene in scenes[:-1] if as_int(get_value(scene, "id", default=0), 0) > 0]
    scene_order.append(scene_id)
    inventory["scene_order"] = scene_order

    home_scenes_value = inventory.get("home_scenes")
    home_scenes = [dict(scene) for scene in home_scenes_value if isinstance(scene, dict)] if isinstance(home_scenes_value, list) else []
    home_scenes.append(build_scene_payload(scene_record, home_id=home_id, include_device_context=True))
    inventory["home_scenes"] = home_scenes

    home_value = inventory.get("home")
    home = dict(home_value) if isinstance(home_value, dict) else {}
    if get_value(home, "id", "home_id", "rrHomeId", "rr_home_id") is None and home_id > 0:
        home["id"] = home_id
    inventory["home"] = home
    write_inventory(ctx, inventory)
    return scene_record


def _split_param_values(values: Sequence[str]) -> list[str]:
    split_values: list[str] = []
    for value in values:
        for part in str(value or "").split(","):
            candidate = part.strip()
            if candidate:
                split_values.append(candidate)
    return split_values


def _routine_runner_for_context(ctx: ServerContext) -> RoutineRunner:
    runner = getattr(ctx, "_routine_runner", None)
    if runner is None:
        runner = RoutineRunner(ctx)
        setattr(ctx, "_routine_runner", runner)
    return runner


def list_scenes_for_device(ctx: ServerContext, device_id: str) -> list[dict[str, Any]]:
    scenes = _scene_state(ctx)["scenes"]
    filtered: list[dict[str, Any]] = []
    for scene in scenes:
        if not isinstance(scene, dict):
            continue
        scene_device = get_value(scene, "device_id", "deviceId", "duid")
        if scene_device and str(scene_device) != str(device_id):
            continue
        filtered.append(build_scene_payload(scene, home_id=None, include_device_context=False))
    return filtered


def list_scenes_for_home(ctx: ServerContext, requested_home_id: Any) -> list[dict[str, Any]]:
    state = _scene_state(ctx)
    home_id = state["home_id"]
    requested_id = as_int(requested_home_id, 0)
    if requested_id and requested_id != home_id:
        return []
    return [
        build_scene_payload(scene, home_id=home_id, include_device_context=True)
        for scene in state["scenes"]
        if isinstance(scene, dict)
    ]


def scene_order(ctx: ServerContext, query_params: dict[str, list[str]]) -> list[int]:
    state = _scene_state(ctx)
    requested_home_id = as_int(_split_param_values(query_params.get("homeId", []))[0] if query_params.get("homeId") else 0, 0)
    home_id = state["home_id"]
    if requested_home_id and requested_home_id != home_id:
        return []
    allowed_device_ids = set(_split_param_values(query_params.get("duids", [])))
    scenes_by_id = {
        as_int(get_value(scene, "id", default=0), 0): scene
        for scene in state["scenes"]
        if isinstance(scene, dict) and as_int(get_value(scene, "id", default=0), 0) > 0
    }
    ordered_scene_ids: list[int] = []
    existing_scene_order = state.get("scene_order")
    if isinstance(existing_scene_order, list):
        for raw_scene_id in existing_scene_order:
            scene_id = as_int(raw_scene_id, 0)
            if scene_id <= 0 or scene_id in ordered_scene_ids:
                continue
            scene = scenes_by_id.get(scene_id)
            if not isinstance(scene, dict):
                continue
            scene_device = str(get_value(scene, "device_id", "deviceId", "duid", default="")).strip()
            if allowed_device_ids and scene_device not in allowed_device_ids:
                continue
            ordered_scene_ids.append(scene_id)
    for scene in state["scenes"]:
        if not isinstance(scene, dict):
            continue
        scene_device = str(get_value(scene, "device_id", "deviceId", "duid", default="")).strip()
        if allowed_device_ids and scene_device not in allowed_device_ids:
            continue
        scene_id = as_int(get_value(scene, "id", default=0), 0)
        if scene_id > 0 and scene_id not in ordered_scene_ids:
            ordered_scene_ids.append(scene_id)
    return ordered_scene_ids


def create_scene(ctx: ServerContext, body_params: dict[str, list[str]]) -> dict[str, Any]:
    scene_request = scene_request_from_body(body_params)
    created_scene = _create_inventory_scene(ctx, scene_request)
    home_id = as_int(get_value(scene_request, "homeId", default=default_home_id(ctx)), default_home_id(ctx))
    return build_scene_payload(created_scene, home_id=home_id, include_device_context=True)


def execute_scene(ctx: ServerContext, scene_id: int) -> Any:
    state = _scene_state(ctx)
    scene = next(
        (
            dict(candidate)
            for candidate in state["scenes"]
            if isinstance(candidate, dict) and as_int(get_value(candidate, "id", default=0), 0) == scene_id
        ),
        None,
    )
    if scene is None:
        raise RoutineExecutionError(f"Scene {scene_id} not found")
    _LOGGER.info("Executing scene %s (%s)", scene_id, get_value(scene, "name", default=""))
    scene = _hydrate_inventory_scene_ranges(ctx, scene)
    return _routine_runner_for_context(ctx).start_scene(scene)


def update_scene_name(ctx: ServerContext, scene_id: int, body_params: dict[str, list[str]]) -> dict[str, Any]:
    scene_name = _first_non_empty(body_params.get("name") or [])
    if not scene_name:
        scene_request = scene_request_from_body(body_params)
        scene_name = str(get_value(scene_request, "name", default="")).strip()
    if not scene_name:
        raise RoutineExecutionError(f"Scene {scene_id} name is required")

    def apply_update(updated_scene: dict[str, Any], inventory: dict[str, Any]) -> None:
        _ = inventory
        updated_scene["name"] = scene_name

    updated_scene, home_id = _replace_inventory_scene(ctx, scene_id=scene_id, scene_updater=apply_update)
    return build_scene_payload(updated_scene, home_id=home_id, include_device_context=True)


def update_scene_param(ctx: ServerContext, scene_id: int, body_params: dict[str, list[str]]) -> dict[str, Any]:
    scene_request = scene_request_from_body(body_params)
    param_payload = _scene_param_payload(scene_request)
    if not param_payload:
        raise RoutineExecutionError(f"Scene {scene_id} param payload is required")
    param_payload, _ = _hydrate_scene_param_with_zone_ranges(ctx, param_payload)

    def apply_update(updated_scene: dict[str, Any], inventory: dict[str, Any]) -> None:
        updated_scene["param"] = _scene_param_json_string(param_payload)
        device_id = _scene_device_id(scene_request, inventory, ctx)
        if device_id:
            updated_scene["device_id"] = device_id
            device_name = _scene_device_name(inventory, device_id)
            if device_name:
                updated_scene["device_name"] = device_name
        if "enabled" in scene_request:
            updated_scene["enabled"] = as_bool(get_value(scene_request, "enabled", default=True), True)
        if "type" in scene_request:
            updated_scene["type"] = str(get_value(scene_request, "type", default="WORKFLOW"))
        if "extra" in scene_request:
            updated_scene["extra"] = scene_request.get("extra")
        tag_id = get_value(scene_request, "tagId", default=get_value(param_payload, "tagId"))
        if tag_id is not None:
            updated_scene["tagId"] = str(tag_id)

    updated_scene, home_id = _replace_inventory_scene(ctx, scene_id=scene_id, scene_updater=apply_update)
    return build_scene_payload(updated_scene, home_id=home_id, include_device_context=True)

