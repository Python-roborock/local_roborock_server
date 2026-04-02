"""Shared device-state services for /user/devices endpoints."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Sequence

from roborock_local_server.inventory import _extract_inventory_vacuums
from roborock_local_server.inventory import _merge_vacuum_state
from shared.constants import DEFAULT_TIMEZONE
from shared.context import ServerContext
from shared.data_helpers import as_bool, as_int, default_product_name, get_value
from shared.inventory_io import WEB_API_INVENTORY_FILE, load_inventory
_DEFAULT_DEVICE_NAME = "Vacuum 1"


def _has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def _cloud_snapshot_path(ctx: ServerContext):
    inventory_path = ctx.http_jsonl.parent / WEB_API_INVENTORY_FILE
    return inventory_path.with_name(f"{inventory_path.stem}_full_snapshot.json")


def _load_cloud_full_snapshot(ctx: ServerContext) -> dict[str, Any] | None:
    full_snapshot_path = _cloud_snapshot_path(ctx)
    if not full_snapshot_path.exists():
        return None
    try:
        parsed = json.loads(full_snapshot_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _load_cloud_home_data(ctx: ServerContext) -> dict[str, Any] | None:
    parsed = _load_cloud_full_snapshot(ctx)
    if not isinstance(parsed, dict):
        return None
    home_data = parsed.get("home_data")
    return home_data if isinstance(home_data, dict) else None


def _device_records(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    out: list[dict[str, Any]] = []
    for key in ("devices", "receivedDevices", "received_devices"):
        value = payload.get(key)
        if not isinstance(value, list):
            continue
        out.extend(item for item in value if isinstance(item, dict))
    return out


def _product_records(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    value = payload.get("products")
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _merge_matching_records(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for record in records:
        for key, value in record.items():
            if key in merged and _has_value(merged[key]):
                continue
            if not _has_value(value):
                continue
            merged[key] = value
    return merged


def _find_device_record(payloads: Sequence[dict[str, Any] | None], device_id: str) -> dict[str, Any]:
    normalized_device_id = str(device_id or "").strip()
    if not normalized_device_id:
        return {}
    matches: list[dict[str, Any]] = []
    for payload in payloads:
        for item in _device_records(payload):
            candidate = str(get_value(item, "duid", "did", "device_id", "deviceId", default="")).strip()
            if candidate == normalized_device_id:
                matches.append(dict(item))
    return _merge_matching_records(matches)


def _find_product_record(payloads: Sequence[dict[str, Any] | None], product_id: str) -> dict[str, Any]:
    normalized_product_id = str(product_id or "").strip()
    if not normalized_product_id:
        return {}
    matches: list[dict[str, Any]] = []
    for payload in payloads:
        for item in _product_records(payload):
            candidate = str(get_value(item, "id", "productId", "product_id", default="")).strip()
            if candidate == normalized_product_id:
                matches.append(dict(item))
    return _merge_matching_records(matches)


def _inventory_devices(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    for key in ("devices", "received_devices", "receivedDevices"):
        value = inventory.get(key)
        if isinstance(value, list):
            devices.extend(item for item in value if isinstance(item, dict))
    return [dict(item) for item in devices]


def _product_from_device_record(raw_item: dict[str, Any]) -> dict[str, Any]:
    product_id = str(get_value(raw_item, "product_id", "productId", default="")).strip()
    if not product_id:
        return {}
    product: dict[str, Any] = {
        "id": product_id,
        "name": str(get_value(raw_item, "product_name", "productName", default="")),
        "model": str(get_value(raw_item, "model", default="")),
        "category": str(get_value(raw_item, "category", default="")),
        "code": str(get_value(raw_item, "code", default="")),
        "iconUrl": str(get_value(raw_item, "iconUrl", "icon_url", default="")),
    }
    capability = get_value(raw_item, "capability")
    if capability is not None:
        product["capability"] = capability
    schema = get_value(raw_item, "schema")
    if isinstance(schema, list):
        product["schema"] = schema
    return {key: value for key, value in product.items() if value is not None and value != ""}


def _normalize_rooms(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    home_data = inventory.get("home")
    home = home_data if isinstance(home_data, dict) else {}
    rooms_value = get_value(home, "rooms")
    if rooms_value is None:
        rooms_value = inventory.get("rooms")
    rooms_list = rooms_value if isinstance(rooms_value, list) else []
    rooms: list[dict[str, Any]] = []
    for index, room in enumerate(rooms_list):
        room_data = room if isinstance(room, dict) else {}
        room_id = as_int(get_value(room_data, "id", "room_id", default=index + 1), index + 1)
        room_name = str(get_value(room_data, "name", default=f"Room {index + 1}"))
        rooms.append({"id": room_id, "name": room_name})
    if rooms:
        return rooms
    return [{"id": 1, "name": "Living Room"}]


def _normalize_devices(
    ctx: ServerContext,
    devices_raw: list[dict[str, Any]],
    *,
    now_ts: int,
    default_name_prefix: str = "Vacuum",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    products_by_id: dict[str, dict[str, Any]] = {}
    devices: list[dict[str, Any]] = []
    for index, raw in enumerate(devices_raw):
        raw_item = raw if isinstance(raw, dict) else {}
        fallback_duid = ctx.duid if index == 0 else f"{ctx.duid}_{index + 1}"
        duid = str(get_value(raw_item, "duid", "did", "device_id", "deviceId", default=fallback_duid)).strip()
        local_key = ctx.resolve_device_localkey(
            did=str(get_value(raw_item, "did", "device_did", default="")),
            duid=duid,
            model=str(get_value(raw_item, "model", default="")),
            name=str(get_value(raw_item, "name", "device_name", default="")),
            product_id=str(get_value(raw_item, "product_id", "productId", default="")),
            source="web_home_data",
            assign_if_missing=True,
        )
        product_id = str(get_value(raw_item, "product_id", "productId", default=f"product_{index + 1}")).strip()
        model = str(get_value(raw_item, "model", default="roborock.vacuum.a117"))
        category = str(get_value(raw_item, "category", default="robot.vacuum.cleaner"))
        product_name = str(get_value(raw_item, "product_name", "productName", default=default_product_name(model)))
        timezone = str(get_value(raw_item, "timezone", "timeZoneId", "time_zone_id", default=DEFAULT_TIMEZONE))
        room_id_value = get_value(raw_item, "room_id", "roomId")
        room_id = as_int(room_id_value, 0) if room_id_value is not None else None
        device = {
            "duid": duid,
            "name": str(get_value(raw_item, "name", "device_name", default=f"{default_name_prefix} {index + 1}")),
            "localKey": local_key,
            "productId": product_id,
            "fv": str(get_value(raw_item, "fv", "firmware", "firmware_version", default="02.33.88")),
            "pv": str(get_value(raw_item, "pv", "protocol_version", default="1.0")),
            "activeTime": as_int(get_value(raw_item, "active_time", "activeTime", default=now_ts), now_ts),
            "timeZoneId": timezone,
            "online": as_bool(get_value(raw_item, "online", default=True), True),
            "sn": str(
                get_value(
                    raw_item,
                    "sn",
                    "serial_number",
                    default=f"RR{hashlib.sha256(duid.encode()).hexdigest()[:12].upper()}",
                )
            ),
        }
        if room_id is not None and room_id > 0:
            device["roomId"] = room_id
        feature_set = get_value(raw_item, "feature_set", "featureSet")
        if feature_set is not None:
            device["featureSet"] = str(feature_set)
        new_feature_set = get_value(raw_item, "new_feature_set", "newFeatureSet")
        if new_feature_set is not None:
            device["newFeatureSet"] = str(new_feature_set)
        devices.append(device)

        if product_id not in products_by_id:
            product = {
                "id": product_id,
                "name": product_name,
                "model": model,
                "category": category,
                "code": str(get_value(raw_item, "code", default=model.split(".")[-1] if model else "a117")),
                "iconUrl": str(get_value(raw_item, "icon_url", "iconUrl", default="")),
            }
            capability = get_value(raw_item, "capability")
            if capability is not None:
                product["capability"] = capability
            schema = get_value(raw_item, "schema")
            if isinstance(schema, list):
                product["schema"] = schema
            products_by_id[product_id] = product
    return devices, list(products_by_id.values())


def resolve_home_id(*sources: dict[str, Any] | None, default: int = 0) -> int:
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in ("id", "rr_home_id", "rrHomeId", "home_id"):
            resolved = as_int(source.get(key), 0)
            if resolved > 0:
                return resolved
    return default


def _runtime_device_identity_map(ctx: ServerContext) -> tuple[dict[str, dict[str, Any]], bool]:
    try:
        inventory_vacuums = _extract_inventory_vacuums(ctx, load_inventory(ctx))
        merged_vacuums = _merge_vacuum_state(context=ctx, inventory_vacuums=inventory_vacuums)
    except Exception:
        return {}, False

    identity_map: dict[str, dict[str, Any]] = {}
    any_runtime_connected = False
    for item in merged_vacuums:
        if not isinstance(item, dict):
            continue
        connected = as_bool(item.get("connected"), False)
        any_runtime_connected = any_runtime_connected or connected
        for key in ("duid", "did", "linked_inventory_duid", "runtime_did"):
            value = str(item.get(key) or "").strip()
            if value and value not in identity_map:
                identity_map[value] = item
    return identity_map, any_runtime_connected


def _runtime_device_for_record(
    raw_item: dict[str, Any],
    *,
    runtime_device_map: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    for key in ("duid", "did", "device_did", "deviceDid", "device_id", "deviceId"):
        value = raw_item.get(key)
        if value is None:
            continue
        normalized = str(value).strip()
        if normalized and normalized in runtime_device_map:
            return runtime_device_map[normalized]
    return {}


def _apply_runtime_online_status(ctx: ServerContext, home_data: dict[str, Any]) -> dict[str, Any]:
    runtime_device_map, any_runtime_connected = _runtime_device_identity_map(ctx)
    if not any_runtime_connected:
        return home_data

    enriched_home = dict(home_data)
    for collection_key in ("devices", "receivedDevices", "received_devices"):
        devices_value = home_data.get(collection_key)
        devices = devices_value if isinstance(devices_value, list) else []
        if not isinstance(devices_value, list):
            continue
        updated_devices: list[dict[str, Any]] = []
        for device in devices:
            if not isinstance(device, dict):
                continue
            updated_device = dict(device)
            runtime_device = _runtime_device_for_record(
                updated_device,
                runtime_device_map=runtime_device_map,
            )
            updated_device["online"] = as_bool(runtime_device.get("connected"), False)
            updated_devices.append(updated_device)
        enriched_home[collection_key] = updated_devices
    return enriched_home


def enrich_home_data_with_cloud_snapshot(ctx: ServerContext, home_data: dict[str, Any]) -> dict[str, Any]:
    cloud_home_data = _load_cloud_home_data(ctx) or {}
    if not cloud_home_data:
        return home_data

    enriched_home = dict(home_data)

    products_value = home_data.get("products")
    products = products_value if isinstance(products_value, list) else []
    enriched_products: list[dict[str, Any]] = []
    for product in products:
        if not isinstance(product, dict):
            continue
        merged_product = dict(product)
        product_id = str(get_value(product, "id", "productId", "product_id", default="")).strip()
        raw_product = _find_product_record((cloud_home_data,), product_id)
        if raw_product:
            icon_url = get_value(raw_product, "iconUrl", "icon_url")
            if icon_url is not None:
                merged_product["iconUrl"] = str(icon_url)
            capability = get_value(raw_product, "capability")
            if capability is not None:
                merged_product["capability"] = capability
            schema = get_value(raw_product, "schema")
            if isinstance(schema, list):
                merged_product["schema"] = schema
        enriched_products.append(merged_product)
    if enriched_products:
        enriched_home["products"] = enriched_products

    rooms_value = home_data.get("rooms")
    rooms = rooms_value if isinstance(rooms_value, list) else []
    room_name_by_id = {
        as_int(room.get("id"), 0): str(room.get("name") or "")
        for room in rooms
        if isinstance(room, dict)
    }

    for collection_key in ("devices", "receivedDevices"):
        devices_value = home_data.get(collection_key)
        devices = devices_value if isinstance(devices_value, list) else []
        enriched_devices: list[dict[str, Any]] = []
        for device in devices:
            if not isinstance(device, dict):
                continue
            merged_device = dict(device)
            device_id = str(get_value(device, "duid", "did", "device_id", "deviceId", default="")).strip()
            raw_device = _find_device_record((cloud_home_data,), device_id)
            if raw_device:
                for source_keys, target_key in (
                    (("iconUrl", "icon_url"), "iconUrl"),
                    (("share",), "share"),
                    (("tuyaMigrated",), "tuyaMigrated"),
                    (("extra",), "extra"),
                    (("featureSet", "feature_set"), "featureSet"),
                    (("newFeatureSet", "new_feature_set"), "newFeatureSet"),
                    (("deviceStatus",), "deviceStatus"),
                    (("silentOtaSwitch",), "silentOtaSwitch"),
                    (("f",), "f"),
                    (("createTime", "create_time"), "createTime"),
                    (("cid",), "cid"),
                ):
                    value = get_value(raw_device, *source_keys)
                    if value is None or value == "":
                        continue
                    merged_device[target_key] = value
                room_id_value = get_value(raw_device, "roomId", "room_id")
                if room_id_value is not None:
                    room_id = as_int(room_id_value, 0)
                    if room_id > 0:
                        merged_device["roomId"] = room_id
                        room_name = room_name_by_id.get(room_id, "")
                        if room_name:
                            merged_device["roomName"] = room_name
            enriched_devices.append(merged_device)
        if enriched_devices:
            enriched_home[collection_key] = enriched_devices

    return enriched_home


def _home_data(ctx: ServerContext) -> dict[str, Any]:
    inventory = load_inventory(ctx)
    home_value = inventory.get("home")
    home = dict(home_value) if isinstance(home_value, dict) else {}
    cloud_home_data = _load_cloud_home_data(ctx) or {}
    now_ts = int(time.time())

    raw_devices = inventory.get("devices")
    devices_source = raw_devices if isinstance(raw_devices, list) and raw_devices else [{}]
    devices, products = _normalize_devices(
        ctx,
        devices_source,
        now_ts=now_ts,
    )

    raw_received = get_value(inventory, "received_devices", "receivedDevices", default=[])
    received_source = raw_received if isinstance(raw_received, list) else []
    received_devices, received_products = _normalize_devices(
        ctx,
        received_source,
        now_ts=now_ts,
        default_name_prefix="Shared Vacuum",
    )
    for product in received_products:
        product_id = str(product.get("id") or "").strip()
        if product_id and all(str(existing.get("id") or "").strip() != product_id for existing in products):
            products.append(product)

    home["devices"] = devices
    home["receivedDevices"] = received_devices
    home["products"] = products
    home["rooms"] = _normalize_rooms(inventory)

    home["id"] = resolve_home_id(home, cloud_home_data, default=0)
    home["name"] = str(get_value(home, "name", "home_name", default="Local Home"))
    return _apply_runtime_online_status(ctx, home)


def device_detail_payload(ctx: ServerContext, device_id: str) -> dict[str, Any]:
    home_data = _home_data(ctx)
    inventory = load_inventory(ctx)
    cloud_home_data = _load_cloud_home_data(ctx) or {}

    normalized_devices: list[dict[str, Any]] = []
    for key in ("devices", "receivedDevices"):
        value = home_data.get(key)
        if isinstance(value, list):
            normalized_devices.extend(item for item in value if isinstance(item, dict))
    normalized_device = next(
        (
            dict(item)
            for item in normalized_devices
            if str(get_value(item, "duid", "did", default="")).strip() == device_id
        ),
        {},
    )
    raw_device = _find_device_record((cloud_home_data, inventory), device_id)

    product_id = str(
        get_value(
            raw_device,
            "productId",
            "product_id",
            default=get_value(normalized_device, "productId", "product_id", default=""),
        )
    ).strip()
    normalized_product = next(
        (
            dict(item)
            for item in (home_data.get("products") if isinstance(home_data.get("products"), list) else [])
            if str(get_value(item, "id", default="")).strip() == product_id
        ),
        {},
    )
    raw_product = _find_product_record((cloud_home_data,), product_id)

    room_name_by_id = {
        as_int(room.get("id"), 0): str(room.get("name") or "")
        for room in (home_data.get("rooms") if isinstance(home_data.get("rooms"), list) else [])
        if isinstance(room, dict)
    }
    room_id_value = get_value(
        raw_device,
        "roomId",
        "room_id",
        default=get_value(normalized_device, "roomId", "room_id", default=None),
    )
    room_id = as_int(room_id_value, 0) if room_id_value is not None else 0
    runtime_device_map, any_runtime_connected = _runtime_device_identity_map(ctx)
    connectivity_source = dict(raw_device)
    for key, value in normalized_device.items():
        connectivity_source.setdefault(key, value)
    runtime_device = _runtime_device_for_record(
        connectivity_source,
        runtime_device_map=runtime_device_map,
    )
    runtime_online = as_bool(runtime_device.get("connected"), False)
    inventory_online = as_bool(
        get_value(normalized_device, "online", default=get_value(raw_device, "online", default=False)),
        False,
    )
    resolved_online = runtime_online if any_runtime_connected else inventory_online

    product_payload: dict[str, Any] = {}
    if product_id:
        product_payload = {
            "id": product_id,
            "name": str(get_value(raw_product, "name", default=get_value(normalized_product, "name", default=""))),
            "model": str(
                get_value(raw_product, "model", default=get_value(normalized_product, "model", default=""))
            ),
            "category": str(
                get_value(raw_product, "category", default=get_value(normalized_product, "category", default=""))
            ),
        }
        capability = get_value(raw_product, "capability", default=get_value(normalized_product, "capability"))
        if capability is not None:
            product_payload["capability"] = capability
        schema = get_value(raw_product, "schema", default=get_value(normalized_product, "schema"))
        if isinstance(schema, list):
            product_payload["schema"] = schema

    payload: dict[str, Any] = {
        "duid": str(
            get_value(raw_device, "duid", "did", "device_id", "deviceId", default=device_id or ctx.duid)
        ).strip(),
        "name": str(
            get_value(raw_device, "name", "device_name", default=get_value(normalized_device, "name", default=""))
        ),
        "attribute": get_value(raw_device, "attribute", default=None),
        "localKey": str(
            get_value(
                raw_device,
                "localKey",
                "local_key",
                "localkey",
                default=get_value(normalized_device, "localKey", default=ctx.localkey),
            )
        ),
        "productId": product_id,
        "fv": str(get_value(raw_device, "fv", default=get_value(normalized_device, "fv", default=""))),
        "pv": str(get_value(raw_device, "pv", default=get_value(normalized_device, "pv", default=""))),
        "activeTime": as_int(
            get_value(
                raw_device,
                "activeTime",
                "active_time",
                default=get_value(normalized_device, "activeTime", default=0),
            ),
            0,
        ),
        "runtimeEnv": get_value(raw_device, "runtimeEnv", "runtime_env", default=None),
        "timeZoneId": str(
            get_value(
                raw_device,
                "timeZoneId",
                "time_zone_id",
                "timezone",
                default=get_value(normalized_device, "timeZoneId", default=DEFAULT_TIMEZONE),
            )
        ),
        "iconUrl": str(
            get_value(
                raw_device,
                "iconUrl",
                "icon_url",
                default=get_value(normalized_device, "iconUrl", "icon_url", default=""),
            )
        ),
        "lon": get_value(raw_device, "lon", default=None),
        "lat": get_value(raw_device, "lat", default=None),
        "online": resolved_online,
        "share": as_bool(get_value(raw_device, "share", default=get_value(normalized_device, "share", default=False)), False),
        "shareTime": get_value(
            raw_device,
            "shareTime",
            "share_time",
            default=get_value(normalized_device, "shareTime", "share_time", default=None),
        ),
        "tuyaMigrated": as_bool(
            get_value(raw_device, "tuyaMigrated", default=get_value(normalized_device, "tuyaMigrated", default=False)),
            False,
        ),
        "extra": get_value(raw_device, "extra", default=get_value(normalized_device, "extra", default="{}")) or "{}",
        "sn": str(get_value(raw_device, "sn", default=get_value(normalized_device, "sn", default=""))),
        "deviceStatus": get_value(
            raw_device,
            "deviceStatus",
            default=get_value(normalized_device, "deviceStatus", default={}),
        )
        or {},
        "silentOtaSwitch": as_bool(
            get_value(
                raw_device,
                "silentOtaSwitch",
                default=get_value(normalized_device, "silentOtaSwitch", default=False),
            ),
            False,
        ),
        "f": as_bool(get_value(raw_device, "f", default=get_value(normalized_device, "f", default=False)), False),
        "homeId": as_int(get_value(home_data, "id", default=0), 0),
        "homeName": str(get_value(home_data, "name", default="")),
        "roomId": room_id_value,
        "tuyaUuid": get_value(raw_device, "tuyaUuid", "tuya_uuid", default=None),
        "setting": get_value(raw_device, "setting", default=None),
    }
    if room_id > 0:
        room_name = room_name_by_id.get(room_id, "")
        if room_name:
            payload["roomName"] = room_name
    feature_set = get_value(
        raw_device,
        "featureSet",
        "feature_set",
        default=get_value(normalized_device, "featureSet"),
    )
    if feature_set is not None:
        payload["featureSet"] = str(feature_set)
    new_feature_set = get_value(
        raw_device,
        "newFeatureSet",
        "new_feature_set",
        default=get_value(normalized_device, "newFeatureSet"),
    )
    if new_feature_set is not None:
        payload["newFeatureSet"] = str(new_feature_set)
    create_time = get_value(raw_device, "createTime", "create_time")
    if create_time is not None:
        payload["createTime"] = as_int(create_time, 0)
    payload["cid"] = get_value(raw_device, "cid", default=None)
    payload["shareType"] = get_value(raw_device, "shareType", "share_type", default=None)
    payload["shareExpiredTime"] = get_value(raw_device, "shareExpiredTime", "share_expired_time", default=None)
    if product_payload:
        payload["product"] = product_payload
        payload["productName"] = str(product_payload.get("name") or "")
        payload["model"] = str(product_payload.get("model") or "")
        payload["category"] = str(product_payload.get("category") or "")
        if "capability" in product_payload:
            payload["capability"] = product_payload["capability"]
        if isinstance(product_payload.get("schema"), list):
            payload["schema"] = product_payload["schema"]
    return payload


def device_jobs_payload(ctx: ServerContext, device_id: str) -> list[dict[str, Any]]:
    schedules_map = load_inventory(ctx).get("schedules")
    schedules_raw = schedules_map.get(device_id) if isinstance(schedules_map, dict) else None
    if not isinstance(schedules_raw, list):
        schedules_raw = []
    schedules: list[dict[str, Any]] = []
    for index, schedule in enumerate(schedules_raw):
        raw = schedule if isinstance(schedule, dict) else {}
        schedules.append(
            {
                "id": as_int(get_value(raw, "id", default=index + 1), index + 1),
                "cron": str(get_value(raw, "cron", default="0 0 * * *")),
                "repeated": as_bool(get_value(raw, "repeated", default=True), True),
                "enabled": as_bool(get_value(raw, "enabled", default=True), True),
                "param": get_value(raw, "param", default={}) or {},
            }
        )
    return schedules


def add_device_payload(ctx: ServerContext) -> dict[str, Any]:
    home_data = _home_data(ctx)
    devices_value = home_data.get("devices")
    devices = devices_value if isinstance(devices_value, list) else []
    first_device = devices[0] if devices else {"duid": ctx.duid, "name": _DEFAULT_DEVICE_NAME}
    return {
        "duid": first_device.get("duid"),
        "name": first_device.get("name"),
    }
