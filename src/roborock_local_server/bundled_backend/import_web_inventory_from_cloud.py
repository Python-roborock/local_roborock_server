#!/usr/bin/env python
"""Import web_api_inventory.json from Roborock cloud home_data.

This helper fetches home_data using existing Roborock user_data credentials and
writes a local inventory file that endpoint_rules.py consumes.
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

import aiohttp
from roborock.data import HomeData, HomeDataDevice, HomeDataProduct, RRiot, UserData
from roborock.exceptions import RoborockRateLimit
from roborock.web_api import PreparedRequest, RoborockApiClient, _get_hawk_authentication


def _find_repo_root() -> Path:
    current = Path(__file__).resolve().parent
    for candidate in (current, *current.parents):
        if (candidate / "python-roborock").exists():
            return candidate
    return current


REPO_ROOT = _find_repo_root()
DEFAULT_ENV_FILE = REPO_ROOT / "python-roborock" / ".env"
DEFAULT_OUTPUT_FILE = Path(__file__).resolve().with_name("web_api_inventory.json")
DEFAULT_HA_CONFIG_ENTRIES_PATH = "/homeassistant/.storage/core.config_entries"
DEFAULT_LOGIN_SESSION_FILE = Path(__file__).resolve().with_name("cloud_login_session.json")


def _load_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _extract_roborock_entry(
    config_entries: dict[str, Any], entry_id: str | None = None
) -> dict[str, Any]:
    entries = (
        config_entries.get("data", {}).get("entries", [])
        if isinstance(config_entries, dict)
        else []
    )
    roborock_entries = [
        entry
        for entry in entries
        if isinstance(entry, dict) and entry.get("domain") == "roborock"
    ]
    if not roborock_entries:
        raise RuntimeError("No roborock config entry found in HA core.config_entries")
    if entry_id:
        for entry in roborock_entries:
            if entry.get("entry_id") == entry_id:
                return entry
        raise RuntimeError(f"Requested roborock entry_id not found: {entry_id}")
    enabled_entries = [e for e in roborock_entries if not e.get("disabled_by")]
    if enabled_entries:
        return enabled_entries[0]
    return roborock_entries[0]


def _build_user_data_source_from_ha_entry(entry: dict[str, Any]) -> tuple[str, str | None, dict[str, Any]]:
    data = entry.get("data", {}) if isinstance(entry, dict) else {}
    username = data.get("username")
    user_data = data.get("user_data")
    base_url = data.get("base_url")
    if not isinstance(username, str) or not username:
        raise RuntimeError("Selected HA roborock entry is missing username")
    if not isinstance(user_data, dict):
        raise RuntimeError("Selected HA roborock entry is missing user_data")
    return username, base_url if isinstance(base_url, str) else None, user_data


def _load_source_from_json_file(
    source_file: Path,
    username_override: str | None = None,
    base_url_override: str | None = None,
) -> tuple[str, str | None, dict[str, Any]]:
    payload = json.loads(source_file.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected object in {source_file}, got {type(payload).__name__}")

    # Accept multiple shapes:
    # 1) {"username": "...", "base_url": "...", "user_data": {...}}
    # 2) {"data": {"username": "...", "base_url": "...", "user_data": {...}}} (HA entry-like)
    # 3) raw user_data object + --username
    if isinstance(payload.get("user_data"), dict):
        username = payload.get("username")
        base_url = payload.get("base_url")
        user_data = payload["user_data"]
    elif isinstance(payload.get("data"), dict) and isinstance(payload["data"].get("user_data"), dict):
        username = payload["data"].get("username")
        base_url = payload["data"].get("base_url")
        user_data = payload["data"]["user_data"]
    else:
        username = None
        base_url = None
        user_data = payload

    if username_override:
        username = username_override
    if base_url_override:
        base_url = base_url_override
    if not isinstance(username, str) or not username:
        raise RuntimeError(
            "Username is missing. Provide --username or include username in the source JSON."
        )
    if not isinstance(user_data, dict):
        raise RuntimeError("Source user_data is not an object")
    return username, base_url if isinstance(base_url, str) else None, user_data


def _ssh_read_ha_config_entries(
    host: str,
    user: str,
    password: str,
    config_entries_path: str,
) -> dict[str, Any]:
    try:
        import paramiko  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "paramiko is required for --from-ha-ssh mode. Install with: pip install paramiko"
        ) from exc

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=user, password=password, timeout=20)
    try:
        command = f"sudo -n cat {config_entries_path}"
        _, stdout, stderr = client.exec_command(command)
        raw = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace").strip()
        if err:
            raise RuntimeError(f"Failed to read HA config entries via SSH: {err}")
        return json.loads(raw)
    finally:
        client.close()


def _category_to_string(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "value"):
        inner = getattr(value, "value")
        if isinstance(inner, str):
            return inner
    return str(value)


def _first_present(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return None


def _normalize_room_list(rooms_source: list[Any] | None) -> list[dict[str, Any]]:
    rooms: list[dict[str, Any]] = []
    for room in rooms_source or []:
        if isinstance(room, dict):
            room_id = room.get("id")
            room_name = room.get("name")
        else:
            room_id = getattr(room, "id", None)
            room_name = getattr(room, "name", None)
        if room_id is None or room_name in (None, ""):
            continue
        rooms.append({"id": room_id, "name": room_name})
    return rooms


def _normalize_dict_list(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    return [dict(item) for item in items if isinstance(item, dict)]


def _normalize_schedule_map(value: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(value, dict):
        return {}
    schedules: dict[str, list[dict[str, Any]]] = {}
    for device_id, items in value.items():
        schedules[str(device_id)] = _normalize_dict_list(items)
    return schedules


def _normalize_dict_map(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        return {}
    return {str(key): dict(item) for key, item in value.items() if isinstance(item, dict)}


def _normalize_value_map(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items()}


def _to_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_jsonable(item) for item in value]
    if is_dataclass(value):
        return _to_jsonable(asdict(value))
    as_dict = getattr(value, "as_dict", None)
    if callable(as_dict):
        return _to_jsonable(as_dict())
    return str(value)


def _annotate_device_scenes(
    scenes: list[dict[str, Any]],
    *,
    device_id: str,
    device_name: str,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for scene in scenes:
        enriched = dict(scene)
        enriched["device_id"] = str(_first_present(enriched.get("device_id"), enriched.get("deviceId"), device_id))
        if device_name:
            enriched["device_name"] = str(
                _first_present(enriched.get("device_name"), enriched.get("deviceName"), device_name)
            )
        output.append(enriched)
    return output


def _flatten_device_scenes(device_scenes: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for scenes in device_scenes.values():
        flattened.extend(_normalize_dict_list(scenes))
    return flattened


def _device_to_inventory_item(
    device: HomeDataDevice,
    product: HomeDataProduct | None,
    index: int,
    default_name_prefix: str,
    *,
    device_detail: dict[str, Any] | None = None,
    device_extra: Any = None,
) -> dict[str, Any]:
    detail = device_detail if isinstance(device_detail, dict) else {}
    item: dict[str, Any] = {
        "duid": str(_first_present(detail.get("duid"), getattr(device, "duid", None), f"device-{index + 1}")),
        "name": str(
            _first_present(detail.get("name"), getattr(device, "name", None), f"{default_name_prefix} {index + 1}")
        ),
        "local_key": _first_present(detail.get("localKey"), getattr(device, "local_key", None)),
        "product_id": _first_present(detail.get("productId"), getattr(device, "product_id", None)),
        "pv": _first_present(detail.get("pv"), getattr(device, "pv", None)),
        "fv": _first_present(detail.get("fv"), getattr(device, "fv", None)),
        "timeZoneId": _first_present(detail.get("timeZoneId"), getattr(device, "time_zone_id", None)),
        "room_id": _first_present(detail.get("roomId"), getattr(device, "room_id", None)),
        "online": _first_present(detail.get("online"), getattr(device, "online", None)),
        "sn": _first_present(detail.get("sn"), getattr(device, "sn", None)),
    }
    optional_device_fields = (
        ("activeTime", _first_present(detail.get("activeTime"), getattr(device, "active_time", None))),
        ("iconUrl", _first_present(detail.get("iconUrl"), getattr(device, "icon_url", None))),
        ("share", _first_present(detail.get("share"), getattr(device, "share", None))),
        ("tuyaMigrated", _first_present(detail.get("tuyaMigrated"), getattr(device, "tuya_migrated", None))),
        ("extra", _first_present(device_extra, detail.get("extra"), getattr(device, "extra", None))),
        ("featureSet", _first_present(detail.get("featureSet"), getattr(device, "feature_set", None))),
        ("newFeatureSet", _first_present(detail.get("newFeatureSet"), getattr(device, "new_feature_set", None))),
        ("deviceStatus", _first_present(detail.get("deviceStatus"), getattr(device, "device_status", None))),
        ("silentOtaSwitch", _first_present(detail.get("silentOtaSwitch"), getattr(device, "silent_ota_switch", None))),
        ("f", _first_present(detail.get("f"), getattr(device, "f", None))),
        ("createTime", _first_present(detail.get("createTime"), getattr(device, "create_time", None))),
        ("cid", _first_present(detail.get("cid"), getattr(device, "cid", None))),
        ("attribute", detail.get("attribute")),
        ("runtimeEnv", detail.get("runtimeEnv")),
        ("shareTime", detail.get("shareTime")),
        ("tuyaUuid", detail.get("tuyaUuid")),
        ("setting", detail.get("setting")),
        ("shareType", detail.get("shareType")),
        ("shareExpiredTime", detail.get("shareExpiredTime")),
        ("lon", detail.get("lon")),
        ("lat", detail.get("lat")),
    )
    for key, value in optional_device_fields:
        if value is not None and value != "":
            item[key] = value
    if product is not None:
        item["product_name"] = product.name
        item["model"] = product.model
        category = _category_to_string(product.category)
        if category:
            item["category"] = category
        capability = getattr(product, "capability", None)
        if capability is not None:
            item["capability"] = capability
        schema = getattr(product, "schema", None)
        if schema is not None:
            item["schema"] = schema
    return {k: _to_jsonable(v) for k, v in item.items() if v is not None and v != ""}


def _all_home_devices(home_data: HomeData) -> list[HomeDataDevice]:
    return [*(home_data.devices or []), *(home_data.received_devices or [])]


def _require_rriot(user_data: UserData) -> RRiot:
    rriot = user_data.rriot
    if rriot is None or rriot.r is None or rriot.r.a is None:
        raise RuntimeError("User data is missing RRiot credentials required for Hawk-authenticated web calls.")
    return rriot


async def _hawk_get_result(
    api: RoborockApiClient,
    user_data: UserData,
    path: str,
    *,
    params: dict[str, Any] | None = None,
) -> Any:
    rriot = _require_rriot(user_data)
    request = PreparedRequest(rriot.r.a, api.session)
    response = await request.request(
        "get",
        path,
        params=params,
        headers={"Authorization": _get_hawk_authentication(rriot, path, params=params)},
    )
    if not isinstance(response, dict):
        raise RuntimeError(f"Unexpected response type for {path}: {type(response).__name__}")
    if not response.get("success"):
        raise RuntimeError(f"Cloud request failed for {path}: {response}")
    return response.get("result")


async def _request_cloud_api_data(
    api: RoborockApiClient,
    user_data: UserData,
    path: str,
    *,
    method: str = "get",
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> Any:
    base_url = await api.base_url
    header_clientid = getattr(api, "_get_header_client_id", lambda: "")()
    headers = {"Authorization": str(user_data.token or "")}
    if json_body is not None:
        headers["Content-Type"] = "application/json"
    request = PreparedRequest(base_url, api.session, {"header_clientid": header_clientid})
    response = await request.request(method, path, params=params, json=json_body, headers=headers)
    if not isinstance(response, dict):
        raise RuntimeError(f"Unexpected response type for {path}: {type(response).__name__}")
    if response.get("code") != 200:
        raise RuntimeError(f"Cloud request failed for {path}: {response}")
    return response.get("data")


def _plugin_product_ids(home_data: HomeData) -> list[int]:
    product_ids: set[int] = set()
    for product in home_data.products or []:
        try:
            product_ids.add(int(product.id))
        except (TypeError, ValueError):
            continue
    for device in _all_home_devices(home_data):
        try:
            product_ids.add(int(getattr(device, "product_id", 0) or 0))
        except (TypeError, ValueError):
            continue
    return sorted(product_id for product_id in product_ids if product_id > 0)


async def _fetch_plugin_catalogs(
    api: RoborockApiClient,
    user_data: UserData,
    home_data: HomeData,
) -> dict[str, Any]:
    """Fetch app/plugin catalog metadata from cloud without making import depend on it."""
    fetched_at = datetime.now(timezone.utc).isoformat()
    catalogs: dict[str, Any] = {"fetched_at_utc": fetched_at}

    async def fetch_catalog(
        name: str,
        path: str,
        *,
        method: str = "get",
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> None:
        try:
            catalogs[name] = {
                "path": path,
                "method": method.upper(),
                "params": dict(params or {}),
                "json": dict(json_body or {}),
                "data": await _request_cloud_api_data(
                    api,
                    user_data,
                    path,
                    method=method,
                    params=params,
                    json_body=json_body,
                ),
            }
        except Exception as exc:  # noqa: BLE001
            catalogs[name] = {
                "path": path,
                "method": method.upper(),
                "params": dict(params or {}),
                "json": dict(json_body or {}),
                "error": str(exc),
            }

    await fetch_catalog(
        "appfeatureplugin",
        "/api/v1/appfeatureplugin",
        params={"type": 2, "apiLevel": 10043},
    )
    await fetch_catalog(
        "plugins",
        "/api/v1/plugins",
        params={"type": 2, "apiLevel": 10043},
    )
    product_ids = _plugin_product_ids(home_data)
    if product_ids:
        await fetch_catalog(
            "appplugin",
            "/api/v1/appplugin",
            method="post",
            json_body={"type": 2, "apilevel": 10043, "productids": product_ids},
        )
    else:
        catalogs["appplugin"] = {
            "path": "/api/v1/appplugin",
            "method": "POST",
            "json": {"type": 2, "apilevel": 10043, "productids": []},
            "error": "no product ids available",
        }
    return catalogs


async def _fetch_additional_web_cache(
    api: RoborockApiClient,
    user_data: UserData,
    home_data: HomeData,
) -> dict[str, Any]:
    home_id = int(getattr(home_data, "id", 0) or 0)
    if home_id <= 0:
        raise RuntimeError("home_data is missing a valid home id")

    rooms_result = await _hawk_get_result(api, user_data, f"/user/homes/{home_id}/rooms")
    home_scenes_result = await _hawk_get_result(api, user_data, f"/user/scene/home/{home_id}")
    scene_order_result = await _hawk_get_result(
        api,
        user_data,
        "/user/scene/order",
        params={"homeId": str(home_id)},
    )

    rooms = _normalize_room_list(rooms_result if isinstance(rooms_result, list) else None)
    home_scenes = _normalize_dict_list(home_scenes_result)
    if not isinstance(scene_order_result, list):
        raise RuntimeError(f"Unexpected scene order payload type: {type(scene_order_result).__name__}")

    device_scenes: dict[str, list[dict[str, Any]]] = {}
    device_schedules: dict[str, list[dict[str, Any]]] = {}
    device_details: dict[str, dict[str, Any]] = {}
    device_extras: dict[str, Any] = {}

    for index, device in enumerate(_all_home_devices(home_data)):
        device_id = str(getattr(device, "duid", "") or "").strip()
        if not device_id:
            continue
        device_name = str(getattr(device, "name", None) or f"Vacuum {index + 1}")

        device_scenes_result = await _hawk_get_result(api, user_data, f"/user/scene/device/{device_id}")
        if not isinstance(device_scenes_result, list):
            raise RuntimeError(
                f"Unexpected scene payload type for device {device_id}: {type(device_scenes_result).__name__}"
            )
        device_scenes[device_id] = _annotate_device_scenes(
            _normalize_dict_list(device_scenes_result),
            device_id=device_id,
            device_name=device_name,
        )

        schedules_result = await _hawk_get_result(api, user_data, f"/user/devices/{device_id}/jobs")
        if not isinstance(schedules_result, list):
            raise RuntimeError(
                f"Unexpected schedule payload type for device {device_id}: {type(schedules_result).__name__}"
            )
        device_schedules[device_id] = _normalize_dict_list(schedules_result)

        device_detail_result = await _hawk_get_result(api, user_data, f"/user/devices/{device_id}")
        if not isinstance(device_detail_result, dict):
            raise RuntimeError(
                f"Unexpected device detail payload type for device {device_id}: {type(device_detail_result).__name__}"
            )
        device_details[device_id] = dict(device_detail_result)
        device_extras[device_id] = await _hawk_get_result(api, user_data, f"/user/devices/{device_id}/extra")

    plugin_catalogs = await _fetch_plugin_catalogs(api, user_data, home_data)

    return {
        "rooms": rooms,
        "home_scenes": home_scenes,
        "scene_order": list(scene_order_result),
        "device_scenes": device_scenes,
        "device_schedules": device_schedules,
        "device_details": device_details,
        "device_extras": device_extras,
        "plugin_catalogs": plugin_catalogs,
    }


def _build_inventory(
    home_data: HomeData,
    *,
    rooms: list[dict[str, Any]] | None = None,
    scenes: list[dict[str, Any]] | None = None,
    schedules: dict[str, list[dict[str, Any]]] | None = None,
    scene_order: list[Any] | None = None,
    home_scenes: list[dict[str, Any]] | None = None,
    device_details: dict[str, dict[str, Any]] | None = None,
    device_extras: dict[str, Any] | None = None,
) -> dict[str, Any]:
    products_by_id = {product.id: product for product in (home_data.products or [])}
    device_details_map = _normalize_dict_map(device_details)
    device_extras_map = _normalize_value_map(device_extras)

    devices: list[dict[str, Any]] = []
    for i, device in enumerate(home_data.devices or []):
        device_id = str(getattr(device, "duid", "") or "")
        devices.append(
            _device_to_inventory_item(
                device=device,
                product=products_by_id.get(device.product_id),
                index=i,
                default_name_prefix="Vacuum",
                device_detail=device_details_map.get(device_id),
                device_extra=device_extras_map.get(device_id),
            )
        )

    received_devices: list[dict[str, Any]] = []
    for i, device in enumerate(home_data.received_devices or []):
        device_id = str(getattr(device, "duid", "") or "")
        received_devices.append(
            _device_to_inventory_item(
                device=device,
                product=products_by_id.get(device.product_id),
                index=i,
                default_name_prefix="Shared Vacuum",
                device_detail=device_details_map.get(device_id),
                device_extra=device_extras_map.get(device_id),
            )
        )

    normalized_rooms = _normalize_room_list(rooms) or _normalize_room_list(list(home_data.rooms or []))
    home_section: dict[str, Any] = {
        "id": home_data.id,
        "name": home_data.name,
        "rooms": normalized_rooms,
    }
    if home_data.lon is not None:
        home_section["lon"] = home_data.lon
    if home_data.lat is not None:
        home_section["lat"] = home_data.lat
    if home_data.geo_name is not None:
        home_section["geo_name"] = home_data.geo_name

    return _to_jsonable({
        "home": home_section,
        "rooms": normalized_rooms,
        "devices": devices,
        "received_devices": received_devices,
        "scenes": _normalize_dict_list(scenes),
        "home_scenes": _normalize_dict_list(home_scenes),
        "scene_order": list(scene_order or []),
        "schedules": _normalize_schedule_map(schedules),
        "device_details": device_details_map,
        "device_extras": device_extras_map,
    })


def _default_full_snapshot_path(inventory_path: Path) -> Path:
    return inventory_path.with_name(f"{inventory_path.stem}_full_snapshot.json")


async def _fetch_cloud_home_data(username: str, base_url: str | None, user_data_dict: dict[str, Any]) -> HomeData:
    _, home_data, _ = await _fetch_cloud_home_data_from_dict(
        username=username,
        base_url=base_url,
        user_data_dict=user_data_dict,
    )
    return home_data


async def _fetch_cloud_home_data_with_api(api: RoborockApiClient, user_data: UserData) -> HomeData:
    last_error: Exception | None = None
    for i, fetch in enumerate((api.get_home_data_v3, api.get_home_data_v2, api.get_home_data)):
        try:
            return await fetch(user_data)
        except RoborockRateLimit:
            # Keep original rate-limit error context; retries are unlikely to help immediately.
            raise
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if i < 2:
                # The library applies request rate-limits per method family.
                # Back off a bit before trying legacy endpoint variants.
                await asyncio.sleep(1.2)
    raise RuntimeError(f"Failed to fetch cloud home_data: {last_error}")


async def _fetch_cloud_home_data_from_dict(
    *,
    username: str,
    base_url: str | None,
    user_data_dict: dict[str, Any],
) -> tuple[dict[str, Any], HomeData, dict[str, Any]]:
    user_data = UserData.from_dict(user_data_dict)
    if user_data is None:
        raise RuntimeError("Unable to parse user_data")
    async with aiohttp.ClientSession() as session:
        api = RoborockApiClient(username=username, base_url=base_url, session=session)
        home_data = await _fetch_cloud_home_data_with_api(api, user_data)
        web_cache = await _fetch_additional_web_cache(api, user_data, home_data)
    return user_data.as_dict(), home_data, web_cache


def _load_json_dict(path: Path, *, kind: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"Unable to read {kind}: {path} ({exc})") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in {kind}: {path} ({exc})") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"{kind} must contain a JSON object: {path}")
    return payload


def _save_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _load_existing_inventory_for_merge(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return loaded if isinstance(loaded, dict) else None


def _record_identity(record: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = record.get(key)
        if value is None:
            continue
        normalized = str(value).strip()
        if normalized:
            return normalized
    return None


def _merge_record_lists_by_identity(
    cloud_records: Any,
    local_records: Any,
    *,
    identity_keys: tuple[str, ...],
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    index_by_identity: dict[str, int] = {}

    for raw in cloud_records if isinstance(cloud_records, list) else []:
        if not isinstance(raw, dict):
            continue
        record = dict(raw)
        identity = _record_identity(record, identity_keys)
        if identity is not None and identity not in index_by_identity:
            index_by_identity[identity] = len(merged)
        merged.append(record)

    for raw in local_records if isinstance(local_records, list) else []:
        if not isinstance(raw, dict):
            continue
        record = dict(raw)
        identity = _record_identity(record, identity_keys)
        if identity is not None and identity in index_by_identity:
            merged[index_by_identity[identity]] = record
            continue
        if identity is not None:
            index_by_identity[identity] = len(merged)
        merged.append(record)

    return merged


def _merge_scene_order(cloud_order: Any, local_order: Any) -> list[Any]:
    if not isinstance(local_order, list) or not local_order:
        return list(cloud_order) if isinstance(cloud_order, list) else []

    merged: list[Any] = []
    seen: set[str] = set()
    for value in [*local_order, *(cloud_order if isinstance(cloud_order, list) else [])]:
        normalized = str(value).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        merged.append(value)
    return merged


def _inventory_rooms(inventory: dict[str, Any]) -> Any:
    rooms = inventory.get("rooms")
    if isinstance(rooms, list):
        return rooms
    home = inventory.get("home")
    if isinstance(home, dict) and isinstance(home.get("rooms"), list):
        return home.get("rooms")
    return []


def _merge_existing_inventory_mutations(
    cloud_inventory: dict[str, Any],
    existing_inventory: dict[str, Any] | None,
) -> dict[str, Any]:
    """Preserve local app mutations when refreshing cloud-derived inventory."""

    if not isinstance(existing_inventory, dict) or not existing_inventory:
        return cloud_inventory

    merged = dict(cloud_inventory)

    rooms = _merge_record_lists_by_identity(
        _inventory_rooms(merged),
        _inventory_rooms(existing_inventory),
        identity_keys=("id", "room_id", "roomId"),
    )
    if rooms:
        merged["rooms"] = rooms
        home = dict(merged.get("home")) if isinstance(merged.get("home"), dict) else {}
        home["rooms"] = rooms
        merged["home"] = home

    scenes = _merge_record_lists_by_identity(
        merged.get("scenes"),
        existing_inventory.get("scenes"),
        identity_keys=("id", "scene_id", "sceneId"),
    )
    if scenes:
        merged["scenes"] = scenes

    home_scenes = _merge_record_lists_by_identity(
        merged.get("home_scenes"),
        existing_inventory.get("home_scenes"),
        identity_keys=("id", "scene_id", "sceneId"),
    )
    if home_scenes:
        merged["home_scenes"] = home_scenes

    merged["scene_order"] = _merge_scene_order(merged.get("scene_order"), existing_inventory.get("scene_order"))
    return merged


async def _request_cloud_login_code(email: str, base_url: str | None) -> dict[str, Any]:
    normalized_email = email.strip()
    if not normalized_email:
        raise RuntimeError("--email is required for --request-code")
    normalized_base_url = base_url.strip() if isinstance(base_url, str) else ""
    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(timeout=timeout) as http_session:
        api = RoborockApiClient(
            username=normalized_email,
            base_url=normalized_base_url or None,
            session=http_session,
        )
        await api.request_code_v4()
        return {
            "email": normalized_email,
            "base_url": str(await api.base_url),
            "country": str(await api.country),
            "country_code": str(await api.country_code),
            # Roborock login code flow expects the same header_clientid between request_code and code_login.
            "device_identifier": str(getattr(api, "_device_identifier", "") or ""),
            "requested_at_utc": datetime.now(timezone.utc).isoformat(),
            "source": "roborock_email_code_request",
        }


async def _login_with_code_and_fetch(
    *,
    email: str | None,
    code: str,
    base_url_override: str | None,
    login_session_file: Path,
) -> tuple[str, str | None, dict[str, Any], HomeData, dict[str, Any]]:
    normalized_code = code.strip()
    if not normalized_code:
        raise RuntimeError("--code cannot be empty")

    session_payload = _load_json_dict(login_session_file, kind="login session file")
    session_email = str(session_payload.get("email") or "").strip()
    normalized_email = (email or "").strip() or session_email
    if not normalized_email:
        raise RuntimeError("Missing email. Provide --email or run --request-code first.")
    if session_email and normalized_email.lower() != session_email.lower():
        raise RuntimeError(
            f"--email does not match login session email ({session_email}); "
            "request a fresh code for the target account."
        )

    base_url_candidate = (base_url_override or "").strip() or str(session_payload.get("base_url") or "").strip()
    resolved_base_url: str | None = base_url_candidate or None
    country = str(session_payload.get("country") or "").strip() or None
    country_code_raw = str(session_payload.get("country_code") or "").strip()
    country_code: int | None = int(country_code_raw) if country_code_raw.isdigit() else None
    device_identifier = str(session_payload.get("device_identifier") or "").strip()

    timeout = aiohttp.ClientTimeout(total=120)
    async with aiohttp.ClientSession(timeout=timeout) as http_session:
        api = RoborockApiClient(username=normalized_email, base_url=resolved_base_url, session=http_session)
        if device_identifier:
            setattr(api, "_device_identifier", device_identifier)
        user_data = await api.code_login_v4(
            normalized_code,
            country=country,
            country_code=country_code,
        )
        home_data = await _fetch_cloud_home_data_with_api(api, user_data)
        web_cache = await _fetch_additional_web_cache(api, user_data, home_data)
    return normalized_email, resolved_base_url, user_data.as_dict(), home_data, web_cache


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate web_api_inventory.json from Roborock cloud home_data."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_FILE,
        help=f"Output inventory path (default: {DEFAULT_OUTPUT_FILE})",
    )
    parser.add_argument(
        "--source-json",
        type=Path,
        help=(
            "Path to source JSON containing either "
            "{username, base_url, user_data}, "
            "{data:{username, base_url, user_data}}, "
            "or a raw user_data object (with --username)."
        ),
    )
    parser.add_argument("--username", help="Roborock account email (overrides source JSON)")
    parser.add_argument("--email", help="Roborock account email for direct login flow.")
    parser.add_argument("--base-url", help="Override API base URL (example: https://usiot.roborock.com)")

    parser.add_argument(
        "--request-code",
        action="store_true",
        help="Request Roborock login email code and save session metadata.",
    )
    parser.add_argument("--code", help="Roborock email verification code.")
    parser.add_argument(
        "--login-session-file",
        type=Path,
        default=DEFAULT_LOGIN_SESSION_FILE,
        help=f"Session metadata path for request-code/code flow (default: {DEFAULT_LOGIN_SESSION_FILE})",
    )
    parser.add_argument(
        "--print-only",
        action="store_true",
        help="Print inventory JSON to stdout and do not write output file.",
    )
    parser.add_argument(
        "--full-snapshot-output",
        type=Path,
        help=(
            "Path for full unredacted snapshot output "
            "(default: <output_stem>_full_snapshot.json)."
        ),
    )
    parser.add_argument(
        "--no-full-snapshot",
        action="store_true",
        help="Do not write full unredacted snapshot file.",
    )
    return parser.parse_args()


async def _main_async() -> None:
    args = _parse_args()

    if args.request_code and args.code:
        raise RuntimeError("Use either --request-code or --code, not both.")

    if args.request_code:
        session_payload = await _request_cloud_login_code(email=str(args.email or ""), base_url=args.base_url)
        _save_json(args.login_session_file, session_payload)
        print(f"Wrote login session: {args.login_session_file}")
        print(f"Email code requested for: {session_payload.get('email')}")
        print(f"Resolved base_url: {session_payload.get('base_url')}")
        print("Next: run this command after you receive the email code:")
        print(
            "python import_web_inventory_from_cloud.py "
            f"--code <EMAIL_CODE> --login-session-file \"{args.login_session_file}\""
        )
        return

    if args.code:
        username, base_url, user_data_dict, home_data, web_cache = await _login_with_code_and_fetch(
            email=args.email,
            code=args.code,
            base_url_override=args.base_url,
            login_session_file=args.login_session_file,
        )
        source_name = "roborock_email_code_login"
    elif args.source_json:
        username, base_url, user_data_dict = _load_source_from_json_file(
            source_file=args.source_json,
            username_override=args.username,
            base_url_override=args.base_url,
        )
        user_data_dict, home_data, web_cache = await _fetch_cloud_home_data_from_dict(
            username=username,
            base_url=base_url,
            user_data_dict=user_data_dict,
        )
        source_name = "source_json_user_data"
    else:
        raise RuntimeError("Provide either --request-code, --code, or --source-json.")

    device_scenes = {
        device_id: _normalize_dict_list(scene_list)
        for device_id, scene_list in _normalize_value_map(web_cache.get("device_scenes")).items()
    }
    inventory = _build_inventory(
        home_data,
        rooms=_normalize_room_list(web_cache.get("rooms") if isinstance(web_cache.get("rooms"), list) else None),
        scenes=_flatten_device_scenes(device_scenes),
        schedules=_normalize_schedule_map(web_cache.get("device_schedules")),
        scene_order=list(web_cache.get("scene_order") or []),
        home_scenes=_normalize_dict_list(web_cache.get("home_scenes")),
        device_details=_normalize_dict_map(web_cache.get("device_details")),
        device_extras=_normalize_value_map(web_cache.get("device_extras")),
    )
    full_snapshot = {
        "meta": {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "username": username,
            "base_url": base_url,
            "source": source_name,
            # TODO(security): sanitize token/rriot/local_key fields before long-term storage or sharing.
            "todo": "sanitize_secrets_before_sharing",
        },
        "user_data": _to_jsonable(user_data_dict),
        "home_data": _to_jsonable(home_data),
        "web_api_cache": _to_jsonable(web_cache),
    }
    normalized_inventory = _merge_existing_inventory_mutations(
        _to_jsonable(inventory),
        _load_existing_inventory_for_merge(args.output),
    )

    if args.print_only:
        print(json.dumps(normalized_inventory, indent=2))
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(normalized_inventory, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote inventory: {args.output}")
        if not args.no_full_snapshot:
            full_snapshot_output = (
                args.full_snapshot_output
                if args.full_snapshot_output is not None
                else _default_full_snapshot_path(args.output)
            )
            full_snapshot_output.parent.mkdir(parents=True, exist_ok=True)
            full_snapshot_output.write_text(
                json.dumps(_to_jsonable(full_snapshot), indent=2) + "\n",
                encoding="utf-8",
            )
            print(f"Wrote full snapshot: {full_snapshot_output}")

    device_names = [device.get("name", "<unnamed>") for device in normalized_inventory.get("devices", [])]
    shared_names = [device.get("name", "<unnamed>") for device in normalized_inventory.get("received_devices", [])]
    print(f"Home: {normalized_inventory.get('home', {}).get('name', '<unknown>')}")
    print(f"Rooms ({len(normalized_inventory.get('rooms', []))}): cached")
    print(f"Scenes ({len(normalized_inventory.get('scenes', []))}): cached")
    print(
        "Schedules ("
        f"{sum(len(value) for value in normalized_inventory.get('schedules', {}).values() if isinstance(value, list))}"
        "): cached"
    )
    print(f"Devices ({len(device_names)}): {', '.join(device_names) if device_names else 'none'}")
    print(
        f"Received devices ({len(shared_names)}): "
        f"{', '.join(shared_names) if shared_names else 'none'}"
    )


def main() -> int:
    try:
        asyncio.run(_main_async())
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}")
        message = str(exc)
        if "Hostname mismatch" in message or "CERTIFICATE_VERIFY_FAILED" in message:
            print(
                "Hint: DNS interception is likely still active for Roborock cloud domains. "
                "Temporarily disable the DNS override or run the importer from a network path "
                "that resolves Roborock domains to the real cloud."
            )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
