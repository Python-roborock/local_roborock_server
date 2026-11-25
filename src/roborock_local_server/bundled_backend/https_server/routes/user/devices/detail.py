from __future__ import annotations

import re
from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response

from .service import device_detail_payload, parse_device_name, parse_strict_bool, store_device_settings


def _device_id_from_path(clean_path: str) -> str:
    parts = [part for part in clean_path.rstrip("/").split("/") if part]
    if len(parts) >= 4 and parts[-1] == "extra":
        return parts[-2]
    return parts[-1] if len(parts) >= 3 else ""


def match(path: str) -> bool:
    clean = path.rstrip("/")
    if clean == "/user/devices/newadd":
        return False
    return bool(re.fullmatch(r"/user/devices/[^/]+", clean))


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    device_id = _device_id_from_path(clean_path)
    return wrap_response(device_detail_payload(ctx, device_id))


def match_put(path: str, method: str = "GET") -> bool:
    return method.upper() == "PUT" and match(path)


def _first_value(body_params: dict[str, list[str]], key: str) -> str | None:
    values = body_params.get(key) or []
    return str(values[0]) if values else None


def build_put(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    device_id = _device_id_from_path(clean_path)
    updates: dict[str, Any] = {}
    raw_name = _first_value(body_params, "name")
    if raw_name is not None:
        name = parse_device_name(raw_name)
        if name is not None:
            updates["name"] = name
    raw_switch = _first_value(body_params, "silentOtaSwitch")
    if raw_switch is not None:
        switch = parse_strict_bool(raw_switch)
        if switch is not None:
            updates["silentOtaSwitch"] = switch
    if updates:
        store_device_settings(ctx, device_id, updates)
    return wrap_response(device_detail_payload(ctx, device_id))


def match_extra(path: str) -> bool:
    clean = path.rstrip("/")
    return bool(re.fullmatch(r"/user/devices/[^/]+/extra", clean))


def build_extra(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    device_id = _device_id_from_path(clean_path)
    payload = device_detail_payload(ctx, device_id)
    return wrap_response(payload.get("extra", "{}") or "{}")
