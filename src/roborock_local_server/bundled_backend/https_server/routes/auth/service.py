from __future__ import annotations

import json
from typing import Any

from shared.context import ServerContext
from shared.inventory_io import WEB_API_INVENTORY_FILE
_WEB_API_FULL_SNAPSHOT_SUFFIX = "_full_snapshot.json"


def ok(data: Any) -> dict[str, Any]:
    return {"code": 200, "msg": "success", "data": data}


def cloud_snapshot_path(ctx: ServerContext):
    inventory_path = ctx.http_jsonl.parent / WEB_API_INVENTORY_FILE
    return inventory_path.with_name(f"{inventory_path.stem}{_WEB_API_FULL_SNAPSHOT_SUFFIX}")


def current_server_urls(ctx: ServerContext) -> tuple[str, str, str]:
    api_url = f"https://{ctx.api_host}"
    mqtt_url = f"ssl://{ctx.mqtt_host}:{ctx.mqtt_tls_port}"
    wood_url = f"https://{ctx.wood_host}"
    return api_url, mqtt_url, wood_url


def with_current_server_urls(ctx: ServerContext, cloud_user_data: dict[str, Any]) -> dict[str, Any]:
    api_url, mqtt_url, wood_url = current_server_urls(ctx)
    patched_user_data = dict(cloud_user_data)

    rriot_value = patched_user_data.get("rriot")
    if isinstance(rriot_value, dict):
        rriot = dict(rriot_value)
        ref_value = rriot.get("r")
        ref = dict(ref_value) if isinstance(ref_value, dict) else {}
        ref.update({"a": api_url, "m": mqtt_url, "l": wood_url})
        rriot["r"] = ref
        patched_user_data["rriot"] = rriot

    servers_value = patched_user_data.get("servers")
    servers = dict(servers_value) if isinstance(servers_value, dict) else {}
    servers.update(
        {
            "apiUrl": api_url,
            "mqttUrl": mqtt_url,
            "woodUrl": wood_url,
            "api_url": api_url,
            "mqtt_url": mqtt_url,
            "wood_url": wood_url,
            "a": api_url,
            "m": mqtt_url,
            "l": wood_url,
        }
    )
    patched_user_data["servers"] = servers
    return patched_user_data


def load_cloud_full_snapshot(ctx: ServerContext) -> dict[str, Any] | None:
    full_snapshot_path = cloud_snapshot_path(ctx)
    if not full_snapshot_path.exists():
        return None
    try:
        parsed = json.loads(full_snapshot_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def load_cloud_user_data(ctx: ServerContext) -> dict[str, Any] | None:
    parsed = load_cloud_full_snapshot(ctx)
    if not isinstance(parsed, dict):
        return None
    user_data = parsed.get("user_data")
    if not isinstance(user_data, dict):
        return None
    return with_current_server_urls(ctx, user_data)


def is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def missing_cloud_login_fields(cloud_user_data: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    if cloud_user_data.get("uid") is None:
        missing.append("uid")
    if not is_non_empty_string(cloud_user_data.get("token")):
        missing.append("token")
    if not is_non_empty_string(cloud_user_data.get("rruid")):
        missing.append("rruid")
    rriot = cloud_user_data.get("rriot")
    if not isinstance(rriot, dict):
        missing.append("rriot")
        return missing
    for key in ("u", "s", "h", "k"):
        if not is_non_empty_string(rriot.get(key)):
            missing.append(f"rriot.{key}")
    ref = rriot.get("r")
    if not isinstance(ref, dict):
        missing.append("rriot.r")
        return missing
    for key in ("r", "a", "m", "l"):
        if not is_non_empty_string(ref.get(key)):
            missing.append(f"rriot.r.{key}")
    return missing


def cloud_login_data_required_response(
    ctx: ServerContext,
    *,
    reason: str,
    missing_fields: list[str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "reason": reason,
        "hint": "Fetch cloud data once via /ui/api/cloud/request-code and /ui/api/cloud/submit-code, then retry login.",
        "required_snapshot": str(cloud_snapshot_path(ctx)),
    }
    if missing_fields:
        payload["missing_fields"] = missing_fields
    return {"code": 41201, "msg": "cloud_user_data_required", "data": payload}


def build_code_send_response(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return ok({"sent": True, "validForSec": 300})


def build_code_validate_response(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return ok({"valid": True})


def build_login_submit_response(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return build_login_data_response(ctx)


def build_password_reset_response(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return ok(None)


def build_login_data_response(ctx: ServerContext) -> dict[str, Any]:
    cloud_user_data = load_cloud_user_data(ctx)
    if cloud_user_data is None:
        return cloud_login_data_required_response(ctx, reason="missing_snapshot_or_user_data")
    missing_fields = missing_cloud_login_fields(cloud_user_data)
    if missing_fields:
        return cloud_login_data_required_response(
            ctx,
            reason="incomplete_cloud_user_data",
            missing_fields=missing_fields,
        )
    return ok(cloud_user_data)

