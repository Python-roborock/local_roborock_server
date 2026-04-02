from __future__ import annotations

import re
from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response

from .service import device_detail_payload


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
