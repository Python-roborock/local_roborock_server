from __future__ import annotations

import re
from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response

from .devices.service import _home_data as device_home_payload
from .homes.service import home_payload, home_rooms_payload


def match_received_devices(path: str, method: str = "GET") -> bool:
    clean = path.rstrip("/")
    return method.upper() == "GET" and clean == "/user/deviceshare/query/receiveddevices"


def build_received_devices(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    payload = device_home_payload(ctx)
    received_devices = payload.get("receivedDevices") if isinstance(payload, dict) else []
    return wrap_response(received_devices if isinstance(received_devices, list) else [])


def match_rooms(path: str, method: str = "GET") -> bool:
    clean = path.rstrip("/")
    return method.upper() == "GET" and bool(re.fullmatch(r"/user/deviceshare/query/[^/]+/rooms", clean))


def build_rooms(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return wrap_response(home_rooms_payload(ctx))
