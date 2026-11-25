from __future__ import annotations

import re
from typing import Any

from shared.context import ServerContext
from shared.data_helpers import as_int, get_value

from ...auth.service import ok
from ...user.homes.service import home_payload


def match_get_home_detail(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/getHomeDetail"


def match_home_devices_order(path: str) -> bool:
    clean = path.rstrip("/")
    return bool(re.fullmatch(r"/api/v1/home/[^/]+/devices/order", clean))


def build_get_home_detail(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    home_data = home_payload(ctx)
    devices_value = home_data.get("devices")
    devices = devices_value if isinstance(devices_value, list) else []
    device_order = [
        str(get_value(device, "duid", "did", default="")).strip()
        for device in devices
        if isinstance(device, dict) and str(get_value(device, "duid", "did", default="")).strip()
    ]
    home_id = as_int(get_value(home_data, "id", "rr_home_id", "rrHomeId", "home_id", default=0), 0)
    home_name = str(get_value(home_data, "name", "home_name", default=""))
    return ok(
        {
            "id": home_id,
            "name": home_name,
            "deviceListOrder": device_order,
            "rrHomeId": home_id,
            "rrHomeName": home_name,
            "tuyaHomeId": 0,
            "homeId": home_id,
        }
    )


def build_home_devices_order(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    home_data = home_payload(ctx)
    devices_value = home_data.get("devices")
    devices = devices_value if isinstance(devices_value, list) else []
    device_order = [
        str(get_value(device, "duid", "did", default="")).strip()
        for device in devices
        if isinstance(device, dict) and str(get_value(device, "duid", "did", default="")).strip()
    ]
    # The app reads this as ApiWrapper<DeviceSortContainerV2>, an object:
    #   {"type": DeviceSortType, "listOrders": [{"source", "did", "order"}]}
    # A bare list of duids fails with "Expected start of the object '{', but
    # had '[' at path: $.data".
    return ok(
        {
            "type": "HOME",
            "listOrders": [
                {"source": "RR", "did": duid, "order": index}
                for index, duid in enumerate(device_order)
            ],
        }
    )
