from __future__ import annotations

from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response

from .service import add_device_payload


def match(path: str) -> bool:
    return path.rstrip("/") == "/user/devices/newadd"


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return wrap_response(add_device_payload(ctx))

