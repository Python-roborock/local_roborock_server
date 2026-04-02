from __future__ import annotations

from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response

from .service import scene_order


def match(path: str) -> bool:
    return path.rstrip("/") == "/user/scene/order"


def build(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return wrap_response(scene_order(ctx, query_params))

