from __future__ import annotations

from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response

from .service import scene_order_by_device


def match(path: str) -> bool:
    return path.rstrip("/") == "/user/scene/order"


def build(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    # The app reads ApiReturn<List<SceneOrder>> with
    # SceneOrder = {"duid": String, "sceneIds": List<Long>}, the same shape the
    # cloud returns. A flat id list fails with "Expected start of the object".
    return wrap_response(scene_order_by_device(ctx, query_params))

