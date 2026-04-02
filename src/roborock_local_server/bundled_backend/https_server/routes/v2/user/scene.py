from __future__ import annotations

from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response

from ...user.scene.service import create_scene


def match(path: str, method: str = "GET") -> bool:
    return method.upper() == "POST" and path.rstrip("/") == "/v2/user/scene"


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return wrap_response(create_scene(ctx, body_params))

