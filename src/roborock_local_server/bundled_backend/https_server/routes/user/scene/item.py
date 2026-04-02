from __future__ import annotations

import re
from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response

from .service import execute_scene, update_scene_name, update_scene_param


_SCENE_ITEM_RE = re.compile(r"/user/scene/(\d+)/(execute|name|param)")


def _scene_id_from_path(clean_path: str) -> int:
    match = _SCENE_ITEM_RE.fullmatch(clean_path.rstrip("/"))
    if match is None:
        return 0
    try:
        return int(match.group(1))
    except (TypeError, ValueError):
        return 0


def match_execute(path: str) -> bool:
    clean = path.rstrip("/")
    return bool(re.fullmatch(r"/user/scene/\d+/execute", clean))


def build_execute(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    scene_id = _scene_id_from_path(clean_path)
    return wrap_response(execute_scene(ctx, scene_id))


def match_put_name(path: str, method: str = "GET") -> bool:
    clean = path.rstrip("/")
    return method.upper() == "PUT" and bool(re.fullmatch(r"/user/scene/\d+/name", clean))


def build_put_name(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    scene_id = _scene_id_from_path(clean_path)
    return wrap_response(update_scene_name(ctx, scene_id, body_params))


def match_put_param(path: str, method: str = "GET") -> bool:
    clean = path.rstrip("/")
    return method.upper() == "PUT" and bool(re.fullmatch(r"/user/scene/\d+/param", clean))


def build_put_param(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    scene_id = _scene_id_from_path(clean_path)
    return wrap_response(update_scene_param(ctx, scene_id, body_params))

