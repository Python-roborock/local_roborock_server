from __future__ import annotations

import re
from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response

from .service import extract_home_id_from_rooms_path, home_rooms_payload, upsert_inventory_room


def match(path: str) -> bool:
    clean = path.rstrip("/")
    # python-roborock currently has a malformed /rooms path for get_rooms; support both.
    return bool(re.fullmatch(r"/user/homes/[^/]+/rooms(?:[^/]*)", clean))


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return wrap_response(home_rooms_payload(ctx))


def match_post(path: str, method: str = "GET") -> bool:
    return method.upper() == "POST" and match(path)


def build_post(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    room_name = ""
    for key in ("name", "roomName"):
        values = body_params.get(key) or []
        for value in values:
            candidate = str(value or "").strip()
            if candidate:
                room_name = candidate
                break
        if room_name:
            break
    home_id = extract_home_id_from_rooms_path(ctx, clean_path)
    room_payload, created = upsert_inventory_room(ctx, home_id=home_id, room_name=room_name)
    response_payload = {
        "id": room_payload["id"],
        "roomId": room_payload["id"],
        "name": room_payload["name"],
        "roomName": room_payload["name"],
        "homeId": home_id,
        "created": created,
    }
    return wrap_response(response_payload)

