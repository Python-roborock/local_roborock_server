from __future__ import annotations

import re
from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response

from ..homes.service import home_rooms_payload


def match(path: str) -> bool:
    clean = path.rstrip("/")
    return bool(re.fullmatch(r"/user/devices/[^/]+/last_known", clean))


def build(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    """The robot's last-known state: status, position, and when it last spoke or went offline.

    ``?map=1`` adds the last map the robot sent (base64 of the same bytes ``get_map_v1`` returns
    once decrypted and decompressed), so a client can draw it while the robot cannot be asked.
    """
    parts = [part for part in clean_path.rstrip("/").split("/") if part]
    duid = parts[-2] if len(parts) >= 2 else ""
    store = ctx.snapshot_store
    snapshot = None
    if store is not None:
        include_map = (query_params.get("map") or [""])[0] in ("1", "true")
        snapshot = store.get(duid, include_map=include_map)
    if snapshot is None:
        return wrap_response({"duid": duid, "known": False})
    # The robot's room table says which segment is which room; the home data knows the names.
    names = {str(room.get("id")): room.get("name") for room in home_rooms_payload(ctx) if isinstance(room, dict)}
    for room in snapshot.get("rooms") or []:
        room["name"] = names.get(str(room.get("iot_id")))
    return wrap_response({**snapshot, "known": True})
