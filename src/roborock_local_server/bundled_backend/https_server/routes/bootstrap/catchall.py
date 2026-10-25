from __future__ import annotations

import copy
from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response

# Unhandled routes for which the app deserializes the payload into a concrete
# type. The generic {"ok": true, "route": ...} object does not fit those types,
# the app raises a deserialization error and shows a generic "network
# unavailable" toast. These are the empty values of the expected types.
TYPED_EMPTY_RESPONSES: dict[str, Any] = {
    # ActivityLatest {i, t}
    "/api/v1/activity/latest": {"i": 0, "t": 0},
    # List<...>
    "/api/v2/activity/current": [],
    "/api/v1/activity/nps": [],
    "/api/v1/recommendation/agreement/status": {},
}


def match(_path: str) -> bool:
    return True


def build(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    typed_empty = TYPED_EMPTY_RESPONSES.get(clean_path.rstrip("/"))
    if typed_empty is not None:
        return wrap_response(copy.deepcopy(typed_empty))
    return wrap_response({"ok": True, "route": clean_path})
