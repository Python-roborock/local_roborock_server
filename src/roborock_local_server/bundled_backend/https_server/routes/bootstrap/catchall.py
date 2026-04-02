from __future__ import annotations

from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response


def match(_path: str) -> bool:
    return True


def build(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    return wrap_response({"ok": True, "route": clean_path})
