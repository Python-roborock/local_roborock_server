from __future__ import annotations

from typing import Any

from shared.context import ServerContext

from ...auth.service import ok
from ...plugin.common import APPPLUGIN_LIST, proxied_plugin_records


def match(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/appplugin"


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return ok(proxied_plugin_records(ctx, APPPLUGIN_LIST))

