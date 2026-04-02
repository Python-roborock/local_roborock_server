from __future__ import annotations

from typing import Any

from shared.context import ServerContext

from ...auth.service import ok
from ...plugin.common import APP_FEATURE_PLUGIN_LIST, proxied_plugin_records


def match(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/appfeatureplugin"


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return ok({"plugins": proxied_plugin_records(ctx, APP_FEATURE_PLUGIN_LIST)})

