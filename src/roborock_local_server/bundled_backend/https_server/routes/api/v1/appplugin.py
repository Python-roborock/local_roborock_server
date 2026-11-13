from __future__ import annotations

import json
from typing import Any

from shared.context import ServerContext

from ...auth.service import ok
from ...plugin.common import APPPLUGIN_LIST, plugin_records_with_snapshot_fallback, proxied_plugin_records

# Request "type" of the iOS app; Android sends 2.
IOS_APP_TYPE = 1


def match(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/appplugin"


def _request_app_type(body_params: dict[str, list[str]]) -> int | None:
    for raw in body_params.get("__json") or []:
        try:
            body = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(body, dict):
            try:
                return int(body.get("type"))
            except (TypeError, ValueError):
                return None
    return None


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    records = plugin_records_with_snapshot_fallback(ctx, "appplugin", APPPLUGIN_LIST)
    if _request_app_type(body_params) == IOS_APP_TYPE:
        # Same plugin version, different zip: the iOS app cannot load the Android
        # one. Imports from before the iOS catalog existed fall back to Android.
        records = plugin_records_with_snapshot_fallback(ctx, "appplugin_ios", records)
    return ok(proxied_plugin_records(ctx, records))
