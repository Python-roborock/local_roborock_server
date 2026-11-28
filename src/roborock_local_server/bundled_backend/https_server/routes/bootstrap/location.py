from __future__ import annotations

from typing import Any

from shared.context import ServerContext
from shared.data_helpers import default_timezone
from shared.http_helpers import wrap_response


def match(path: str) -> bool:
    return "location" in path


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    country = (ctx.region or "us").strip().upper() or "US"
    timezone = default_timezone(ctx)
    return wrap_response({"country": country, "timezone": timezone})

