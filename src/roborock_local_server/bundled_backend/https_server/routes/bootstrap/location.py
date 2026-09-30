from __future__ import annotations

from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response

REGION_TIMEZONES: dict[str, str] = {
    "eu": "Europe/Berlin",
    "us": "America/New_York",
    "cn": "Asia/Shanghai",
    "ru": "Europe/Moscow",
}

DEFAULT_FALLBACK_TIMEZONE = "America/New_York"


def match(path: str) -> bool:
    return "location" in path


def determine_timezone(ctx: ServerContext) -> str:
    if ctx.timezone and ctx.timezone.strip():
        return ctx.timezone.strip()

    region = (ctx.region or "").strip().lower()
    return REGION_TIMEZONES.get(region, DEFAULT_FALLBACK_TIMEZONE)


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    country = (ctx.region or "us").strip().upper() or "US"
    timezone = determine_timezone(ctx)
    return wrap_response({"country": country, "timezone": timezone})

