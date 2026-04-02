from __future__ import annotations

from typing import Any, Sequence

from shared.context import ServerContext
from shared.http_helpers import wrap_response


def _split_param_values(values: Sequence[str]) -> list[str]:
    split_values: list[str] = []
    for value in values:
        for part in str(value or "").split(","):
            candidate = part.strip()
            if candidate:
                split_values.append(candidate)
    return split_values


def match(path: str) -> bool:
    return path.rstrip("/") == "/user/app/info"


def build(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    payload = {"stored": True}
    for source_key, payload_key in (
        ("pushChannel", "pushChannel"),
        ("channelToken", "channelToken"),
        ("locale", "locale"),
        ("lang", "lang"),
        ("osType", "osType"),
    ):
        values = _split_param_values(body_params.get(source_key, []))
        if values:
            payload[payload_key] = values[0]
    return wrap_response(payload)
