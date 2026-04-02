from __future__ import annotations

from typing import Any

from shared.context import ServerContext

from ...auth.service import ok
from ..appconfig_service import app_config_common_payload


def match(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/appconfig"


def build(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return ok(app_config_common_payload())
