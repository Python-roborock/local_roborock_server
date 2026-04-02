from __future__ import annotations

from typing import Any

from shared.context import ServerContext

from ...auth.service import ok
from ..appconfig_service import app_config_common_payload

_APP_CONFIG_V2_EXTRAS = {
    "entryConfigs": [
        {"name": "MEMBER_CENTER", "enabled": False, "target": None},
        {"name": "SERVICE_CENTER", "enabled": False, "target": None},
    ],
    "pluginEntryConfigs": {"ASSISTANT": False},
}


def match(path: str) -> bool:
    return path.rstrip("/") == "/api/v2/appconfig"


def build(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    payload = app_config_common_payload()
    payload.update(_APP_CONFIG_V2_EXTRAS)
    return ok(payload)
