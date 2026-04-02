from __future__ import annotations

import re
from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response

from .service import device_jobs_payload


def match(path: str) -> bool:
    clean = path.rstrip("/")
    return bool(re.fullmatch(r"/user/devices/[^/]+/jobs", clean))


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    parts = [part for part in clean_path.rstrip("/").split("/") if part]
    device_id = parts[-2] if len(parts) >= 2 else ""
    return wrap_response(device_jobs_payload(ctx, device_id))

