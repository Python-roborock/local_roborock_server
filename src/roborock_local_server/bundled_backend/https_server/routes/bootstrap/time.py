from __future__ import annotations

import time
from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response


def match(path: str) -> bool:
    return "time" in path


def build(
    _ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return wrap_response(int(time.time()))

