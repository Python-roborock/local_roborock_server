from __future__ import annotations

import re
from typing import Any

from shared.context import ServerContext
from shared.http_helpers import wrap_response

from .service import home_payload


def match(path: str) -> bool:
    clean = path.rstrip("/")
    return bool(re.fullmatch(r"/(?:(?:v2|v3)/)?user/homes/[^/]+", clean))


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return wrap_response(home_payload(ctx))

