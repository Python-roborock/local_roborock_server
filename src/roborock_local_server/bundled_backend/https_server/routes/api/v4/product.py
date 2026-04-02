from __future__ import annotations

from typing import Any

from shared.context import ServerContext

from ...auth.service import ok
from ..product_service import build_product_response


def match(path: str) -> bool:
    return path.rstrip("/") == "/api/v4/product"


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    return ok(build_product_response(ctx))
