from __future__ import annotations

import json
from typing import Any

from shared.context import ServerContext
from shared.data_helpers import as_int

from ...auth.service import ok
from ...plugin.common import APPPLUGIN_LIST, plugin_records_with_snapshot_fallback, proxied_plugin_records


def match(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/appplugin"


def _requested_product_ids(body_params: dict[str, list[str]]) -> set[int]:
    # The app posts JSON like {"apilevel": 10046, "productids": [263], "type": 2}.
    # Form bodies may repeat the field or join the ids with commas.
    values: list[Any] = []
    for raw in body_params.get("__json") or []:
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(parsed, dict):
            requested = parsed.get("productids")
            values.extend(requested if isinstance(requested, list) else [requested])
    for raw in body_params.get("productids") or []:
        values.extend(str(raw).strip("[] ").split(","))
    product_ids = {as_int(value, 0) for value in values if value is not None}
    product_ids.discard(0)
    return product_ids


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    records = plugin_records_with_snapshot_fallback(ctx, "appplugin", APPPLUGIN_LIST)
    product_ids = _requested_product_ids(body_params)
    # The app installs the first record without checking its productid, so a
    # device must only get the records for the product ids it asked for.
    matching = [record for record in records if as_int(record.get("productid"), 0) in product_ids]
    return ok(proxied_plugin_records(ctx, matching or records))
