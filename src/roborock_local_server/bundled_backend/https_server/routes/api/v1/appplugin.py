from __future__ import annotations

import json
from typing import Any

from shared.context import ServerContext
from shared.data_helpers import as_int

from ...auth.service import ok
from ...plugin.common import APPPLUGIN_LIST, proxied_plugin_records, snapshot_plugin_records

# Request "type" of the iOS app; Android sends 2.
IOS_APP_TYPE = 1


def match(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/appplugin"


def _request_app_type(body_params: dict[str, list[str]]) -> int | None:
    for raw in body_params.get("__json") or []:
        try:
            body = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(body, dict):
            try:
                return int(body.get("type"))
            except (TypeError, ValueError):
                return None
    return None


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


def _product_id(record: dict[str, Any]) -> int:
    return as_int(record.get("productid"), 0)


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    snapshot_records = snapshot_plugin_records(ctx, "appplugin")
    if _request_app_type(body_params) == IOS_APP_TYPE:
        # Same plugin version, different zip: the iOS app cannot load the Android
        # one. Imports from before the iOS catalog existed fall back to Android.
        snapshot_records = snapshot_plugin_records(ctx, "appplugin_ios") or snapshot_records
    product_ids = _requested_product_ids(body_params)
    # The app installs the first record without checking its productid, so a
    # device must only get the records for the product ids it asked for.
    matching = [record for record in snapshot_records if _product_id(record) in product_ids]
    # A device added after the snapshot import has no snapshot record, so the
    # ids that the snapshot lacks come from the built-in list. The built-in list
    # is the same for both platforms. So an iOS request can get an Android zip
    # here, which the iOS app cannot load. The fallback to the Android catalog
    # above has the same limitation if the snapshot has no iOS catalog.
    missing_ids = product_ids - {_product_id(record) for record in snapshot_records}
    matching += [record for record in APPPLUGIN_LIST if _product_id(record) in missing_ids]
    return ok(proxied_plugin_records(ctx, matching or snapshot_records or APPPLUGIN_LIST))
