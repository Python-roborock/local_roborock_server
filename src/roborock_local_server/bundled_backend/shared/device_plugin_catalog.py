"""Built-in numeric product ids and Android device plugin records.

The data comes from the Roborock EU cloud: GET /api/v5/product gives the
numeric product id of each model, and POST /api/v1/appplugin gives the Android
plugin record of each product id. scripts/refresh_device_plugin_catalog.py
rebuilds device_plugin_catalog.json with any cloud login.

The server falls back to this data. The product ids and plugin records of a
cloud import keep precedence, because product ids differ by cloud region.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .data_helpers import as_int, stable_int

DEVICE_PLUGIN_CATALOG_PATH = Path(__file__).with_name("device_plugin_catalog.json")

_CATALOG: dict[str, Any] = json.loads(DEVICE_PLUGIN_CATALOG_PATH.read_text(encoding="utf-8"))

# Model -> numeric product id. /api/v5/product answers it as the product "id",
# and the app requests the device plugin with it.
BUILTIN_PRODUCT_IDS: dict[str, int] = {
    model: int(entry["id"]) for model, entry in _CATALOG["products"].items()
}

# Android (type 2) records in the shape of the /api/v1/appplugin answer.
BUILTIN_APPPLUGIN_RECORDS: list[dict[str, Any]] = [dict(record) for record in _CATALOG["appplugin"]]

_RECORDS_BY_PRODUCT_ID = {as_int(record.get("productid"), 0): record for record in BUILTIN_APPPLUGIN_RECORDS}

# Model -> its Android record. /api/v1/appplugin looks the record up by the
# model that /api/v5/product gives the requested id to.
BUILTIN_APPPLUGIN_RECORDS_BY_MODEL: dict[str, dict[str, Any]] = {
    model: _RECORDS_BY_PRODUCT_ID[product_id]
    for model, product_id in BUILTIN_PRODUCT_IDS.items()
    if product_id in _RECORDS_BY_PRODUCT_ID
}


def product_fields(product: Mapping[str, Any]) -> tuple[str, str, str]:
    """Return the model, the home data product id and the category of a home data product."""
    return (
        str(product.get("model") or "roborock.vacuum.a117"),
        str(product.get("id") or ""),
        str(product.get("category") or "robot.vacuum.cleaner"),
    )


def resolve_product_ids(products: Sequence[Mapping[str, Any]], import_ids: Mapping[str, int]) -> list[int]:
    """Return the numeric product id that /api/v5/product gives each home data product.

    The app requests the device plugin with this id. A snapshot record matches
    only the id of the cloud import, and /api/v1/appplugin finds a built-in
    record by the model that holds the id. So each id must name one model.
    Product ids differ by cloud region. So a model gets the id of the
    account's cloud import (model -> id) first, then a numeric id in home
    data, then its built-in id, then a hashed id. Newer models (e.g. a226)
    have a string id in home data.
    """
    fields = [product_fields(product) for product in products]
    model_keys = [model.strip().lower() for model, _, _ in fields]
    fixed_ids = [import_ids.get(key) or as_int(raw_id, 0) for key, (_, raw_id, _) in zip(model_keys, fields)]
    holders: dict[int, set[str]] = {}
    for key, product_id in [*import_ids.items(), *zip(model_keys, fixed_ids)]:
        if product_id:
            holders.setdefault(product_id, set()).add(key)
    product_ids: list[int] = []
    for key, fixed_id, (_, raw_id, category) in zip(model_keys, fixed_ids, fields):
        built_in_id = BUILTIN_PRODUCT_IDS.get(key)
        if fixed_id:
            product_ids.append(fixed_id)
        # The built-in ids come from the EU cloud. Another model can hold the
        # same id in the import or in home data, like the a199 holds 199 in
        # the US cloud. Then the id would name two models.
        elif built_in_id and holders.get(built_in_id, set()) <= {key}:
            product_ids.append(built_in_id)
        else:
            product_ids.append(stable_int(raw_id or category) % 1_000_000)
    return product_ids
