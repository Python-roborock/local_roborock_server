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
from pathlib import Path
from typing import Any

DEVICE_PLUGIN_CATALOG_PATH = Path(__file__).with_name("device_plugin_catalog.json")

_CATALOG: dict[str, Any] = json.loads(DEVICE_PLUGIN_CATALOG_PATH.read_text(encoding="utf-8"))

# Model -> numeric product id. /api/v5/product answers it as the product "id",
# and the app requests the device plugin with it.
BUILTIN_PRODUCT_IDS: dict[str, int] = {
    model: int(entry["id"]) for model, entry in _CATALOG["products"].items()
}

# Numeric product id -> model. Each id belongs to one model.
BUILTIN_MODELS_BY_PRODUCT_ID: dict[int, str] = {product_id: model for model, product_id in BUILTIN_PRODUCT_IDS.items()}

# Android (type 2) records in the shape of the /api/v1/appplugin answer.
BUILTIN_APPPLUGIN_RECORDS: list[dict[str, Any]] = [dict(record) for record in _CATALOG["appplugin"]]
