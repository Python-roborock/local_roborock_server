from __future__ import annotations

from typing import Any

from shared.constants import MODEL_PRODUCT_ID_OVERRIDES
from shared.context import ServerContext
from shared.data_helpers import as_int, default_product_name, stable_int

from ..user.homes.service import home_payload


def build_product_response(ctx: ServerContext) -> dict[str, Any]:
    home_data = home_payload(ctx)
    products_value = home_data.get("products")
    products = products_value if isinstance(products_value, list) else []
    categories: dict[str, dict[str, Any]] = {}
    for product in products:
        if not isinstance(product, dict):
            continue
        raw_product_id = str(product.get("id") or "")
        category_name = str(product.get("category") or "robot.vacuum.cleaner")
        if category_name not in categories:
            category_id = len(categories) + 1
            categories[category_name] = {
                "category": {
                    "id": category_id,
                    "displayName": category_name,
                    "iconUrl": "",
                },
                "productList": [],
            }
        model = str(product.get("model") or "roborock.vacuum.a117")
        model_key = model.strip().lower()
        product_id = MODEL_PRODUCT_ID_OVERRIDES.get(
            model_key,
            as_int(raw_product_id, stable_int(raw_product_id or category_name) % 1_000_000),
        )
        product_entry = {
            "id": product_id,
            "name": str(product.get("name") or default_product_name(model)),
            "model": model,
            "packagename": f"com.roborock.{model.split('.')[-1]}",
            "ncMode": "global",
            "status": 10,
        }
        icon_url = product.get("iconUrl")
        if isinstance(icon_url, str) and icon_url:
            product_entry["picurl"] = icon_url
            product_entry["cardPicUrl"] = icon_url
            product_entry["pluginPicUrl"] = icon_url
        categories[category_name]["productList"].append(product_entry)
    return {"categoryDetailList": list(categories.values())}
