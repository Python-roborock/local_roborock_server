from __future__ import annotations

from typing import Any

from shared.context import ServerContext
from shared.data_helpers import as_int, default_product_name, model_product_ids, stable_int
from shared.device_plugin_catalog import BUILTIN_PRODUCT_IDS

from ..plugin.common import snapshot_plugin_catalog_data

from ..user.homes.service import home_payload


def build_product_response(ctx: ServerContext) -> dict[str, Any]:
    home_data = home_payload(ctx)
    products_value = home_data.get("products")
    products = products_value if isinstance(products_value, list) else []
    cloud_product_ids = model_product_ids(snapshot_plugin_catalog_data(ctx, "product"))
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
                    # CategoryEntity.code becomes Product.code in the app, which
                    # the device plugin receives as deviceCategory.
                    "code": category_name,
                    "displayName": category_name,
                    "iconUrl": "",
                },
                "productList": [],
            }
        model = str(product.get("model") or "roborock.vacuum.a117")
        model_key = model.strip().lower()
        # The app requests the device plugin with this numeric id, so a hashed
        # id gets it no plugin. Product ids differ by cloud region. So the id
        # from the account's own cloud import wins, then a numeric id in home
        # data, then the built-in id of the model. Newer models (e.g. a226)
        # have a string id in home data. The built-in ids come from the EU
        # cloud. Without an import, they only need to match the built-in plugin
        # records, because the app gets both answers from this server.
        product_id = (
            cloud_product_ids.get(model_key)
            or as_int(raw_product_id, 0)
            or BUILTIN_PRODUCT_IDS.get(model_key)
            or stable_int(raw_product_id or category_name) % 1_000_000
        )
        product_entry = {
            "id": product_id,
            "name": str(product.get("name") or default_product_name(model)),
            "model": model,
            # The app's API model reads the IoT product id as "rriotid" and
            # joins the home data device's productId against it. Without it the
            # product lookup fails and opening the device shows error 21020.
            "rriotid": raw_product_id,
            "categoryId": categories[category_name]["category"]["id"],
            "packagename": f"com.roborock.{model.split('.')[-1]}",
            "ncMode": "global",
            "status": 10,
            # Read by PluginSDKModule.getProductAgreements; a missing field is
            # null and the device plugin's privacy check never completes.
            "agreements": [],
        }
        icon_url = product.get("iconUrl")
        if isinstance(icon_url, str) and icon_url:
            product_entry["picurl"] = icon_url
            product_entry["cardpicurl"] = icon_url
            product_entry["pluginPicUrl"] = icon_url
        categories[category_name]["productList"].append(product_entry)
    return {"categoryDetailList": list(categories.values())}
