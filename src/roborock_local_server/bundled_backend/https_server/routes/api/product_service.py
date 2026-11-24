from __future__ import annotations

from typing import Any

from shared.context import ServerContext
from shared.data_helpers import default_product_name, model_product_ids
from shared.device_plugin_catalog import DevicePluginCatalog, product_fields, resolve_product_ids

from ..plugin.common import built_in_catalog, snapshot_plugin_catalog_data, snapshot_plugin_record_owners

from ..user.homes.service import home_payload


def _served_products(ctx: ServerContext, catalog: DevicePluginCatalog) -> list[tuple[dict[str, Any], int]]:
    """Pair each home data product with the numeric product id of /api/v5/product."""
    products_value = home_payload(ctx).get("products")
    products = products_value if isinstance(products_value, list) else []
    products = [product for product in products if isinstance(product, dict)]
    cloud_product_ids = model_product_ids(snapshot_plugin_catalog_data(ctx, "product"))
    product_ids = resolve_product_ids(products, cloud_product_ids, catalog, snapshot_plugin_record_owners(ctx))
    return list(zip(products, product_ids))


def served_models_by_product_id(ctx: ServerContext, catalog: DevicePluginCatalog) -> dict[int, set[str]]:
    """Map each product id that /api/v5/product answers to the models that get it."""
    models: dict[int, set[str]] = {}
    for product, product_id in _served_products(ctx, catalog):
        model, _, _ = product_fields(product)
        models.setdefault(product_id, set()).add(model.strip().lower())
    return models


def build_product_response(ctx: ServerContext) -> dict[str, Any]:
    categories: dict[str, dict[str, Any]] = {}
    for product, product_id in _served_products(ctx, built_in_catalog(ctx)):
        model, raw_product_id, category_name = product_fields(product)
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
