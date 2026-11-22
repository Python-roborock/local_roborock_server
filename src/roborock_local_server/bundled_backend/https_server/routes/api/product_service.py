from __future__ import annotations

import json
from typing import Any

from shared.constants import MODEL_PRODUCT_ID_OVERRIDES
from shared.context import ServerContext
from shared.data_helpers import as_int, default_product_name, model_product_ids, stable_int

from ..plugin.common import snapshot_plugin_catalog_data

from ..user.homes.service import home_payload
from .card_spec import card_spec_for_category

# Fallback for products the cloud snapshot does not list. Values as the cloud
# sends them for a vacuum (a307): forceShow gates the scene tiles,
# requirePlugin/pluginLevel are only read when a scene entry opens the device
# plugin.
_FALLBACK_SCENE_TAG: dict[str, Any] = {
    "name": "scene_2.0",
    "requirePlugin": True,
    "pluginLevel": 3000,
    "forceShow": True,
}
# Only vacuums get the fallback tag: the tiles also need the category card
# spec, which we only have for vacuums, and the tag values were only seen on
# a vacuum. Mowers, washers etc. get it only when the cloud sends it.
_FALLBACK_SCENE_TAG_CATEGORIES = frozenset({"robot.vacuum.cleaner"})


def _cloud_card_spec(value: Any) -> str | None:
    """The category's cloud ``cardspec`` as the app reads it, or None if empty."""
    if isinstance(value, str):
        return value if value.strip() else None
    if isinstance(value, dict) and value:
        wrapped = value if set(value) == {"data"} else {"data": value}
        return json.dumps(wrapped, ensure_ascii=False, separators=(",", ":"))
    return None


def _cloud_product_details(
    cloud_products: Any,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
    """Map model -> productTags and category code -> cardspec from a cloud
    /api/v5/product payload (the snapshot taken at import)."""
    tags_by_model: dict[str, list[dict[str, Any]]] = {}
    card_specs: dict[str, str] = {}
    category_details = cloud_products.get("categoryDetailList") if isinstance(cloud_products, dict) else None
    for category_detail in category_details or []:
        if not isinstance(category_detail, dict):
            continue
        category = category_detail.get("category")
        if isinstance(category, dict):
            code = str(category.get("code") or "").strip()
            card_spec = _cloud_card_spec(category.get("cardspec"))
            if code and card_spec is not None:
                card_specs.setdefault(code, card_spec)
        for product in category_detail.get("productList") or []:
            if not isinstance(product, dict):
                continue
            model = str(product.get("model") or "").strip().lower()
            tags = product.get("productTags")
            if model and isinstance(tags, list):
                tags_by_model[model] = [dict(tag) for tag in tags if isinstance(tag, dict)]
    return tags_by_model, card_specs


def _fallback_product_tags(category_name: str) -> list[dict[str, Any]]:
    if category_name in _FALLBACK_SCENE_TAG_CATEGORIES:
        return [dict(_FALLBACK_SCENE_TAG)]
    return []


def build_product_response(ctx: ServerContext) -> dict[str, Any]:
    home_data = home_payload(ctx)
    products_value = home_data.get("products")
    products = products_value if isinstance(products_value, list) else []
    cloud_products = snapshot_plugin_catalog_data(ctx, "product")
    cloud_product_ids = model_product_ids(cloud_products)
    # The cloud's own productTags and category cardspec (22 languages) win;
    # the built-in values are only a fallback.
    cloud_product_tags, cloud_card_specs = _cloud_product_details(cloud_products)
    categories: dict[str, dict[str, Any]] = {}
    for product in products:
        if not isinstance(product, dict):
            continue
        raw_product_id = str(product.get("id") or "")
        category_name = str(product.get("category") or "robot.vacuum.cleaner")
        if category_name not in categories:
            category_id = len(categories) + 1
            category_entry: dict[str, Any] = {
                "id": category_id,
                # CategoryEntity.code becomes Product.code in the app, which
                # the device plugin receives as deviceCategory.
                "code": category_name,
                "displayName": category_name,
                "iconUrl": "",
            }
            card_spec = cloud_card_specs.get(category_name) or card_spec_for_category(category_name)
            if card_spec is not None:
                # Required for the scene tiles. Like the cloud, a JSON string
                # with the spec wrapped in {"data": ...}.
                category_entry["cardspec"] = card_spec
            categories[category_name] = {
                "category": category_entry,
                "productList": [],
            }
        model = str(product.get("model") or "roborock.vacuum.a117")
        model_key = model.strip().lower()
        # String product ids (e.g. a226) take the cloud's numeric id for the model;
        # plugins are keyed by it, so a hashed id gets the app no device plugin.
        product_id = MODEL_PRODUCT_ID_OVERRIDES.get(
            model_key,
            cloud_product_ids.get(model_key)
            or as_int(raw_product_id, stable_int(raw_product_id or category_name) % 1_000_000),
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
            # ProductEntity.sceneProduct() looks up the "scene_2.0" tag; without
            # it the scene tiles stay hidden. The app builds productTagsMap from
            # this list itself.
            "productTags": (
                cloud_product_tags[model_key]
                if model_key in cloud_product_tags
                else _fallback_product_tags(category_name)
            ),
        }
        icon_url = product.get("iconUrl")
        if isinstance(icon_url, str) and icon_url:
            product_entry["picurl"] = icon_url
            product_entry["cardpicurl"] = icon_url
            product_entry["pluginPicUrl"] = icon_url
        categories[category_name]["productList"].append(product_entry)
    return {"categoryDetailList": list(categories.values())}
