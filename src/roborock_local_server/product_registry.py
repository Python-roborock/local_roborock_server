from __future__ import annotations

import copy
import json
import logging
from pathlib import Path
from typing import Any

from .bundled_backend.shared.constants import DEFAULT_PRODUCT_SCHEMA

_LOGGER = logging.getLogger(__name__)

ROBOT_VACUUM_CATEGORY = "robot.vacuum.cleaner"

# Robot vacuum models (Roborock product catalog category 1) mapped to their cloud product
# name and product id ("rriotid"). Regenerate from python-roborock's
# RoborockApiClient.get_products() when Roborock ships new models.
PRODUCT_CATALOG_PATH = Path(__file__).with_name("product_catalog.json")


def _load_builtin_registry() -> dict[str, dict[str, Any]]:
    products = json.loads(PRODUCT_CATALOG_PATH.read_text(encoding="utf-8"))["products"]
    return {
        model: {
            "model": model,
            "product_name": entry["product_name"],
            "category": ROBOT_VACUUM_CATEGORY,
            "product_id": entry["product_id"],
            "schema": DEFAULT_PRODUCT_SCHEMA,
        }
        for model, entry in products.items()
    }


BUILTIN_PRODUCT_REGISTRY: dict[str, dict[str, Any]] = _load_builtin_registry()


def normalize_model_string(model: str | None) -> str:
    """Normalize a model name into canonical roborock.<category>.<code format."""
    trimmed = str(model or "").strip().lower()
    if not trimmed:
        return ""
    if trimmed.startswith("roborock."):
        return trimmed
    # If passed just a short code like 'a72'
    return f"roborock.vacuum.{trimmed}"


def resolve_product_metadata(
    model: str | None,
    custom_name: str | None = None,
    custom_registry_path: Path | None = None,
) -> dict[str, Any]:
    """Resolve full product metadata and schema for a given model.

    Checks:
    1. Optional custom user registry JSON file
    2. Built-in product catalog
    3. Fallback baseline profile with standard 17-item DP schema
    """
    normalized_model = normalize_model_string(model)
    short_code = normalized_model.split(".")[-1] if normalized_model else ""

    # Check custom registry file if available
    if custom_registry_path and custom_registry_path.exists():
        try:
            custom_data = json.loads(custom_registry_path.read_text(encoding="utf-8"))
            if isinstance(custom_data, dict):
                match = custom_data.get(normalized_model) or custom_data.get(short_code)
                if isinstance(match, dict):
                    result = copy.deepcopy(match)
                    if custom_name:
                        result["product_name"] = custom_name
                    return result
        except Exception as exc:  # noqa: BLE001
            _LOGGER.warning("Failed reading custom product registry %s: %s", custom_registry_path, exc)

    # Check built-in catalog
    if normalized_model in BUILTIN_PRODUCT_REGISTRY:
        result = copy.deepcopy(BUILTIN_PRODUCT_REGISTRY[normalized_model])
        if custom_name:
            result["product_name"] = custom_name
        return result

    # Fallback to standard baseline
    fallback_name = custom_name or (f"Roborock {short_code.upper()}" if short_code else "Roborock Vacuum")
    return {
        "model": normalized_model or "roborock.vacuum.generic",
        "product_name": fallback_name,
        "category": ROBOT_VACUUM_CATEGORY,
        "product_id": short_code or "generic",
        "schema": copy.deepcopy(DEFAULT_PRODUCT_SCHEMA),
    }
