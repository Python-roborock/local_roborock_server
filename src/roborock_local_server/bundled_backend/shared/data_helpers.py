from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from .context import ServerContext


def get_value(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = data.get(key)
        if value is None:
            continue
        if isinstance(value, str) and value.strip() == "":
            continue
        return value
    return default


def as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "y", "on"}:
            return True
        if lowered in {"0", "false", "no", "n", "off"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def stable_int(seed: str) -> int:
    return int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12], 16)


def model_product_ids(cloud_products: Any) -> dict[str, int]:
    """Map model -> numeric product id from a cloud /api/v5/product payload."""
    ids: dict[str, int] = {}
    category_details = cloud_products.get("categoryDetailList") if isinstance(cloud_products, dict) else None
    for category_detail in category_details or []:
        for product in (category_detail or {}).get("productList") or []:
            model = str(product.get("model") or "").strip().lower()
            product_id = as_int(product.get("id"), 0)
            if model and product_id > 0:
                ids[model] = product_id
    return ids


# First label of the Roborock cloud API host -> cloud region.
CLOUD_REGIONS_BY_HOST = {"euiot": "eu", "usiot": "us", "cniot": "cn", "ruiot": "ru"}


def cloud_region_from_base_url(base_url: Any) -> str | None:
    """Return the cloud region of a cloud API base URL, or None for an unknown host."""
    url = str(base_url or "").strip()
    host = urlsplit(url if "//" in url else f"//{url}").hostname or ""
    return CLOUD_REGIONS_BY_HOST.get(host.split(".")[0])


def known_cloud_region(value: Any) -> str | None:
    """Return a region code like "EU" in lower case, or None if no cloud host has it."""
    region = str(value or "").strip().lower()
    return region if region in CLOUD_REGIONS_BY_HOST.values() else None


def default_home_id(ctx: ServerContext) -> int:
    return stable_int(f"{ctx.duid}:home")


def default_product_name(model: str) -> str:
    short_model = model.split(".")[-1].upper() if model else "VACUUM"
    return f"Roborock {short_model}"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
