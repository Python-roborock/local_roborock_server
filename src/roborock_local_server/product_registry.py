from __future__ import annotations

import copy
import json
import logging
from pathlib import Path
from typing import Any

from .bundled_backend.shared.constants import DEFAULT_PRODUCT_SCHEMA

_LOGGER = logging.getLogger(__name__)

# B01 protocol 28-item schema (for Tuya-DP models like Q7 Series sc05)
B01_PRODUCT_SCHEMA: list[dict[str, Any]] = [
    {"id": 101, "name": "RPC Request", "code": "rpc_request", "mode": "rw", "type": "RAW"},
    {"id": 102, "name": "RPC Response", "code": "rpc_response", "mode": "rw", "type": "RAW"},
    {"id": 120, "name": "error_code", "code": "error_code", "mode": "ro", "type": "ENUM"},
    {"id": 121, "name": "state", "code": "state", "mode": "ro", "type": "VALUE"},
    {"id": 122, "name": "battery", "code": "battery", "mode": "ro", "type": "ENUM"},
    {"id": 123, "name": "fan_power", "code": "fan_power", "mode": "rw", "type": "ENUM"},
    {"id": 124, "name": "water_box_mode", "code": "water_box_mode", "mode": "rw", "type": "RAW"},
    {"id": 125, "name": "main_brush_life", "code": "main_brush_life", "mode": "ro", "type": "ENUM"},
    {"id": 126, "name": "side_brush_life", "code": "side_brush_life", "mode": "ro", "type": "ENUM"},
    {"id": 127, "name": "filter_life", "code": "filter_life", "mode": "ro", "type": "ENUM"},
    {"id": 135, "name": "offline_status", "code": "offline_status", "mode": "ro", "type": "ENUM"},
    {"id": 136, "name": "clean_times", "code": "clean_times", "mode": "rw", "type": "ENUM"},
    {"id": 137, "name": "cleaning_preference", "code": "cleaning_preference", "mode": "rw", "type": "ENUM"},
    {"id": 138, "name": "clean_task_type", "code": "clean_task_type", "mode": "ro", "type": "ENUM"},
    {"id": 139, "name": "back_type", "code": "back_type", "mode": "ro", "type": "ENUM"},
    {"id": 141, "name": "cleaning_progress", "code": "cleaning_progress", "mode": "ro", "type": "ENUM"},
    {"id": 142, "name": "fc_state", "code": "fc_state", "mode": "ro", "type": "RAW"},
    {"id": 201, "name": "start_clean_task", "code": "start_clean_task", "mode": "wo", "type": "ENUM"},
    {"id": 202, "name": "start_back_dock_task", "code": "start_back_dock_task", "mode": "wo", "type": "ENUM"},
    {"id": 203, "name": "start_dock_task", "code": "start_dock_task", "mode": "wo", "type": "ENUM"},
    {"id": 204, "name": "pause", "code": "pause", "mode": "wo", "type": "RAW"},
    {"id": 205, "name": "resume", "code": "resume", "mode": "wo", "type": "RAW"},
    {"id": 206, "name": "stop", "code": "stop", "mode": "wo", "type": "RAW"},
    {"id": 10000, "name": "request_cmd", "code": "request_cmd", "mode": "wo", "type": "RAW"},
    {"id": 10001, "name": "response_cmd", "code": "response_cmd", "mode": "ro", "type": "RAW"},
    {"id": 10002, "name": "request_map", "code": "request_map", "mode": "ro", "type": "RAW"},
    {"id": 10003, "name": "response_map", "code": "response_map", "mode": "ro", "type": "RAW"},
    {"id": 10004, "name": "event_report", "code": "event_report", "mode": "rw", "type": "RAW"},
]

# Built-in Roborock device registry mapping model identifiers to verified profiles
BUILTIN_PRODUCT_REGISTRY: dict[str, dict[str, Any]] = {
    "roborock.vacuum.a87": {
        "model": "roborock.vacuum.a87",
        "product_name": "Roborock Qrevo MaxV",
        "category": "robot.vacuum.cleaner",
        "product_id": "5gUei3OIJIXVD3eD85Balg",
        "schema": DEFAULT_PRODUCT_SCHEMA,
    },
    "roborock.vacuum.a15": {
        "model": "roborock.vacuum.a15",
        "product_name": "Roborock S7",
        "category": "robot.vacuum.cleaner",
        "product_id": "1YYW18rpgyAJTISwb1NM91",
        "schema": DEFAULT_PRODUCT_SCHEMA,
    },
    "roborock.vacuum.sc05": {
        "model": "roborock.vacuum.sc05",
        "product_name": "Roborock Q7 Series",
        "category": "robot.vacuum.cleaner",
        "product_id": "5ayEx3aKgStqZZ0v5IpMBP",
        "schema": B01_PRODUCT_SCHEMA,
    },
    "roborock.vacuum.a72": {
        "model": "roborock.vacuum.a72",
        "product_name": "Roborock Q5 Pro",
        "category": "robot.vacuum.cleaner",
        "product_id": "a72",
        "schema": DEFAULT_PRODUCT_SCHEMA,
    },
    "roborock.vacuum.a51": {
        "model": "roborock.vacuum.a51",
        "product_name": "Roborock S8",
        "category": "robot.vacuum.cleaner",
        "product_id": "a51",
        "schema": DEFAULT_PRODUCT_SCHEMA,
    },
    "roborock.vacuum.a27": {
        "model": "roborock.vacuum.a27",
        "product_name": "Roborock S7 MaxV",
        "category": "robot.vacuum.cleaner",
        "product_id": "a27",
        "schema": DEFAULT_PRODUCT_SCHEMA,
    },
    "roborock.vacuum.a75": {
        "model": "roborock.vacuum.a75",
        "product_name": "Roborock Q Revo",
        "category": "robot.vacuum.cleaner",
        "product_id": "a75",
        "schema": DEFAULT_PRODUCT_SCHEMA,
    },
    "roborock.vacuum.a288": {
        "model": "roborock.vacuum.a288",
        "product_name": "Roborock Saros 20 Complete",
        "category": "robot.vacuum.cleaner",
        "product_id": "a288",
        "schema": DEFAULT_PRODUCT_SCHEMA,
    },
    "roborock.vacuum.a170": {
        "model": "roborock.vacuum.a170",
        "product_name": "Roborock Qrevo C",
        "category": "robot.vacuum.cleaner",
        "product_id": "a170",
        "schema": DEFAULT_PRODUCT_SCHEMA,
    },
    "roborock.vacuum.s5e": {
        "model": "roborock.vacuum.s5e",
        "product_name": "Roborock S5 Max",
        "category": "robot.vacuum.cleaner",
        "product_id": "s5e",
        "schema": DEFAULT_PRODUCT_SCHEMA,
    },
    "roborock.vacuum.a102": {
        "model": "roborock.vacuum.a102",
        "product_name": "Roborock Zeo One",
        "category": "roborock.washer",
        "product_id": "a102",
        "schema": DEFAULT_PRODUCT_SCHEMA,
    },
}


def normalize_model_string(model: str | None) -> str:
    """Normalize a model name into canonical roborock.<category>.<code format."""
    trimmed = str(model or "").strip().lower()
    if not trimmed:
        return ""
    if trimmed.startswith("roborock."):
        return trimmed
    # If passed just a short code like 'a72' or 'sc05'
    return f"roborock.vacuum.{trimmed}"


def resolve_product_metadata(
    model: str | None,
    custom_name: str | None = None,
    custom_registry_path: Path | None = None,
) -> dict[str, Any]:
    """Resolve full product metadata and schema for a given model.

    Checks:
    1. Optional custom user registry JSON file
    2. Built-in product registry
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

    # Check built-in registry
    if normalized_model in BUILTIN_PRODUCT_REGISTRY:
        result = copy.deepcopy(BUILTIN_PRODUCT_REGISTRY[normalized_model])
        if custom_name:
            result["product_name"] = custom_name
        return result
    if short_code and short_code in BUILTIN_PRODUCT_REGISTRY:
        result = copy.deepcopy(BUILTIN_PRODUCT_REGISTRY[short_code])
        if custom_name:
            result["product_name"] = custom_name
        return result

    # Fallback to standard baseline
    fallback_name = custom_name or (f"Roborock {short_code.upper()}" if short_code else "Roborock Vacuum")
    return {
        "model": normalized_model or "roborock.vacuum.generic",
        "product_name": fallback_name,
        "category": "robot.vacuum.cleaner",
        "product_id": short_code or "generic",
        "schema": copy.deepcopy(DEFAULT_PRODUCT_SCHEMA),
    }


def export_sanitized_device_profile(raw_device: dict[str, Any]) -> dict[str, Any] | None:
    """Scrub sensitive PII/credentials and return a clean community device profile.

    Removes did, duid, local_key, sn, wifi SSID/BSSID, MAC, IP, home details, tokens.
    Retains model, product_name, category, product_id, capability, and schema.
    """
    if not isinstance(raw_device, dict):
        return None

    model = str(raw_device.get("model") or "").strip()
    if not model:
        return None

    name = str(raw_device.get("product_name") or raw_device.get("name") or "").strip()
    category = str(raw_device.get("category") or "robot.vacuum.cleaner").strip()
    if category.startswith("RoborockCategory."):
        cat_suffix = category.split(".")[-1].lower()
        category = "roborock.washer" if cat_suffix == "washer" else "robot.vacuum.cleaner"

    product_id = str(raw_device.get("product_id") or raw_device.get("id") or "").strip()
    capability = raw_device.get("capability")
    schema = raw_device.get("schema")

    profile: dict[str, Any] = {
        "model": model,
        "product_name": name or f"Roborock {model.split('.')[-1].upper()}",
        "category": category,
        "product_id": product_id or model.split(".")[-1],
    }

    if capability is not None:
        profile["capability"] = capability

    if isinstance(schema, list) and schema:
        # Sanitize schema items: ensure standard fields id, name, code, mode, type
        sanitized_schema: list[dict[str, Any]] = []
        for item in schema:
            if isinstance(item, dict):
                sanitized_item: dict[str, Any] = {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "code": item.get("code"),
                    "mode": item.get("mode"),
                    "type": item.get("type"),
                }
                if item.get("property") is not None:
                    sanitized_item["property"] = item.get("property")
                sanitized_schema.append(sanitized_item)
        profile["schema"] = sanitized_schema
    else:
        profile["schema"] = copy.deepcopy(DEFAULT_PRODUCT_SCHEMA)

    return profile


def export_inventory_device_profiles(inventory: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    """Export sanitized profiles for all distinct device models in an inventory or snapshot."""
    seen_models: set[str] = set()
    profiles: list[dict[str, Any]] = []

    candidates: list[Any] = []
    if isinstance(inventory, list):
        candidates.extend(inventory)
    elif isinstance(inventory, dict):
        for key in ("devices", "received_devices", "products"):
            val = inventory.get(key)
            if isinstance(val, list):
                candidates.extend(val)
        home_data = inventory.get("home_data")
        if isinstance(home_data, dict):
            for key in ("devices", "received_devices", "products"):
                val = home_data.get(key)
                if isinstance(val, list):
                    candidates.extend(val)

    for item in candidates:
        if isinstance(item, dict):
            profile = export_sanitized_device_profile(item)
            if profile and profile["model"] not in seen_models:
                seen_models.add(profile["model"])
                profiles.append(profile)

    return profiles
