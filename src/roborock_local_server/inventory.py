"""Inventory helpers used by the release admin API."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .bundled_backend.shared.runtime_state import ONBOARDING_STEP_LABELS, REQUIRED_ONBOARDING_STEPS

if TYPE_CHECKING:
    from .bundled_backend.shared.context import ServerContext


def _default_inventory() -> dict[str, Any]:
    return {
        "home": {
            "name": "Local Home",
            "rooms": [{"id": 1, "name": "Living Room"}],
        },
        "devices": [],
        "received_devices": [],
        "scenes": [],
        "schedules": {},
    }


def _load_inventory(path: Path) -> dict[str, Any]:
    if not path.exists():
        return _default_inventory()
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _default_inventory()
    if not isinstance(loaded, dict):
        return _default_inventory()
    return loaded


def _extract_inventory_vacuums(context: "ServerContext", inventory: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for source_key in ("devices", "received_devices", "receivedDevices"):
        source_list = inventory.get(source_key)
        if not isinstance(source_list, list):
            continue
        for raw in source_list:
            if not isinstance(raw, dict):
                continue
            duid = str(raw.get("duid") or raw.get("did") or raw.get("device_id") or "").strip()
            if not duid:
                continue
            local_key = context.resolve_device_localkey(
                did=str(raw.get("did") or raw.get("device_did") or "").strip(),
                duid=duid,
                model=str(raw.get("model") or "").strip(),
                name=str(raw.get("name") or raw.get("device_name") or "").strip(),
                product_id=str(raw.get("product_id") or raw.get("productId") or "").strip(),
                source="inventory",
                assign_if_missing=True,
            )
            mapped_device = (
                context.runtime_credentials.resolve_device(
                    did=str(raw.get("did") or raw.get("device_did") or "").strip(),
                    duid=duid,
                    model=str(raw.get("model") or "").strip(),
                )
                if context.runtime_credentials is not None
                else None
            )
            out.append(
                {
                    "duid": duid,
                    "did": str((mapped_device or {}).get("did") or raw.get("did") or raw.get("device_did") or "").strip(),
                    "name": str(raw.get("name") or raw.get("device_name") or "").strip(),
                    "local_key": local_key,
                    "model": str(raw.get("model") or "").strip(),
                    "product_id": str(raw.get("product_id") or raw.get("productId") or "").strip(),
                    "pv": str(raw.get("pv") or "").strip(),
                    "source": source_key,
                }
            )
    return out


def _merge_vacuum_state(
    *,
    context: "ServerContext",
    inventory_vacuums: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    runtime_state = context.runtime_state
    key_models_by_did: dict[str, str] = {}
    if runtime_state is not None:
        for inv in inventory_vacuums:
            runtime_state.upsert_vacuum(
                inv["duid"],
                name=inv.get("name") or None,
                local_key=inv.get("local_key") or None,
                source=inv.get("source") or "inventory",
            )
        runtime_vacuums = runtime_state.vacuum_snapshot()
        key_models_by_did = runtime_state.key_models_by_did()
    else:
        runtime_vacuums = []

    by_inventory = {item["duid"]: item for item in inventory_vacuums}
    by_inventory_did = {
        str(item.get("did") or "").strip(): item
        for item in inventory_vacuums
        if str(item.get("did") or "").strip()
    }
    inventory_by_unique_model: dict[str, dict[str, Any]] = {}
    inventory_model_counts: dict[str, int] = {}
    for inv in inventory_vacuums:
        model = str(inv.get("model") or "").strip().lower()
        if not model:
            continue
        inventory_model_counts[model] = inventory_model_counts.get(model, 0) + 1
    for inv in inventory_vacuums:
        model = str(inv.get("model") or "").strip().lower()
        if not model:
            continue
        if inventory_model_counts.get(model, 0) == 1:
            inventory_by_unique_model[model] = inv

    out: list[dict[str, Any]] = []
    seen_inventory_duids: set[str] = set()
    seen_runtime_duids: set[str] = set()

    def _runtime_item_is_active(item: dict[str, Any]) -> bool:
        if bool(item.get("connected")):
            return True
        if str(item.get("last_message_at") or "").strip():
            return True
        if str(item.get("last_http_at") or "").strip():
            return True
        if str(item.get("last_mqtt_at") or "").strip():
            return True
        onboarding_steps = item.get("onboarding_steps")
        if isinstance(onboarding_steps, dict) and onboarding_steps:
            return True
        return False

    runtime_items_sorted = sorted(
        runtime_vacuums,
        key=lambda item: (
            0 if _runtime_item_is_active(item) else 1,
            0 if bool(item.get("connected")) else 1,
            (item.get("name") or "").lower(),
            item.get("duid") or "",
        ),
    )

    for runtime_item in runtime_items_sorted:
        runtime_identifier = str(runtime_item.get("duid") or "")
        if not runtime_identifier or runtime_identifier in seen_runtime_duids:
            continue
        runtime_id_kind = str(runtime_item.get("id_kind") or "").strip().lower()
        runtime_did = str(runtime_item.get("did") or "").strip()
        runtime_duid_candidate = runtime_identifier
        if runtime_id_kind == "did":
            runtime_did = runtime_did or runtime_identifier
            runtime_duid_candidate = ""
        inv = by_inventory.get(runtime_duid_candidate, {}) if runtime_duid_candidate else {}
        linked_via = ""
        if not inv and runtime_did:
            inv = by_inventory_did.get(runtime_did, {})
            if inv:
                linked_via = "did"
        runtime_model_hint = str(runtime_item.get("key_model") or key_models_by_did.get(runtime_did) or "").strip()
        if not inv and runtime_model_hint:
            inv = inventory_by_unique_model.get(runtime_model_hint.lower(), {})
            if inv:
                linked_via = "model_pid"
        inventory_duid = str(inv.get("duid") or "")
        if inventory_duid and inventory_duid in seen_inventory_duids:
            continue
        if not inv and not _runtime_item_is_active(runtime_item):
            continue
        merged = dict(runtime_item)
        merged["name"] = merged.get("name") or inv.get("name") or runtime_identifier
        merged["local_key"] = merged.get("local_key") or inv.get("local_key") or ""
        merged["model"] = inv.get("model") or runtime_model_hint or ""
        merged["product_id"] = inv.get("product_id") or ""
        merged["pv"] = inv.get("pv") or ""
        merged["inventory_source"] = inv.get("source") or merged.get("source") or ""
        if inventory_duid:
            merged["duid"] = inventory_duid
            merged["id_kind"] = "duid"
            if runtime_did:
                merged["did"] = runtime_did
                merged["runtime_did"] = runtime_did
        elif runtime_did:
            merged["did"] = runtime_did
            merged["runtime_did"] = runtime_did
            merged.setdefault("id_kind", "did")
        elif str(inv.get("did") or "").strip():
            merged["did"] = str(inv.get("did") or "").strip()
        if inventory_duid and linked_via:
            merged["linked_inventory_duid"] = inventory_duid
            merged["linked_inventory_name"] = str(inv.get("name") or "")
            merged["linked_via"] = linked_via
        out.append(merged)
        seen_runtime_duids.add(runtime_identifier)
        if inventory_duid:
            seen_inventory_duids.add(inventory_duid)

    for inv in inventory_vacuums:
        duid = inv["duid"]
        if duid in seen_inventory_duids or duid in seen_runtime_duids:
            continue
        out.append(
            {
                "duid": duid,
                "did": str(inv.get("did") or "").strip(),
                "id_kind": "duid",
                "name": inv.get("name") or duid,
                "local_key": inv.get("local_key") or "",
                "model": inv.get("model") or "",
                "product_id": inv.get("product_id") or "",
                "pv": inv.get("pv") or "",
                "inventory_source": inv.get("source") or "",
                "connected": False,
                "last_message_at": "",
                "last_message_source": "",
                "onboarding_steps": {},
                "onboarding": {
                    "required_steps": list(REQUIRED_ONBOARDING_STEPS),
                    "step_labels": dict(ONBOARDING_STEP_LABELS),
                    "missing_steps": list(REQUIRED_ONBOARDING_STEPS),
                    "has_required_messages": False,
                    "has_public_key": False,
                    "public_key_ready": False,
                    "status": "collecting_messages",
                    "guidance": "Waiting for onboarding traffic from this vacuum.",
                    "unsupported": False,
                    "unsupported_reason": "",
                    "key_state": {
                        "query_samples": 0,
                        "header_samples": 0,
                        "max_signature_len": 0,
                        "has_modulus": False,
                        "recovery_state": "",
                        "recovery_note": "",
                        "recovery_error": "",
                        "recovery_started_at": "",
                        "recovery_finished_at": "",
                    },
                },
            }
        )

    out.sort(key=lambda item: ((item.get("name") or "").lower(), item.get("duid") or ""))
    return out
