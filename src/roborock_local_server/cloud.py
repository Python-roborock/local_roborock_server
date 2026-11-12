"""Cloud import helpers for the admin API."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import threading
import time
from typing import Any, Literal

import aiohttp
from roborock.data import UserData
from roborock.web_api import RoborockApiClient

from .backend import (
    _build_inventory,
    _fetch_additional_web_cache,
    _fetch_cloud_home_data_with_api,
    _fetch_plugin_catalogs,
    _flatten_device_scenes,
    _load_existing_inventory_for_merge,
    _merge_existing_inventory_mutations,
    _normalize_dict_list,
    _normalize_dict_map,
    _normalize_room_list,
    _normalize_schedule_map,
    _normalize_value_map,
)
from shared.inventory_io import atomic_write_inventory, inventory_transaction


def summarize_plugin_catalogs(catalogs: dict[str, Any]) -> dict[str, Any]:
    """The plugin catalogs reduced to what picks a plugin: versions, levels and download URLs."""
    keep = ("version", "apiLevel", "apilevel", "pluginLevel", "productid", "categoryId", "category", "moduleType", "url")
    summary: dict[str, Any] = {"fetched_at_utc": catalogs.get("fetched_at_utc")}
    for name, catalog in catalogs.items():
        if not isinstance(catalog, dict):
            continue
        entry: dict[str, Any] = {"params": catalog.get("params") or catalog.get("json") or {}}
        if "error" in catalog:
            entry["error"] = catalog["error"]
        data = catalog.get("data")
        if isinstance(data, dict):
            data = data.get("categoryPluginList")
        records = data if isinstance(data, list) else []
        entry["plugins"] = [
            {key: record[key] for key in keep if key in record} for record in records if isinstance(record, dict)
        ]
        summary[name] = entry
    return summary


def _to_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_jsonable(item) for item in value]
    if is_dataclass(value):
        return _to_jsonable(asdict(value))
    as_dict = getattr(value, "as_dict", None)
    if callable(as_dict):
        return _to_jsonable(as_dict())
    return str(value)


@dataclass
class PendingCloudSession:
    session_id: str
    email: str
    base_url: str
    country: str | None
    country_code: int | None
    login_method: Literal["v1", "v4"]
    device_identifier: str
    expires_at_ts: float


class CloudImportManager:
    """Handles request-code and submit-code admin flows."""

    def __init__(self, *, inventory_path: Path, snapshot_path: Path, ttl_seconds: int = 900) -> None:
        self.inventory_path = inventory_path
        self.snapshot_path = snapshot_path
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, PendingCloudSession] = {}
        self._lock = threading.Lock()

    def _cleanup_locked(self) -> None:
        now = time.time()
        expired = [key for key, value in self._sessions.items() if value.expires_at_ts <= now]
        for key in expired:
            self._sessions.pop(key, None)

    async def request_code(self, *, email: str, base_url: str = "") -> dict[str, Any]:
        normalized_email = email.strip()
        if not normalized_email:
            raise ValueError("email is required")
        timeout = aiohttp.ClientTimeout(total=60)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            api = RoborockApiClient(
                username=normalized_email,
                base_url=base_url.strip() or None,
                session=session,
            )
            await api.request_code_v4()
            resolved_base_url = str(await api.base_url)
            resolved_country = await api.country
            raw_country_code = await api.country_code
            if raw_country_code is None:
                resolved_country_code = None
            else:
                raw_country_code_str = str(raw_country_code)
                resolved_country_code = int(raw_country_code_str) if raw_country_code_str.isdigit() else None
            # Mirrors request_code_v4()'s own v1 fallback rule, so submit_code() can replay it.
            login_method: Literal["v1", "v4"] = (
                "v1" if resolved_country_code is None or resolved_country is None else "v4"
            )
            device_identifier = str(getattr(api, "_device_identifier", "") or "")

        session_id = secrets.token_urlsafe(18)
        expires_at_ts = time.time() + self.ttl_seconds
        pending = PendingCloudSession(
            session_id=session_id,
            email=normalized_email,
            base_url=resolved_base_url,
            country=resolved_country,
            country_code=resolved_country_code,
            login_method=login_method,
            device_identifier=device_identifier,
            expires_at_ts=expires_at_ts,
        )
        with self._lock:
            self._cleanup_locked()
            self._sessions[session_id] = pending
        return {
            "success": True,
            "step": "code_requested",
            "session_id": session_id,
            "email": normalized_email,
            "base_url": resolved_base_url,
            "country": resolved_country,
            "country_code": resolved_country_code,
            "expires_at": datetime.fromtimestamp(expires_at_ts, tz=timezone.utc).isoformat(),
        }

    def _read_snapshot(self) -> dict[str, Any]:
        try:
            parsed = json.loads(self.snapshot_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def plugin_catalogs(self) -> dict[str, Any]:
        """The stored plugin catalogs, summarized, without any cloud request."""
        web_cache = self._read_snapshot().get("web_api_cache")
        catalogs = web_cache.get("plugin_catalogs") if isinstance(web_cache, dict) else None
        return summarize_plugin_catalogs(catalogs) if isinstance(catalogs, dict) else {}

    async def refresh_plugin_catalogs(self, *, plugin_type: int = 2) -> dict[str, Any]:
        """Re-reads the plugin catalogs from the cloud with the login the snapshot already holds.

        Only the plugin catalogs in the snapshot change; the inventory is left alone. A rejected
        login needs the email-code sign-in again, which stores a fresh one.
        """
        snapshot = self._read_snapshot()
        meta = snapshot.get("meta") if isinstance(snapshot.get("meta"), dict) else {}
        try:
            user_data = UserData.from_dict(snapshot.get("user_data"))
        except (TypeError, ValueError, KeyError):
            user_data = None
        email = str(meta.get("username") or "")
        if user_data is None or not user_data.token or not email:
            raise ValueError("No cloud login is stored. Request a code and sign in first.")

        timeout = aiohttp.ClientTimeout(total=120)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            api = RoborockApiClient(username=email, base_url=str(meta.get("base_url") or "") or None, session=session)
            if meta.get("device_identifier"):
                setattr(api, "_device_identifier", str(meta["device_identifier"]))
            try:
                home_data = await _fetch_cloud_home_data_with_api(api, user_data)
                catalogs = await _fetch_plugin_catalogs(api, user_data, home_data, plugin_type=plugin_type)
            except Exception as exc:  # noqa: BLE001
                raise ValueError(
                    f"The cloud rejected the stored login ({exc}). Request a code and sign in again."
                ) from exc

        failed = [name for name, item in catalogs.items() if isinstance(item, dict) and "error" in item]
        if failed and len(failed) == sum(1 for item in catalogs.values() if isinstance(item, dict)):
            errors = "; ".join(str(catalogs[name]["error"]) for name in failed)
            raise ValueError(f"The cloud returned no plugin catalogs ({errors}). Request a code and sign in again.")

        web_cache = snapshot.get("web_api_cache")
        if not isinstance(web_cache, dict):
            web_cache = {}
            snapshot["web_api_cache"] = web_cache
        web_cache["plugin_catalogs"] = _to_jsonable(catalogs)
        self.snapshot_path.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
        return {"success": True, "step": "plugins_refreshed", "plugin_type": plugin_type, **summarize_plugin_catalogs(catalogs)}

    async def submit_code(self, *, session_id: str, code: str) -> dict[str, Any]:
        normalized_session_id = session_id.strip()
        normalized_code = code.strip()
        if not normalized_session_id:
            raise ValueError("session_id is required")
        if not normalized_code:
            raise ValueError("code is required")

        with self._lock:
            self._cleanup_locked()
            session_data = self._sessions.get(normalized_session_id)
        if session_data is None:
            raise ValueError("Session expired or not found. Request a new code.")

        timeout = aiohttp.ClientTimeout(total=120)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            api = RoborockApiClient(
                username=session_data.email,
                base_url=session_data.base_url or None,
                session=session,
            )
            if session_data.device_identifier:
                setattr(api, "_device_identifier", session_data.device_identifier)
            if session_data.login_method == "v1":
                user_data = await api.code_login(normalized_code)
            else:
                user_data = await api.code_login_v4(
                    normalized_code,
                    country=session_data.country,
                    country_code=session_data.country_code,
                )
            home_data = await _fetch_cloud_home_data_with_api(api, user_data)
            web_cache = await _fetch_additional_web_cache(api, user_data, home_data)

        device_scenes = {
            device_id: _normalize_dict_list(scene_list)
            for device_id, scene_list in _normalize_value_map(web_cache.get("device_scenes")).items()
        }
        inventory = _build_inventory(
            home_data,
            rooms=_normalize_room_list(web_cache.get("rooms") if isinstance(web_cache.get("rooms"), list) else None),
            scenes=_flatten_device_scenes(device_scenes),
            schedules=_normalize_schedule_map(web_cache.get("device_schedules")),
            scene_order=list(web_cache.get("scene_order") or []),
            home_scenes=_normalize_dict_list(web_cache.get("home_scenes")),
            device_details=_normalize_dict_map(web_cache.get("device_details")),
            device_extras=_normalize_value_map(web_cache.get("device_extras")),
        )
        snapshot = {
            "meta": {
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "username": session_data.email,
                "base_url": session_data.base_url,
                "device_identifier": session_data.device_identifier,
                "source": "admin_email_code_login",
            },
            "user_data": _to_jsonable(user_data),
            "home_data": _to_jsonable(home_data),
            "web_api_cache": _to_jsonable(web_cache),
        }
        normalized_inventory = _to_jsonable(inventory)
        normalized_snapshot = _to_jsonable(snapshot)
        self.inventory_path.parent.mkdir(parents=True, exist_ok=True)
        with inventory_transaction(self.inventory_path):
            normalized_inventory = _merge_existing_inventory_mutations(
                normalized_inventory,
                _load_existing_inventory_for_merge(self.inventory_path),
            )

            atomic_write_inventory(self.inventory_path, normalized_inventory)
        self.snapshot_path.write_text(json.dumps(normalized_snapshot, indent=2) + "\n", encoding="utf-8")

        with self._lock:
            self._sessions.pop(normalized_session_id, None)

        device_names = [
            str(device.get("name") or "<unnamed>")
            for device in normalized_inventory.get("devices", [])
            if isinstance(device, dict)
        ]
        shared_device_names = [
            str(device.get("name") or "<unnamed>")
            for device in normalized_inventory.get("received_devices", [])
            if isinstance(device, dict)
        ]
        return {
            "success": True,
            "step": "inventory_fetched",
            "inventory_path": str(self.inventory_path),
            "cloud_snapshot_path": str(self.snapshot_path),
            "home_name": str(normalized_inventory.get("home", {}).get("name", "")),
            "device_count": len(device_names),
            "shared_device_count": len(shared_device_names),
            "device_names": device_names,
            "shared_device_names": shared_device_names,
        }
