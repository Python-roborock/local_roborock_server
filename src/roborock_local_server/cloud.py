"""Cloud import helpers for the admin API."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import threading
import time
from typing import Any

import aiohttp
from roborock.web_api import RoborockApiClient

from .backend import (
    _build_inventory,
    _fetch_additional_web_cache,
    _fetch_cloud_home_data_with_api,
    _flatten_device_scenes,
    _normalize_dict_list,
    _normalize_dict_map,
    _normalize_room_list,
    _normalize_schedule_map,
    _normalize_value_map,
)


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
    country: str
    country_code: int | None
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
            resolved_country = str(await api.country)
            resolved_country_code_raw = str(await api.country_code)
            resolved_country_code = int(resolved_country_code_raw) if resolved_country_code_raw.isdigit() else None
            device_identifier = str(getattr(api, "_device_identifier", "") or "")

        session_id = secrets.token_urlsafe(18)
        expires_at_ts = time.time() + self.ttl_seconds
        pending = PendingCloudSession(
            session_id=session_id,
            email=normalized_email,
            base_url=resolved_base_url,
            country=resolved_country,
            country_code=resolved_country_code,
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
            user_data = await api.code_login_v4(
                normalized_code,
                country=session_data.country or None,
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
                "source": "admin_email_code_login",
            },
            "user_data": _to_jsonable(user_data),
            "home_data": _to_jsonable(home_data),
            "web_api_cache": _to_jsonable(web_cache),
        }
        normalized_inventory = _to_jsonable(inventory)
        normalized_snapshot = _to_jsonable(snapshot)

        self.inventory_path.parent.mkdir(parents=True, exist_ok=True)
        self.inventory_path.write_text(json.dumps(normalized_inventory, indent=2) + "\n", encoding="utf-8")
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
