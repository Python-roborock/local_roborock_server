"""Authenticated dashboard adapter for the existing schedule store.

This layer edits the recurring job and its cleaning payload. Room selection is
validated against fresh, read-only queries of the vacuum's loaded map.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from shared.constants import DEFAULT_TIMEZONE
from shared.data_helpers import as_bool
from shared.schedule_runner import next_fire_time_utc, parse_cron
from shared.schedule_store import upsert_job

from .admin_schedule_settings import (
    RoomCatalogError, merge_settings, read_room_catalog, schedule_param,
    setting_choices, validate_rooms,
)
from .admin_schedule_timers import TimerSyncError, sync_timer


_SETTING_KEYS = (
    "map_index", "segments", "fan_power", "water_box_mode", "mop_mode",
    "mop_template_id", "clean_order_mode", "repeat", "clean_mop",
)
_EDIT_FIELDS = frozenset({"cron", "timeZoneId", "enabled", "repeated", "settings"})


def _response(payload: dict[str, Any], status: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status, headers={"Cache-Control": "no-store"})


def _inventory(supervisor: Any) -> dict[str, Any]:
    path = supervisor.paths.inventory_path
    if not path.exists():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("schedules", {}), dict):
        raise ValueError("Invalid inventory shape")
    return value


def _revision(job: dict[str, Any]) -> str:
    data = json.dumps(job, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _job_param(job: dict[str, Any]) -> dict[str, Any]:
    param = job.get("param")
    if isinstance(param, str):
        try:
            param = json.loads(param)
        except (ValueError, TypeError):
            return {}
    return param if isinstance(param, dict) else {}


def _settings(job: dict[str, Any]) -> dict[str, Any]:
    params = _job_param(job).get("params")
    if isinstance(params, list) and len(params) == 1:
        params = params[0]
    return params if isinstance(params, dict) else {}


def _schedule(job: dict[str, Any], default_zone: str, now: datetime) -> dict[str, Any]:
    settings = _settings(job)
    native = settings.get("name")
    recurring = as_bool(job.get("repeated", True), True)
    next_run = next_fire_time_utc(job, default_timezone=default_zone, now=now)
    # Never return the inventory record or command payload wholesale: imported
    # records can contain fields unrelated to a schedule editor.
    return {
        "id": job.get("id"),
        "revision": _revision(job),
        "cron": str(job.get("cron") or ""),
        "timeZoneId": str(job.get("timeZoneId") or default_zone),
        "enabled": as_bool(job.get("enabled", True), True),
        "repeated": recurring,
        "next_run_at": next_run.isoformat() if next_run else None,
        "native_timer_name": native if isinstance(native, str) else None,
        "native_timer_state": "not_checked" if "name" in settings else None,
        "settings": {key: settings[key] for key in _SETTING_KEYS if key in settings},
        "setting_choices": setting_choices(settings),
        "settings_editable": schedule_param(job) is not None,
        "editable": isinstance(job.get("id"), (int, str)) and not isinstance(job.get("id"), bool),
    }


def _list_payload(supervisor: Any) -> dict[str, Any]:
    inventory = _inventory(supervisor)
    schedules = inventory.get("schedules", {})
    now = datetime.now(timezone.utc)
    default_zone = supervisor.config.network.timezone or DEFAULT_TIMEZONE
    devices: dict[str, dict[str, Any]] = {}
    for raw in supervisor._vacuums_payload().get("vacuums", []):
        duid = str(raw.get("duid") or "")
        if duid:
            devices[duid] = {
                "duid": duid,
                "name": str(raw.get("name") or "Unnamed vacuum"),
                "model": str(raw.get("model") or ""),
                "connected": raw.get("connected") is True,
                "schedules": [],
            }
    for duid, jobs in schedules.items():
        if not isinstance(jobs, list):
            raise ValueError("Invalid schedule list")
        device = devices.setdefault(str(duid), {
            "duid": str(duid), "name": "Unlisted vacuum", "model": "",
            "connected": None, "schedules": [],
        })
        for job in jobs:
            if not isinstance(job, dict):
                raise ValueError("Invalid schedule record")
            device["schedules"].append(_schedule(job, default_zone, now))
    return {
        "generated_at": now.isoformat(),
        "server_timezone": default_zone,
        "supported": True,
        "devices": list(devices.values()),
    }


async def _update(supervisor: Any, duid: str, job_id: str, body: Any) -> JSONResponse:
    if not isinstance(body, dict):
        return _response({"error": "JSON body must be an object"}, 400)
    if set(body) - (_EDIT_FIELDS | {"revision", "room_revision"}):
        return _response({"error": "Only schedule time, enablement, rooms and cleaning options can be edited here"}, 400)
    if not isinstance(body.get("revision"), str) or not (set(body) & _EDIT_FIELDS):
        return _response({"error": "A revision and at least one edited field are required"}, 400)
    try:
        jobs = _inventory(supervisor).get("schedules", {}).get(duid, [])
        if not isinstance(jobs, list):
            raise ValueError("Invalid schedule list")
    except (OSError, ValueError):
        return _response({"error": "Unable to read stored schedules"}, 500)
    matches = [job for job in jobs if isinstance(job, dict) and str(job.get("id")) == job_id]
    if not matches:
        return _response({"error": "Schedule not found"}, 404)
    if len(matches) != 1:
        return _response({"error": "Duplicate schedule IDs must be resolved before editing"}, 409)
    existing = matches[0]
    if body["revision"] != _revision(existing):
        return _response({"error": "This schedule changed. Reload it before saving again."}, 409)
    cron = body.get("cron", existing.get("cron"))
    enabled = body.get("enabled", as_bool(existing.get("enabled", True), True))
    repeated = body.get("repeated", as_bool(existing.get("repeated", True), True))
    zone = body.get("timeZoneId", "")
    if not isinstance(cron, str) or not cron.strip() or len(cron) > 200:
        return _response({"error": "A valid five-field schedule expression is required"}, 400)
    if type(enabled) is not bool:
        return _response({"error": "Schedule enablement must be true or false"}, 400)
    if type(repeated) is not bool:
        return _response({"error": "Repeat must be true or false"}, 400)
    if "timeZoneId" in body and (not isinstance(zone, str) or not zone.strip() or len(zone) > 100):
        return _response({"error": "Enter a valid IANA timezone"}, 400)
    try:
        parse_cron(cron)
        if "timeZoneId" in body:
            zone = zone.strip()
            ZoneInfo(zone)
    except (ValueError, ZoneInfoNotFoundError):
        return _response({"error": "Check the schedule expression and IANA timezone"}, 400)
    param = None
    if "settings" in body:
        try:
            param, needs_rooms = merge_settings(existing, body["settings"])
        except ValueError as exc:
            return _response({"error": str(exc)}, 400)
        if needs_rooms:
            try:
                catalog = await read_room_catalog(supervisor, duid)
                validate_rooms(param, catalog, body.get("room_revision"))
            except KeyError:
                return _response({"error": "Vacuum not found"}, 404)
            except RoomCatalogError as exc:
                return _response({"error": str(exc), "code": "room_catalog_changed"}, 409)
    native_state = None
    settings = _settings(existing)
    params = _job_param(existing).get("params")
    has_native_reference = "name" in settings or (
        isinstance(params, list) and any(isinstance(entry, dict) and "name" in entry for entry in params)
    )
    if "enabled" in body and has_native_reference:
        name = settings.get("name")
        if not isinstance(name, str) or not name.strip():
            return _response({"error": "This schedule has no usable robot timer reference."}, 409)

        def check_current() -> None:
            try:
                latest = _inventory(supervisor).get("schedules", {}).get(duid, [])
                if not isinstance(latest, list):
                    raise ValueError("Invalid schedule list")
            except (OSError, ValueError):
                raise TimerSyncError("Unable to read stored schedules", 500) from None
            current = [job for job in latest if isinstance(job, dict) and str(job.get("id")) == job_id]
            if current != [existing]:
                raise TimerSyncError("This schedule changed. Reload it before saving again.", 409)
            linked = [job for job in latest if isinstance(job, dict) and _settings(job).get("name") == name]
            if len(linked) != 1:
                raise TimerSyncError("Multiple schedules reference this robot timer. Resolve that conflict before changing it.", 409)

        try:
            check_current()
            native_state = await sync_timer(supervisor, duid, name, enabled, check_current=check_current)
            check_current()
        except TimerSyncError as exc:
            if native_state is not None:
                return _response({"error": f"The robot timer was verified {native_state}, but the schedule changed or could not be read again. Refresh schedules and retry.",
                                  "code": "schedule_changed_after_timer_sync"}, exc.status)
            return _response({"error": str(exc), "code": "timer_sync_failed"}, exc.status)
    try:
        updated = upsert_job(
            supervisor.context, duid, job_id=existing["id"], cron=cron.strip(), enabled=enabled,
            time_zone=zone, override_time_zone="timeZoneId" in body, expected_job=existing,
            param=param,
            repeated=repeated if "repeated" in body else None,
        )
    except ValueError:
        if native_state is not None:
            return _response({"error": "This schedule changed while its robot timer was being verified. Refresh schedules and retry.",
                              "code": "schedule_changed_after_timer_sync"}, 409)
        return _response({"error": "This schedule changed. Reload it before saving again."}, 409)
    except OSError:
        if native_state is not None:
            return _response({"error": f"The robot timer was verified {native_state}, but the server schedule could not be saved. Refresh schedules and retry.",
                              "code": "schedule_save_failed_after_timer_sync"}, 500)
        return _response({"error": "Unable to save the schedule. Your changes were not acknowledged."}, 500)
    default_zone = supervisor.config.network.timezone or DEFAULT_TIMEZONE
    now = datetime.now(timezone.utc)
    payload = _schedule(updated, default_zone, now)
    if native_state is not None:
        payload.update(native_timer_state=native_state, native_timer_checked_at=now.isoformat())
    return _response({"schedule": payload})


async def _edit_body(request: Request) -> Any:
    origin = request.headers.get("origin")
    if origin:
        try:
            parsed = urlsplit(origin)
        except ValueError:
            return _response({"error": "Invalid request origin"}, 403)
        if parsed.scheme not in ("http", "https") or parsed.netloc.casefold() != request.headers.get("host", "").casefold():
            return _response({"error": "Cross-origin schedule changes are not allowed"}, 403)
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        return _response({"error": "Use an application/json request body"}, 415)
    raw = await request.body()
    if len(raw) > 16384:
        return _response({"error": "Schedule edit is too large"}, 413)
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return _response({"error": "Invalid JSON body"}, 400)


def register_schedule_routes(app: FastAPI, supervisor: Any) -> None:
    # Dashboard writes and background reconciliation share the same per-vacuum lock.
    # The expected-job check still detects edits made by an app during an await.

    @app.get("/admin/api/schedules/{duid}/rooms")
    async def schedule_rooms(duid: str, request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        try:
            return _response(await read_room_catalog(supervisor, duid))
        except KeyError:
            return _response({"error": "Vacuum not found"}, 404)
        except RoomCatalogError as exc:
            return _response({"error": str(exc)}, 503)

    @app.post("/admin/api/schedules/{duid}/rooms")
    async def load_schedule_map(duid: str, request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        body = await _edit_body(request)
        if isinstance(body, JSONResponse):
            return body
        if not isinstance(body, dict) or set(body) != {"map_index"} or type(body["map_index"]) is not int or not 0 <= body["map_index"] < 63:
            return _response({"error": "Choose a saved map reported by this vacuum."}, 400)
        try:
            return _response(await read_room_catalog(supervisor, duid, load_map=body["map_index"]))
        except KeyError:
            return _response({"error": "Vacuum not found"}, 404)
        except RoomCatalogError as exc:
            return _response({"error": str(exc)}, 409)

    @app.get("/admin/api/schedules")
    async def schedules_list(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        try:
            return _response(_list_payload(supervisor))
        except (OSError, ValueError, TypeError):
            return _response({"error": "Unable to read stored schedules"}, 500)

    @app.patch("/admin/api/schedules/{duid}/{job_id}")
    async def schedules_update(duid: str, job_id: str, request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        body = await _edit_body(request)
        if isinstance(body, JSONResponse):
            return body
        async with supervisor.schedule_sync.lock(duid):
            return await _update(supervisor, duid, job_id, body)
