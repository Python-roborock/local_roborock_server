from __future__ import annotations

import json
import re
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from shared.constants import DEFAULT_TIMEZONE
from shared.context import ServerContext
from shared.data_helpers import as_bool
from shared.http_helpers import wrap_response
from shared.schedule_runner import parse_cron
from shared.schedule_store import SettingsError, delete_job, list_jobs, native_timer_name, upsert_job
from shared.native_schedule_sync import TimerSyncError, sync_timer

from .service import device_jobs_payload

_COLLECTION_RE = re.compile(r"/user/devices/([^/]+)/jobs")
_ITEM_RE = re.compile(r"/user/devices/([^/]+)/jobs/([^/]+)")


def match(path: str, method: str = "GET") -> bool:
    return method.upper() == "GET" and bool(_COLLECTION_RE.fullmatch(path.rstrip("/")))


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    parts = [part for part in clean_path.rstrip("/").split("/") if part]
    device_id = parts[-2] if len(parts) >= 2 else ""
    return wrap_response(device_jobs_payload(ctx, device_id))


def _error(code: int, message: str) -> dict[str, Any]:
    return {"success": False, "code": code, "msg": message, "data": None, "result": None}


def _json_body(body_params: dict[str, list[str]]) -> dict[str, Any]:
    for raw in body_params.get("__json") or []:
        try:
            parsed = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("request body must be a JSON object")


def _validate_zone(value: Any) -> str:
    name = str(value or "").strip()
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("timeZoneId must be a valid IANA timezone") from exc
    return name


def _parse_param(value: Any) -> dict[str, Any] | None:
    if isinstance(value, str) and value.strip():
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return None
    return value if isinstance(value, dict) else None


def match_create(path: str, method: str = "GET") -> bool:
    return method.upper() == "POST" and bool(_COLLECTION_RE.fullmatch(path.rstrip("/")))


def build_create(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    duid = _COLLECTION_RE.fullmatch(clean_path.rstrip("/")).group(1)  # type: ignore[union-attr]
    try:
        body = _json_body(body_params)
        cron = str(body.get("cron") or "").strip()
        parse_cron(cron)
        zone = _validate_zone(body.get("timeZoneId", getattr(ctx, "timezone", "") or DEFAULT_TIMEZONE))
    except ValueError as exc:
        return _error(400, str(exc))
    param = _parse_param(body.get("param"))
    if body.get("param") is not None and param is None:
        return _error(400, "param must be a JSON object")
    try:
        created = upsert_job(
            ctx, duid, job_id=body.get("id"), cron=cron,
            enabled=as_bool(body.get("enabled", True), True), time_zone=zone,
            repeated=as_bool(body.get("repeated", True), True), param=param,
            extra_fields=body, create_only=True,
        )
    except ValueError as exc:
        return _error(409, str(exc))
    except OSError:
        return _error(500, "unable to persist schedule")
    return wrap_response(created)


def match_update(path: str, method: str = "GET") -> bool:
    return method.upper() in ("PUT", "PATCH") and bool(_ITEM_RE.fullmatch(path.rstrip("/")))


class ScheduleUpdateError(ValueError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


def _prepare_update(ctx, duid, job_id, body_params):
    matches = [job for job in list_jobs(ctx, duid) if str(job.get("id")) == job_id]
    if not matches:
        raise ScheduleUpdateError(404, "schedule not found")
    if len(matches) != 1:
        raise ScheduleUpdateError(409, "duplicate schedule IDs")
    existing = matches[0]
    try:
        body = _json_body(body_params)
        cron = str(body.get("cron", existing.get("cron")) or "").strip()
        parse_cron(cron)
        zone = _validate_zone(body["timeZoneId"]) if "timeZoneId" in body else ""
    except ValueError as exc:
        raise ScheduleUpdateError(400, str(exc)) from exc
    param = _parse_param(body.get("param")) if "param" in body else None
    if "param" in body and param is None:
        raise ScheduleUpdateError(400, "param must be a JSON object")
    values = dict(
        job_id=job_id, cron=cron,
        enabled=as_bool(body.get("enabled", existing.get("enabled", True)), True),
        time_zone=zone,
        repeated=as_bool(body["repeated"], True) if "repeated" in body else None,
        param=param, override_time_zone=bool(zone), extra_fields=body, expected_job=existing,
    )
    return existing, body, values


def _save_update(ctx, duid, values):
    try:
        return wrap_response(upsert_job(ctx, duid, **values))
    except ValueError as exc:
        return _error(409, str(exc))
    except OSError:
        return _error(500, "unable to persist schedule")


def build_update(ctx, _query_params, body_params, clean_path):
    match_ = _ITEM_RE.fullmatch(clean_path.rstrip("/"))
    duid, job_id = match_.group(1), match_.group(2)
    try:
        _, _, values = _prepare_update(ctx, duid, job_id, body_params)
    except ScheduleUpdateError as exc:
        return _error(exc.code, str(exc))
    return _save_update(ctx, duid, values)


async def build_update_synced(ctx, _query_params, body_params, clean_path, coordinator):
    """Authenticated HTTP edits share the same native state as every MQTT client."""
    match_ = _ITEM_RE.fullmatch(clean_path.rstrip("/"))
    duid, job_id = match_.group(1), match_.group(2)
    async with coordinator.lock(duid):
        try:
            existing, body, values = _prepare_update(ctx, duid, job_id, body_params)
            candidate = {**existing}
            if values["param"] is not None:
                candidate["param"] = values["param"]
            name = native_timer_name(candidate) if "enabled" in body else None

            def check_current():
                jobs = list_jobs(ctx, duid)
                if [job for job in jobs if str(job.get("id")) == job_id] != [existing]:
                    raise TimerSyncError("Schedule changed during timer verification; read it again", 409)
                for other in jobs:
                    if str(other.get("id")) != job_id and native_timer_name(other) == name:
                        raise TimerSyncError("Multiple schedules reference this native timer", 409)

            if name is not None:
                check_current()
                await sync_timer(ctx, duid, name, values["enabled"], check_current=check_current)
                check_current()
            result = _save_update(ctx, duid, values)
            if name is not None and not result.get("success"):
                result["msg"] = "Robot timer was verified, but the schedule could not be saved; refresh before retrying"
            return result
        except ScheduleUpdateError as exc:
            return _error(exc.code, str(exc))
        except SettingsError as exc:
            return _error(409, str(exc))
        except TimerSyncError as exc:
            return _error(exc.status, str(exc))


def match_delete(path: str, method: str = "GET") -> bool:
    return method.upper() == "DELETE" and bool(_ITEM_RE.fullmatch(path.rstrip("/")))


def build_delete(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    match_ = _ITEM_RE.fullmatch(clean_path.rstrip("/"))
    duid, job_id = match_.group(1), match_.group(2)  # type: ignore[union-attr]
    try:
        if not delete_job(ctx, duid, job_id):
            return _error(404, "schedule not found")
    except OSError:
        return _error(500, "unable to persist schedule")
    return wrap_response({"id": job_id})
