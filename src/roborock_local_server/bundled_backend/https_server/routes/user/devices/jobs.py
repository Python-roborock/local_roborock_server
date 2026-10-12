from __future__ import annotations

import json
import re
import time
from typing import Any

from shared.constants import DEFAULT_TIMEZONE
from shared.context import ServerContext
from shared.data_helpers import as_bool
from shared.http_helpers import wrap_response
from shared.schedule_runner import CronError, parse_cron
from shared.schedule_store import delete_job, list_jobs, upsert_job

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
    return {}


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
    body = _json_body(body_params)
    cron = str(body.get("cron") or "").strip()
    try:
        parse_cron(cron)
    except CronError as exc:
        return _error(400, f"invalid cron: {exc}")
    param = _parse_param(body.get("param"))
    if body.get("param") is not None and param is None:
        return _error(400, "param must be a JSON object")
    job_id = body.get("id") or int(time.time())
    created = upsert_job(
        ctx,
        duid,
        job_id=job_id,
        cron=cron,
        enabled=as_bool(body.get("enabled", True), True),
        time_zone=str(body.get("timeZoneId") or getattr(ctx, "timezone", "") or DEFAULT_TIMEZONE),
        repeated=as_bool(body.get("repeated", True), True),
        param=param,
    )
    return wrap_response(created)


def match_update(path: str, method: str = "GET") -> bool:
    return method.upper() in ("PUT", "PATCH") and bool(_ITEM_RE.fullmatch(path.rstrip("/")))


def build_update(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    match_ = _ITEM_RE.fullmatch(clean_path.rstrip("/"))
    duid, job_id = match_.group(1), match_.group(2)  # type: ignore[union-attr]
    existing = next((job for job in list_jobs(ctx, duid) if str(job.get("id")) == job_id), None)
    if existing is None:
        return _error(404, "schedule not found")
    body = _json_body(body_params)
    cron = str(body.get("cron") or existing.get("cron") or "").strip()
    try:
        parse_cron(cron)
    except CronError as exc:
        return _error(400, f"invalid cron: {exc}")
    param = _parse_param(body.get("param")) if "param" in body else None
    if "param" in body and param is None:
        return _error(400, "param must be a JSON object")
    updated = upsert_job(
        ctx,
        duid,
        job_id=job_id,
        cron=cron,
        enabled=as_bool(body.get("enabled", existing.get("enabled", True)), True),
        time_zone=str(body.get("timeZoneId") or ""),
        repeated=as_bool(body["repeated"], True) if "repeated" in body else None,
        param=param,
        override_time_zone=bool(body.get("timeZoneId")),
    )
    return wrap_response(updated)


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
    if not delete_job(ctx, duid, job_id):
        return _error(404, "schedule not found")
    return wrap_response({"id": job_id})
