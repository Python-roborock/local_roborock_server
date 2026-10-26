"""Create, update and delete the per-device schedules kept in the inventory."""

from __future__ import annotations

import copy
from datetime import datetime
import json
import time
from typing import TYPE_CHECKING, Any

from .data_helpers import as_bool
from .inventory_io import inventory_mutation, load_inventory, write_inventory

if TYPE_CHECKING:
    from .context import ServerContext

DEFAULT_JOB_PARAM: dict[str, Any] = {
    "id": 1,
    "method": "server_scheduled_start",
    "params": [{"repeat": 1, "segments": "0"}],
}


JOB_SETTING_KEYS = (
    "repeat",
    "fan_power",
    "water_box_mode",
    "mop_mode",
    "mop_template_id",
    "segments",
    "clean_mop",
)
_INT_SETTING_KEYS = frozenset(JOB_SETTING_KEYS) - {"segments"}


class SettingsError(ValueError):
    """A schedule setting had a value this server cannot store."""


def _normalize_setting(key: str, value: Any) -> Any:
    if key == "segments":
        items = value.replace(";", ",").split(",") if isinstance(value, str) else list(value)
        try:
            ids = [int(str(item).strip()) for item in items if str(item).strip()]
        except ValueError as exc:
            raise SettingsError(f"segments must be room ids, got {value!r}") from exc
        ids = [room for room in ids if room > 0]
        return ",".join(str(room) for room in ids) if ids else "0"
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise SettingsError(f"{key} must be a number, got {value!r}")
    try:
        return int(value)
    except ValueError as exc:
        raise SettingsError(f"{key} must be a number, got {value!r}") from exc


def _settings_entry(job: dict[str, Any]) -> dict[str, Any]:
    param = job.get("param")
    if isinstance(param, str):
        try:
            param = json.loads(param)
        except json.JSONDecodeError:
            return {}
    params = param.get("params") if isinstance(param, dict) else None
    return params[0] if isinstance(params, list) and params and isinstance(params[0], dict) else {}


def has_native_timer(job: dict[str, Any]) -> bool:
    return "name" in _settings_entry(job)


def native_timer_name(job: dict[str, Any]) -> str | None:
    """Return an exact native reference, refusing malformed or multiple references."""
    param = job.get("param")
    if isinstance(param, str):
        try:
            param = json.loads(param)
        except (ValueError, TypeError):
            return None
    if not isinstance(param, dict) or param.get("method") != "server_scheduled_start":
        return None
    params = param.get("params")
    if isinstance(params, list):
        if len(params) != 1:
            if any(isinstance(entry, dict) and "name" in entry for entry in params):
                raise SettingsError("Schedule has multiple or ambiguous native timer references")
            return None
        params = params[0]
    if not isinstance(params, dict) or "name" not in params:
        return None
    name = params["name"]
    if not isinstance(name, str) or not name.strip():
        raise SettingsError("Schedule has an invalid native timer reference")
    return name


@inventory_mutation
def reconcile_native_enabled(
    ctx: ServerContext, duid: str, snapshot: list[dict[str, Any]], states: dict[str, bool],
    *, explicit_enable: dict[str, Any] | None = None,
) -> list[Any]:
    """Merge a fresh robot read only into unchanged, uniquely linked jobs.

    Preserve complete records and occurrence claims. A still-on robot timer
    must not resurrect a consumed one-time job after a restart or routine poll.
    """
    inventory = load_inventory(ctx)
    jobs = _jobs_for(inventory, duid, create=False) or []
    by_name: dict[str, list[dict[str, Any]]] = {}
    for job in jobs:
        if not isinstance(job, dict):
            continue
        try:
            name = native_timer_name(job)
        except SettingsError:
            continue
        if name is not None:
            by_name.setdefault(name, []).append(job)
    changed = []
    claims = inventory.get("schedule_occurrences", {}).get(duid, {})
    for name, linked in by_name.items():
        if len(linked) != 1 or name not in states:
            continue
        job = linked[0]
        before = [entry for entry in snapshot if _same_id(entry, job.get("id"))]
        if before != [job] or sum(_same_id(entry, job.get("id")) for entry in jobs) != 1:
            continue
        enabled = states[name]
        if as_bool(job.get("enabled", True), True) == enabled:
            continue
        if (enabled and not as_bool(job.get("repeated", True), True)
                and str(job.get("id")) in claims
                and (name not in (explicit_enable or {})
                     or claims[str(job.get("id"))] != explicit_enable[name])):
            continue
        job["enabled"] = enabled
        job.pop("nextFireTime", None)
        changed.append(job["id"])
    if changed:
        _persist(ctx, inventory)
    return changed


def job_settings(job: dict[str, Any]) -> dict[str, Any]:
    """The vac/mop settings a job carries, as a flat dict.

    ``name``, when the job has one, rides along too, outside ``JOB_SETTING_KEYS``: it is not a
    vac/mop setting a client edits, it is the official app's own link from this job to the
    robot's server_timer entry it saved alongside it (POST/PUT /user/devices/{duid}/jobs carries
    it in exactly this spot, confirmed live). Native timer entries themselves are
    read from the robot; this helper does not turn them into legacy timers.
    """
    entry = _settings_entry(job)
    settings = {key: entry[key] for key in JOB_SETTING_KEYS if key in entry}
    name = entry.get("name")
    if isinstance(name, str) and name:
        settings["name"] = name
    return settings


def merge_job_settings(param: dict[str, Any] | None, settings: dict[str, Any]) -> dict[str, Any]:
    """Copy of ``param`` with ``settings`` merged in; a None value clears that setting.

    Settings not mentioned are left alone, so editing one option never resets the rest.
    """
    merged = copy.deepcopy(param) if isinstance(param, dict) else copy.deepcopy(DEFAULT_JOB_PARAM)
    params = merged.get("params")
    if not isinstance(params, list) or not params or not isinstance(params[0], dict):
        params = copy.deepcopy(DEFAULT_JOB_PARAM["params"])
        merged["params"] = params
    entry = params[0]
    for key, value in settings.items():
        if key not in JOB_SETTING_KEYS:
            raise SettingsError(f"unknown schedule setting {key!r}")
        if value is None:
            entry.pop(key, None)
        else:
            entry[key] = _normalize_setting(key, value)
    return merged


def _same_id(job: Any, job_id: Any) -> bool:
    return isinstance(job, dict) and str(job.get("id")) == str(job_id)


def _jobs_for(inventory: dict[str, Any], duid: str, *, create: bool) -> list[Any] | None:
    schedules = inventory.get("schedules")
    if not isinstance(schedules, dict):
        if not create:
            return None
        schedules = {}
        inventory["schedules"] = schedules
    jobs = schedules.get(duid)
    if not isinstance(jobs, list):
        if not create:
            return None
        jobs = []
        schedules[duid] = jobs
    return jobs


def _coerce_id(job_id: Any) -> Any:
    text = str(job_id).strip()
    return int(text) if text.isdigit() else text


def list_jobs(ctx: ServerContext, duid: str) -> list[dict[str, Any]]:
    jobs = _jobs_for(load_inventory(ctx), duid, create=False) or []
    return [copy.deepcopy(job) for job in jobs if isinstance(job, dict)]


def _persist(ctx: ServerContext, inventory: dict[str, Any]) -> None:
    if not write_inventory(ctx, inventory):
        raise OSError("Unable to persist schedule inventory")


@inventory_mutation
def upsert_job(
    ctx: ServerContext,
    duid: str,
    *,
    job_id: Any,
    cron: str,
    enabled: bool,
    time_zone: str = "",
    repeated: bool | None = None,
    param: dict[str, Any] | None = None,
    override_time_zone: bool = False,
    extra_fields: dict[str, Any] | None = None,
    create_only: bool = False,
    expected_job: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create the job, or update cron/enabled on an existing one while keeping its settings.

    An existing job keeps its own timezone unless ``override_time_zone`` is set.
    """
    inventory = load_inventory(ctx)
    jobs = _jobs_for(inventory, duid, create=True)
    assert jobs is not None
    if job_id is None:
        job_id = time.time_ns() // 1_000_000
        while any(_same_id(job, job_id) for job in jobs):
            job_id += 1
    existing = next((job for job in jobs if _same_id(job, job_id)), None)
    if create_only and existing is not None:
        raise ValueError("schedule id already exists")
    if expected_job is not None and existing != expected_job:
        raise ValueError("schedule changed or was deleted; read it again before updating")
    if existing is None:
        existing = {
            "id": _coerce_id(job_id),
            "repeated": True if repeated is None else repeated,
            "type": "clean",
            "param": copy.deepcopy(param) if param is not None else copy.deepcopy(DEFAULT_JOB_PARAM),
        }
        if time_zone:
            existing["timeZoneId"] = time_zone
        jobs.append(existing)
    else:
        if repeated is not None:
            existing["repeated"] = repeated
        if param is not None:
            existing["param"] = copy.deepcopy(param)
        if override_time_zone and time_zone:
            existing["timeZoneId"] = time_zone
    existing["cron"] = cron
    existing["enabled"] = enabled
    # Preserve model-specific job fields without allowing a body to replace the
    # path ID, validated fields, or the server's calculated next-fire value.
    reserved = {"id", "nextFireTime", "cron", "enabled", "timeZoneId", "repeated", "param"}
    existing.update(copy.deepcopy({key: value for key, value in (extra_fields or {}).items() if key not in reserved}))
    existing.pop("nextFireTime", None)
    _persist(ctx, inventory)
    return copy.deepcopy(existing)


@inventory_mutation
def set_enabled(ctx: ServerContext, duid: str, job_id: Any, enabled: bool) -> bool:
    inventory = load_inventory(ctx)
    jobs = _jobs_for(inventory, duid, create=False) or []
    found = False
    for job in jobs:
        if _same_id(job, job_id):
            job["enabled"] = enabled
            found = True
    if found:
        _persist(ctx, inventory)
    return found


@inventory_mutation
def delete_job(ctx: ServerContext, duid: str, job_id: Any) -> bool:
    inventory = load_inventory(ctx)
    jobs = _jobs_for(inventory, duid, create=False)
    if not jobs:
        return False
    remaining = [job for job in jobs if not _same_id(job, job_id)]
    if len(remaining) == len(jobs):
        return False
    jobs[:] = remaining
    occurrences = inventory.get("schedule_occurrences", {}).get(duid, {})
    occurrences.pop(str(job_id), None)
    _persist(ctx, inventory)
    return True


@inventory_mutation
def claim_occurrence(ctx: ServerContext, duid: str, job: dict[str, Any], due: datetime) -> bool:
    """Persist an at-most-once decision before any robot command is sent.

    A crash after this write can skip a clean; replaying a clean after restart is
    deliberately avoided. Compare the snapshot under the same lock as CRUD so a
    disabled, edited, or deleted job cannot be claimed from a stale tick.
    """
    inventory = load_inventory(ctx)
    jobs = _jobs_for(inventory, duid, create=False) or []
    current = next((item for item in jobs if _same_id(item, job.get("id"))), None)
    if current != job or not as_bool(job.get("enabled", True), True):
        return False
    occurrences = inventory.setdefault("schedule_occurrences", {}).setdefault(duid, {})
    key = str(job["id"])
    instant = int(due.timestamp())
    if occurrences.get(key, -1) >= instant:
        return False
    occurrences[key] = instant
    if not as_bool(job.get("repeated", True), True):
        current["enabled"] = False
    _persist(ctx, inventory)
    return True


def claimed_job_is_current(ctx: ServerContext, duid: str, job: dict[str, Any]) -> bool:
    """Recheck after network awaits; a time edit must cancel stale queued work."""
    expected = copy.deepcopy(job)
    if not as_bool(job.get("repeated", True), True):
        expected["enabled"] = False  # Consumed atomically by claim_occurrence.
    return any(item == expected for item in list_jobs(ctx, duid))
