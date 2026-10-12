"""Create, update and delete the per-device schedules kept in the inventory."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Any

from .inventory_io import inventory_mutation, load_inventory, write_inventory

if TYPE_CHECKING:
    from .context import ServerContext

DEFAULT_JOB_PARAM: dict[str, Any] = {
    "id": 1,
    "method": "server_scheduled_start",
    "params": [{"repeat": 1, "segments": "0"}],
}


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
) -> dict[str, Any]:
    """Create the job, or update cron/enabled on an existing one while keeping its settings.

    An existing job keeps its own timezone unless ``override_time_zone`` is set.
    """
    inventory = load_inventory(ctx)
    jobs = _jobs_for(inventory, duid, create=True)
    assert jobs is not None
    existing = next((job for job in jobs if _same_id(job, job_id)), None)
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
    write_inventory(ctx, inventory)
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
        write_inventory(ctx, inventory)
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
    write_inventory(ctx, inventory)
    return True
