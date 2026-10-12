"""Local executor for cloud-style schedules (``server_scheduled_start`` jobs).

Roborock's cloud fires these at ``nextFireTime``. With the vacuum pointed at this
server, nothing else would, so the server evaluates the stored cron entries
itself and hands each due job to the routine runner.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone, tzinfo
import json
import logging
from typing import TYPE_CHECKING, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .constants import DEFAULT_TIMEZONE
from .data_helpers import as_bool
from .inventory_io import load_inventory
from .routine_runner import RoutineExecutionError, RoutineStep, get_routine_runner
from .schedule_store import set_enabled

if TYPE_CHECKING:
    from .context import ServerContext

_LOGGER = logging.getLogger(__name__)

TICK_SECONDS = 20
_SUPPORTED_JOB_METHOD = "server_scheduled_start"
_CARRIED_ENTRY_KEYS = ("repeat", "fan_power", "water_box_mode", "mop_mode", "mop_template_id")


class CronError(ValueError):
    """Raised for a cron expression this scheduler cannot evaluate."""


@dataclass(frozen=True)
class CronSpec:
    minutes: tuple[int, ...]
    hours: tuple[int, ...]
    days_of_month: frozenset[int]
    months: frozenset[int]
    days_of_week: frozenset[int]
    dom_restricted: bool
    dow_restricted: bool

    def day_matches(self, day: date) -> bool:
        if day.month not in self.months:
            return False
        dom_ok = day.day in self.days_of_month
        # cron weekday 0 = Sunday; python's isoweekday() has Sunday as 7.
        dow_ok = (day.isoweekday() % 7) in self.days_of_week
        if self.dom_restricted and self.dow_restricted:
            return dom_ok or dow_ok
        return dom_ok and dow_ok


def _parse_field(text: str, low: int, high: int, *, name: str) -> tuple[frozenset[int], bool]:
    text = text.strip()
    if text in ("*", "?"):
        return frozenset(range(low, high + 1)), False
    values: set[int] = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            raise CronError(f"empty {name} entry in {text!r}")
        step = 1
        if "/" in part:
            part, _, step_text = part.partition("/")
            try:
                step = int(step_text)
            except ValueError as exc:
                raise CronError(f"bad {name} step {step_text!r}") from exc
            if step <= 0:
                raise CronError(f"{name} step must be positive")
        if part in ("*", "?", ""):
            start, end = low, high
        elif "-" in part:
            first, _, last = part.partition("-")
            try:
                start, end = int(first), int(last)
            except ValueError as exc:
                raise CronError(f"bad {name} range {part!r}") from exc
        else:
            try:
                start = int(part)
            except ValueError as exc:
                raise CronError(f"bad {name} value {part!r}") from exc
            end = high if step != 1 else start
        if start < low or end > high or start > end:
            raise CronError(f"{name} value out of range in {text!r}")
        values.update(range(start, end + 1, step))
    return frozenset(values), True


def parse_cron(expression: str) -> CronSpec:
    fields = str(expression or "").split()
    if len(fields) != 5:
        raise CronError(f"expected 5 cron fields, got {len(fields)}: {expression!r}")
    minutes, _ = _parse_field(fields[0], 0, 59, name="minute")
    hours, _ = _parse_field(fields[1], 0, 23, name="hour")
    dom, dom_restricted = _parse_field(fields[2], 1, 31, name="day-of-month")
    months, _ = _parse_field(fields[3], 1, 12, name="month")
    raw_dow, dow_restricted = _parse_field(fields[4], 0, 7, name="day-of-week")
    dow = frozenset(0 if value == 7 else value for value in raw_dow)
    return CronSpec(
        minutes=tuple(sorted(minutes)),
        hours=tuple(sorted(hours)),
        days_of_month=dom,
        months=months,
        days_of_week=dow,
        dom_restricted=dom_restricted,
        dow_restricted=dow_restricted,
    )


def next_fire(spec: CronSpec, after: datetime) -> datetime | None:
    """First fire instant strictly after ``after`` (an aware datetime), in its timezone."""
    zone = after.tzinfo
    if zone is None:
        raise ValueError("after must be timezone-aware")
    start = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
    start_utc = start.astimezone(timezone.utc)
    first_day = start.date()
    for offset in range(0, 800):
        day = first_day + timedelta(days=offset)
        if not spec.day_matches(day):
            continue
        for hour in spec.hours:
            for minute in spec.minutes:
                candidate = datetime(day.year, day.month, day.day, hour, minute, tzinfo=zone)
                if candidate.astimezone(timezone.utc) >= start_utc:
                    return candidate
    return None


def _zone(name: str, fallback: str) -> tzinfo:
    # DEFAULT_TIMEZONE is what /location tells the robot when none is configured.
    for candidate in (name, fallback, DEFAULT_TIMEZONE):
        candidate = str(candidate or "").strip()
        if not candidate:
            continue
        try:
            return ZoneInfo(candidate)
        except (ZoneInfoNotFoundError, ValueError):
            continue
    return timezone.utc


def _segment_ids(value: Any) -> list[int]:
    if isinstance(value, str):
        items: list[Any] = [part for part in value.replace(";", ",").split(",") if part.strip()]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    elif value is None:
        items = []
    else:
        items = [value]
    segments: list[int] = []
    for item in items:
        try:
            number = int(str(item).strip())
        except ValueError:
            continue
        if number > 0:
            segments.append(number)
    return segments


def job_param(job: dict[str, Any]) -> dict[str, Any]:
    param = job.get("param")
    if isinstance(param, str):
        try:
            param = json.loads(param)
        except json.JSONDecodeError as exc:
            raise RoutineExecutionError("schedule param is not valid JSON") from exc
    if not isinstance(param, dict):
        raise RoutineExecutionError("schedule is missing its param payload")
    return param


def steps_for_job(job: dict[str, Any]) -> list[RoutineStep]:
    param = job_param(job)
    method = str(param.get("method") or "").strip()
    if method != _SUPPORTED_JOB_METHOD:
        raise RoutineExecutionError(f"unsupported schedule method {method!r}")
    params = param.get("params")
    entry = params[0] if isinstance(params, list) and params else params
    if not isinstance(entry, dict):
        raise RoutineExecutionError("schedule params must contain one settings object")

    settings = {key: entry[key] for key in _CARRIED_ENTRY_KEYS if key in entry}
    name = str(entry.get("name") or job.get("name") or "").strip()
    if not name or name.isdigit():
        name = f"Schedule {job.get('id', '')}".strip()
    segments = _segment_ids(entry.get("segments"))
    if segments:
        return [
            RoutineStep(
                step_id=1,
                name=name,
                method="do_scenes_segments",
                params={"data": [{**settings, "segs": segments}]},
                finish_dp_ids=(),
            )
        ]
    return [
        RoutineStep(
            step_id=1,
            name=name,
            method="do_scenes_app_start",
            params=[settings],
            finish_dp_ids=(),
        )
    ]


def next_fire_time_utc(job: dict[str, Any], *, default_timezone: str = "", now: datetime | None = None) -> datetime | None:
    if not as_bool(job.get("enabled", True), True):
        return None
    try:
        spec = parse_cron(str(job.get("cron") or ""))
    except CronError:
        return None
    zone = _zone(str(job.get("timeZoneId") or ""), default_timezone)
    current = (now or datetime.now(timezone.utc)).astimezone(zone)
    upcoming = next_fire(spec, current)
    return upcoming.astimezone(timezone.utc) if upcoming is not None else None


class ScheduleRunner:
    def __init__(self, context: ServerContext, *, default_timezone: str = "") -> None:
        self._context = context
        self._default_timezone = default_timezone
        self._last_tick: datetime | None = None
        self._logger = context.loggers.get("api") or context.loggers.get("unknown") or _LOGGER

    def due_jobs(self, since: datetime, until: datetime) -> list[tuple[str, dict[str, Any]]]:
        inventory = load_inventory(self._context)
        schedules = inventory.get("schedules")
        if not isinstance(schedules, dict):
            return []
        due: list[tuple[str, dict[str, Any]]] = []
        for device_id, jobs in schedules.items():
            if not isinstance(jobs, list):
                continue
            for job in jobs:
                if not isinstance(job, dict) or not as_bool(job.get("enabled", True), True):
                    continue
                try:
                    spec = parse_cron(str(job.get("cron") or ""))
                except CronError as exc:
                    self._logger.warning("Skipping schedule %s on %s: %s", job.get("id"), device_id, exc)
                    continue
                zone = _zone(str(job.get("timeZoneId") or ""), self._default_timezone)
                upcoming = next_fire(spec, since.astimezone(zone))
                if upcoming is not None and upcoming.astimezone(timezone.utc) <= until:
                    due.append((str(device_id), job))
        return due

    def tick(self, now: datetime | None = None) -> list[dict[str, Any]]:
        """Fire anything that came due since the previous tick. Needs a running event loop."""
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        previous = self._last_tick
        self._last_tick = current
        if previous is None:
            return []
        results: list[dict[str, Any]] = []
        runner = get_routine_runner(self._context)
        for device_id, job in self.due_jobs(previous, current):
            job_id = job.get("id")
            try:
                steps = steps_for_job(job)
                result = runner.start_job(
                    device_id=device_id,
                    job_id=int(job_id) if str(job_id).isdigit() else 0,
                    name=steps[0].name,
                    steps=steps,
                )
            except (RoutineExecutionError, ValueError) as exc:
                self._logger.warning("Schedule %s on %s not started: %s", job_id, device_id, exc)
                result = {"accepted": False, "status": "error", "error": str(exc), "deviceId": device_id}
            else:
                self._logger.info("Schedule %s on %s fired: %s", job_id, device_id, result.get("status"))
                if result.get("accepted") and not as_bool(job.get("repeated", True), True):
                    set_enabled(self._context, device_id, job_id, False)
            results.append({"jobId": job_id, **result})
        return results

    async def run(self, stop_event: asyncio.Event, *, tick_seconds: float = TICK_SECONDS) -> None:
        self.tick()
        while not stop_event.is_set():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=tick_seconds)
            except TimeoutError:
                pass
            if stop_event.is_set():
                return
            try:
                self.tick()
            except Exception as exc:  # noqa: BLE001
                self._logger.warning("Schedule tick failed: %s", exc)
