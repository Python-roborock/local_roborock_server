"""Opt-in local weekly routine schedules, separate from imported cloud jobs."""

from __future__ import annotations

import asyncio
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import re
import sqlite3
from typing import Any, Callable
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

_LOGGER = logging.getLogger(__name__)


def validate_schedule(value: Any) -> dict[str, Any]:
    """Accept a complete, explicit weekly schedule definition."""
    fields = {"scene_id", "time", "timezone", "weekdays", "enabled"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Required fields: scene_id, time, timezone, weekdays, enabled")
    if type(value["scene_id"]) is not int or value["scene_id"] <= 0:
        raise ValueError("scene_id must be a positive integer")
    if not isinstance(value["time"], str) or not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value["time"]):
        raise ValueError("time must be HH:MM in 24-hour time")
    if not isinstance(value["timezone"], str):
        raise ValueError("timezone must be an IANA time zone")
    try:
        ZoneInfo(value["timezone"])
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("timezone must be an IANA time zone") from exc
    days = value["weekdays"]
    if (
        not isinstance(days, list) or not days or len(days) > 7
        or any(type(day) is not int or not 0 <= day <= 6 for day in days)
        or len(set(days)) != len(days)
    ):
        raise ValueError("weekdays must contain unique integers from 0 (Monday) to 6 (Sunday)")
    if type(value["enabled"]) is not bool:
        raise ValueError("enabled must be a boolean")
    return {**value, "weekdays": sorted(days)}


def _scene_fingerprint(scene: dict[str, Any]) -> str:
    # Refuse to silently run a changed/replaced routine. Names can be edited freely.
    payload = {"device_id": scene.get("device_id"), "param": json.loads(scene["param"])}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


class RoutineScheduler:
    """Minute-resolution, at-most-once dispatch; no catch-up or automatic retries."""

    def __init__(
        self,
        path: Path,
        *,
        load_scene: Callable[[int], dict[str, Any]],
        dispatch: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> None:
        self.path = path
        self._load_scene = load_scene
        self._dispatch = dispatch
        self._task: asyncio.Task[None] | None = None
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS routine_schedules ("
                "id TEXT PRIMARY KEY, definition TEXT NOT NULL, fingerprint TEXT NOT NULL, "
                "last_date TEXT NOT NULL DEFAULT '', last_result TEXT NOT NULL DEFAULT '')"
            )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def list(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as db:
            return [
                {"id": row["id"], **json.loads(row["definition"]),
                 "last_date": row["last_date"] or None, "last_result": row["last_result"] or None}
                for row in db.execute("SELECT * FROM routine_schedules ORDER BY id")
            ]

    def save(self, value: Any, *, schedule_id: str | None = None) -> str:
        definition = validate_schedule(value)
        scene = self._load_scene(definition["scene_id"])
        fingerprint = _scene_fingerprint(scene)
        encoded = json.dumps(definition, sort_keys=True)
        with closing(self._connect()) as db, db:
            if schedule_id is None:
                schedule_id = uuid4().hex
                db.execute(
                    "INSERT INTO routine_schedules (id, definition, fingerprint) VALUES (?, ?, ?)",
                    (schedule_id, encoded, fingerprint),
                )
            else:
                # Keep the claim even across edits/disable-enable cycles on the same date.
                updated = db.execute(
                    "UPDATE routine_schedules SET definition = ?, fingerprint = ? WHERE id = ?",
                    (encoded, fingerprint, schedule_id),
                )
                if not updated.rowcount:
                    raise KeyError(schedule_id)
        return schedule_id

    def delete(self, schedule_id: str) -> bool:
        with closing(self._connect()) as db, db:
            return bool(db.execute("DELETE FROM routine_schedules WHERE id = ?", (schedule_id,)).rowcount)

    def tick(self, now: datetime) -> None:
        """Dispatch only occurrences matching this instant's local calendar minute."""
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM routine_schedules").fetchall()
        for row in rows:
            try:
                definition = validate_schedule(json.loads(row["definition"]))
                local = now.astimezone(ZoneInfo(definition["timezone"]))
                date = local.date().isoformat()
                if (
                    not definition["enabled"]
                    or local.weekday() not in definition["weekdays"]
                    or local.strftime("%H:%M") != definition["time"]
                    or date <= row["last_date"]
                ):
                    continue
                # Commit before dispatch. A crash after this point may lose a run,
                # but a restart, DST fold, or clock rollback must never replay it.
                with closing(self._connect()) as db, db:
                    claimed = db.execute(
                        "UPDATE routine_schedules SET last_date = ?, last_result = 'claimed' "
                        "WHERE id = ? AND last_date < ? AND definition = ? AND fingerprint = ?",
                        (date, row["id"], date, row["definition"], row["fingerprint"]),
                    ).rowcount
                if not claimed:
                    continue
                try:
                    scene = self._load_scene(definition["scene_id"])
                    if _scene_fingerprint(scene) != row["fingerprint"]:
                        result = "scene_changed"
                    elif scene.get("enabled", True) is False:
                        result = "scene_disabled"
                    else:
                        result = str(self._dispatch(scene).get("status", "dispatched"))
                except Exception as exc:  # noqa: BLE001
                    result = "dispatch_failed"
                    _LOGGER.warning("Scheduled routine %s failed: %s", row["id"], exc)
                with closing(self._connect()) as db, db:
                    db.execute(
                        "UPDATE routine_schedules SET last_result = ? WHERE id = ? AND last_date = ?",
                        (result, row["id"], date),
                    )
                _LOGGER.info("Scheduled routine %s: %s", row["id"], result)
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Unable to process routine schedule %s", row["id"])

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="routine-scheduler")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _run(self) -> None:
        while True:
            try:
                self.tick(datetime.now(timezone.utc))
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Routine scheduler tick failed")
            await asyncio.sleep(10)


def register_routine_schedule_routes(app: FastAPI, supervisor: Any) -> None:
    """Use the same admin session requirement as the existing dashboard routes."""
    scheduler = supervisor.routine_scheduler

    @app.get("/admin/api/routines")
    async def list_routines(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        from https_server.routes.user.scene.service import list_scenes_for_home

        scenes = list_scenes_for_home(supervisor.context, 0)
        return JSONResponse({"routines": scenes})

    @app.get("/admin/api/routine-schedules")
    async def list_schedules(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        return JSONResponse({"schedules": scheduler.list()})

    async def save_schedule(request: Request, schedule_id: str | None = None) -> JSONResponse:
        supervisor._require_admin(request)
        try:
            value = await request.json()
            saved_id = scheduler.save(value, schedule_id=schedule_id)
        except KeyError:
            return JSONResponse({"error": "Schedule not found"}, status_code=404)
        except (ValueError, RuntimeError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        return JSONResponse({"id": saved_id}, status_code=201 if schedule_id is None else 200)

    @app.post("/admin/api/routine-schedules")
    async def create_schedule(request: Request) -> JSONResponse:
        return await save_schedule(request)

    @app.put("/admin/api/routine-schedules/{schedule_id}")
    async def update_schedule(schedule_id: str, request: Request) -> JSONResponse:
        return await save_schedule(request, schedule_id)

    @app.delete("/admin/api/routine-schedules/{schedule_id}")
    async def delete_schedule(schedule_id: str, request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        if not scheduler.delete(schedule_id):
            return JSONResponse({"error": "Schedule not found"}, status_code=404)
        return JSONResponse({"ok": True})
