"""Persist the app's scene validity reports without modifying scene actions."""

from __future__ import annotations

import json
import logging
from typing import Any

from shared.context import ServerContext
from shared.data_helpers import as_int
from shared.inventory_io import WEB_API_INVENTORY_FILE, inventory_transaction, load_inventory, write_inventory
from shared.routine_runner import RoutineExecutionError

_LOGGER = logging.getLogger(__name__)


def match(path: str, method: str = "GET") -> bool:
    return method.upper() == "PUT" and path.rstrip("/") == "/user/scene/validity"


def _extra(value: Any) -> dict[str, Any]:
    if value is None or (isinstance(value, str) and not value.strip()):
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError as exc:
            raise RoutineExecutionError("Scene validity extra must contain a JSON object") from exc
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RoutineExecutionError("Scene validity extra must contain a JSON object")
    return value


def _reports(body_params: dict[str, list[str]]) -> dict[int, list[int]]:
    candidates = body_params.get("__json") or []
    if not candidates:
        raise RoutineExecutionError("Scene validity requires a JSON array")
    try:
        reports = json.loads(candidates[0])
    except (TypeError, ValueError) as exc:
        raise RoutineExecutionError("Scene validity requires a JSON array") from exc
    if not isinstance(reports, list):
        raise RoutineExecutionError("Scene validity requires a JSON array")
    updates: dict[int, list[int]] = {}
    for index, report in enumerate(reports):
        if not isinstance(report, dict):
            _LOGGER.warning("Skipping scene validity entry %d: expected object", index)
            continue
        scene_id = report.get("sceneId")
        normalized_id = as_int(scene_id, 0) if type(scene_id) in (int, str) else 0
        if normalized_id <= 0:
            _LOGGER.warning("Skipping scene validity entry %d: unsupported sceneId", index)
            continue
        try:
            extra = _extra(report.get("extra"))
        except RoutineExecutionError:
            _LOGGER.warning("Skipping scene validity entry %d: unsupported extra", index)
            continue
        if "invalidActions" not in extra:
            _LOGGER.debug("Skipping scene validity entry %d: no invalidActions report", index)
            continue
        invalid = extra["invalidActions"]
        if not isinstance(invalid, list) or any(type(value) is not int for value in invalid):
            _LOGGER.warning("Skipping scene validity entry %d: unsupported invalidActions", index)
            continue
        updates[normalized_id] = invalid
    return updates


def _persist(ctx: ServerContext, updates: dict[int, list[int]]) -> None:
    with inventory_transaction(ctx.http_jsonl.parent / WEB_API_INVENTORY_FILE):
        inventory = load_inventory(ctx)
        changed = False
        for key in ("scenes", "home_scenes"):
            scenes = inventory.get(key)
            if not isinstance(scenes, list):
                continue
            for index, scene in enumerate(scenes):
                if not isinstance(scene, dict):
                    continue
                scene_id = as_int(scene.get("id"), 0)
                if scene_id not in updates:
                    continue
                try:
                    extra = dict(_extra(scene.get("extra")))
                except RoutineExecutionError:
                    _LOGGER.warning("Skipping scene validity stored %s record %d: unsupported extra", key, index)
                    continue
                if extra.get("invalidActions") == updates[scene_id]:
                    continue
                extra["invalidActions"] = updates[scene_id]
                scene["extra"] = extra if isinstance(scene.get("extra"), dict) else json.dumps(
                    extra, ensure_ascii=False, separators=(",", ":")
                )
                changed = True
        if changed and not write_inventory(ctx, inventory):
            _LOGGER.warning("Scene validity inventory write failed")


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    try:
        _persist(ctx, _reports(body_params))
    except RoutineExecutionError as exc:
        _LOGGER.warning("Scene validity rejected: %s", exc)
        return {"success": False, "code": 400, "msg": str(exc), "data": None, "result": None}
    # Observed from the cloud API after an authenticated app-report replay.
    return {"api": None, "result": None, "status": "ok", "success": True}
