"""Background scan that finds released firmware versions by asking the cloud, walking down from the current one."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from . import firmware_versions
from .firmware_catalog import SOURCE_PROBE, FirmwareCatalog
from .ota_dry_run import package_address, package_headers, package_md5

logger = logging.getLogger("real_stack.api")

DEFAULT_MAX_EMPTY = 8
PACE_SECONDS = 0.2


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class FirmwareScan:
    def __init__(self, sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep) -> None:
        self._sleep = sleep
        self._task: asyncio.Task[None] | None = None
        self._cancel = False
        self._state: dict[str, Any] = {"running": False}

    @property
    def running(self) -> bool:
        return bool(self._state.get("running"))

    def state(self) -> dict[str, Any]:
        return {**self._state, "found": list(self._state.get("found", []))}

    def cancel(self) -> bool:
        if not self.running:
            return False
        self._cancel = True
        return True

    def start(
        self, cloud: Any, catalog: FirmwareCatalog, duid: str, model: str, current: str, max_empty: int = DEFAULT_MAX_EMPTY,
    ) -> dict[str, Any]:
        """Starts the scan as a task and returns the initial state; the caller checks that none is running."""
        self._cancel = False
        self._state = {
            "running": True, "duid": duid, "model": model, "startVersion": current, "maxEmptyMinors": max_empty,
            "startedAt": _now(), "finishedAt": None, "checking": "", "minorsDone": 0, "emptyMinors": 0,
            "found": [], "error": "", "stoppedAt": "", "stoppedReason": "",
        }
        self._task = asyncio.create_task(self._run(cloud, catalog, duid, model, current, max_empty))
        return self.state()

    async def wait(self) -> None:
        if self._task is not None:
            await self._task

    async def _run(self, cloud: Any, catalog: FirmwareCatalog, duid: str, model: str, current: str, max_empty: int) -> None:
        state = self._state
        try:
            state["stoppedReason"] = await self._walk(cloud, catalog, duid, model, current, max_empty)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Firmware scan for %s stopped: %s", model, exc)
            state["error"], state["stoppedReason"] = str(exc), "error"
        state["running"], state["finishedAt"] = False, _now()

    async def _walk(self, cloud: Any, catalog: FirmwareCatalog, duid: str, model: str, current: str, max_empty: int) -> str:
        state = self._state
        major, minor, top = firmware_versions.parse(current) or (0, 0, 0)  # the first line only has builds below top
        while True:
            hits = 0
            for b in range(top - 1, -1, -1):
                version = f"{major:02d}.{minor:02d}.{b:02d}"
                if (major, minor, b) == (0, 0, 0):
                    break
                if self._cancel:
                    return "cancelled"
                state["checking"] = version
                known = catalog.entry(model, version) or {}
                if known.get("md5"):
                    hits += 1
                    continue
                await self._sleep(PACE_SECONDS)
                try:
                    url = await package_address(cloud, duid, version)
                except Exception:
                    state["stoppedAt"] = version
                    raise
                if not url:
                    continue
                released, size = ("", None) if known.get("released") and known.get("size") else await package_headers(url)
                catalog.add(model, version, source=SOURCE_PROBE, url=url, md5=package_md5(url), size=size, released=released)
                state["found"].append(version)
                hits += 1
            state["minorsDone"] += 1
            state["emptyMinors"] = 0 if hits else state["emptyMinors"] + 1
            if state["emptyMinors"] >= max_empty:
                return "empty_minors"
            if minor > 0:
                minor -= 1
            elif major > 0:
                major, minor = major - 1, 99
            else:
                return "floor"
            top = 100  # lower lines are scanned from build 99
