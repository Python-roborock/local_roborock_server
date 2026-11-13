"""Installs firmware when the official app's Update button is pressed.

The cloud says which version is on offer; the package is fetched, checked against the checksum in its
address and served to the robot from this server, which then downloads, installs and reboots.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .bundled_backend.shared.routine_runner import _RoutineMqttClient
from .ota_dry_run import PackageRefused, clean_package_cache, resolve_package

# A child logger: only real_stack.<name> loggers have an output handler, plain real_stack drops INFO.
logger = logging.getLogger("real_stack.api")


class OtaInstaller:
    def __init__(self, supervisor: Any) -> None:
        self._supervisor = supervisor
        self._running: dict[str, asyncio.Task[None]] = {}
        self.results: dict[str, dict[str, Any]] = {}
        # What the official app reads while an install runs: the cloud knows nothing of a local install, so
        # the app's status polls are answered from here. The app treats IDLE as success and an error as failure.
        self._live: dict[str, dict[str, Any]] = {}

    @property
    def cache_dir(self) -> Path:
        return self._supervisor.paths.runtime_dir / "ota_packages"

    async def start(self, duid: str) -> dict[str, Any]:
        """Begins an install in the background, or says why not. One install runs at a time."""
        supervisor = self._supervisor
        if any(not task.done() for task in self._running.values()):
            return {"started": False, "reason": "Another firmware install is already running"}
        vacuum = next((v for v in supervisor._vacuums_payload()["vacuums"] if str(v.get("duid") or "") == duid), None)
        if vacuum is None:
            return {"started": False, "reason": f"Unknown device {duid!r}"}
        try:
            info = await supervisor.cloud_manager.firmware_update_info(duid)
        except Exception as exc:  # noqa: BLE001
            return {"started": False, "reason": f"Could not ask the cloud about updates: {exc}"}
        version = info.get("version") if isinstance(info, dict) else None
        if not isinstance(info, dict) or info.get("updatable") is not True or not version:
            return {"started": False, "reason": "The cloud offers no update for this robot"}
        try:
            package = await resolve_package(supervisor.cloud_manager, duid, str(version), serve=True, allow_update=True, cache_dir=self.cache_dir,
            )
        except PackageRefused as exc:
            return {"started": False, "reason": str(exc)}
        except Exception as exc:  # noqa: BLE001
            return {"started": False, "reason": f"Could not fetch the package: {exc}"}
        device = {"duid": duid, "localkey": str(vacuum.get("local_key") or "")}
        self.results.pop(duid, None)
        self._set_live(duid, "START")
        self._running[duid] = asyncio.create_task(self._install(device, package, str(version)))
        return {"started": True, "version": str(version)}

    _APP_STATES = {"downloading": "DOWNLOADING", "installing": "INSTALLING", "wait_install": "WAIT_INSTALL"}
    LIVE_SECONDS = 1800

    def _set_live(self, duid: str, status: str, progress: str = "", err_msg: str = "", err_code: int = 0) -> None:
        self._live[duid] = {
            "status": status, "progress": progress, "errCode": err_code, "errMsg": err_msg, "at": time.monotonic(),
        }

    def _robot_state(self, duid: str, state: Any, progress: Any) -> None:
        """Mirrors the robot's own OTA state. A robot that is idle or silent keeps its last status; IDLE and FAILED
        are only set at the end, since the app reads IDLE as the update being done."""
        status = self._APP_STATES.get(str(state))
        if status is None:
            return
        text = "" if progress is None else str(progress)
        previous = self._live.get(duid)
        if status == "INSTALLING":
            # The robot reports no progress of its own while installing (its query answers 0 even though its
            # messages said 100 at the end of the download), so keep the download's last number.
            text = "100"
        elif previous is not None and previous["status"] == status and previous["progress"] not in ("", "0"):
            # The robot sometimes does not answer the progress query, or answers 0; keep the last real number
            # so the app's percentage does not fall back to 0 and climb again.
            if text in ("", "0"):
                text = previous["progress"]
        self._set_live(duid, status, text)

    def _write_record(self, duid: str, record: dict[str, Any]) -> None:
        """Keeps the whole install (state timeline, what the robot downloaded, the version it reports afterwards)
        in the data volume, since it is otherwise lost when the container restarts."""
        try:
            folder = self._supervisor.paths.runtime_dir / "ota_results"
            folder.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            (folder / f"{stamp}_{duid}.json").write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not write the firmware install record: %s", exc)

    def live_status(self, duid: str) -> dict[str, Any] | None:
        """The status for the app's poll, or None when no local install ran in the last half hour."""
        entry = self._live.get(duid)
        if entry is None or time.monotonic() - entry["at"] > self.LIVE_SECONDS:
            return None
        return {key: value for key, value in entry.items() if key != "at"}

    async def _install(self, device: dict[str, str], package: dict[str, Any], version: str) -> None:
        supervisor = self._supervisor
        duid = device["duid"]
        client = _RoutineMqttClient(supervisor.context, device, logger)
        try:
            await client.connect()
            result = await supervisor.ota_dry_run.run(
                client, supervisor.context.api_url(), package, None, True,
                on_state=lambda state, progress: self._robot_state(duid, state, progress),
            )
        except Exception as exc:  # noqa: BLE001
            result = {"ran": False, "reason": str(exc)}
        finally:
            await client.close()
        snapshot = supervisor.context.snapshot_store.get(duid) if supervisor.context.snapshot_store else None
        reported = (snapshot or {}).get("firmware_version")
        self.results[duid] = {**result, "version": version, "firmware_version_reported": reported}
        self._write_record(duid, self.results[duid])
        succeeded = bool(result.get("ran")) and result.get("final_state") == "idle" and bool(result.get("saw_offline"))
        if succeeded:
            self._set_live(duid, "IDLE", "100")
        else:
            self._set_live(duid, "FAILED", err_msg=str(result.get("reason") or "The robot did not finish the update"), err_code=1)
        if reported != version:
            logger.warning("After the install the robot %s reports firmware %r, not %s", duid, reported, version)
        if result.get("ran") and result.get("final_state") == "idle" and result.get("saw_offline"):
            clean_package_cache(self.cache_dir)
        logger.info("Firmware install of %s on %s finished: ran=%s final=%s", version, duid, result.get("ran"), result.get("final_state"))
