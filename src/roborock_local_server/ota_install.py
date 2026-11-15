"""Installs firmware when the official app's Update button is pressed.

The cloud says which version is on offer; the package is fetched, checked against the checksum in its
address and served to the robot from this server, which then downloads, installs and reboots. With
[ota] allow_downgrade any other version in the firmware catalog can be installed the same way.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import firmware_versions
from .bundled_backend.shared.routine_runner import _RoutineMqttClient
from .firmware_catalog import SOURCE_INSTALL, SOURCE_OFFER, SOURCE_ROBOT, FirmwareCatalog
from .ota_dry_run import (
    PackageRefused,
    PackageUnavailable,
    clean_package_cache,
    package_address,
    package_md5,
    resolve_package,
)

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
        self._catalog: FirmwareCatalog | None = None
        self._lookups: dict[tuple[str, str], asyncio.Task[Any]] = {}

    @property
    def cache_dir(self) -> Path:
        return self._supervisor.paths.runtime_dir / "ota_packages"

    @property
    def catalog(self) -> FirmwareCatalog:
        if self._catalog is None:
            self._catalog = FirmwareCatalog(self._supervisor.paths.runtime_dir / "firmware_catalog.json")
        return self._catalog

    @property
    def _keep_packages(self) -> bool:
        return bool(getattr(self._supervisor.config.ota, "keep_previous_package", False))

    def _vacuum(self, duid: str) -> dict[str, Any] | None:
        return next((v for v in self._supervisor._vacuums_payload()["vacuums"] if str(v.get("duid") or "") == duid), None)

    def model_of(self, duid: str, vacuum: dict[str, Any] | None = None) -> str:
        """The robot's model, from the inventory or else from the account's home data."""
        model = str(((vacuum if vacuum is not None else self._vacuum(duid)) or {}).get("model") or "")
        if model:
            return model
        devices = getattr(self._supervisor.cloud_manager, "firmware_devices", None)
        try:
            rows = devices() if callable(devices) else []
        except Exception:  # noqa: BLE001
            rows = []
        return next((str(row.get("model") or "") for row in rows if str(row.get("duid") or "") == duid), "")

    async def _learn(self, duid: str, model: str, version: str, source: str) -> dict[str, Any] | None:
        """Adds a version to the catalog, asking the cloud for its package address when the catalog lacks it."""
        entry = self.catalog.entry(model, version)
        if entry is not None and entry.get("md5"):
            return self.catalog.add(model, version, source=source)
        try:
            url = await package_address(self._supervisor.cloud_manager, duid, version)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not look up the package of firmware %s for %s: %s", version, model, exc)
            url = ""
        return self.catalog.add(model, version, source=source, url=url, md5=package_md5(url))

    def learn_offers(self, result: Any, duid: str = "") -> None:
        """Adds the versions the cloud offers in an update answer (either shape) to the catalog, in the background."""
        pairs: list[tuple[str, Any]] = []
        if isinstance(result, list):
            pairs = [(str(row.get("duid") or ""), row.get("firmwareUpdateResponse")) for row in result if isinstance(row, dict)]
        elif isinstance(result, dict):
            pairs = [(duid, result)]
        for robot, info in pairs:
            version = str(info.get("version") or "") if isinstance(info, dict) else ""
            model = self.model_of(robot) if robot and version else ""
            if not model:
                continue
            entry = self.catalog.entry(model, version)
            running = self._lookups.get((model, version))
            if (entry and entry.get("md5") and SOURCE_OFFER in entry["sources"]) or (running and not running.done()):
                continue
            self._lookups[(model, version)] = asyncio.create_task(self._learn(robot, model, version, SOURCE_OFFER))

    async def start(self, duid: str) -> dict[str, Any]:
        """Begins an install in the background, or says why not. One install runs at a time."""
        supervisor = self._supervisor
        if any(not task.done() for task in self._running.values()):
            return {"started": False, "reason": "Another firmware install is already running"}
        vacuum = self._vacuum(duid)
        if vacuum is None:
            return {"started": False, "reason": f"Unknown device {duid!r}"}
        reported = firmware_versions.reported_version(supervisor.context.snapshot_store, duid)
        try:
            # The cloud's own idea of the current version is stale after any local install.
            info = firmware_versions.apply_reported(await supervisor.cloud_manager.firmware_update_info(duid), reported)
        except Exception as exc:  # noqa: BLE001
            return {"started": False, "reason": f"Could not ask the cloud about updates: {exc}"}
        version = info.get("version") if isinstance(info, dict) else None
        if not isinstance(info, dict) or info.get("updatable") is not True or not version:
            return {"started": False, "reason": "The cloud offers no update for this robot"}

        async def resolve(keep: set[str]) -> dict[str, Any]:
            return await resolve_package(
                supervisor.cloud_manager, duid, str(version), serve=True, allow_update=True, cache_dir=self.cache_dir,
                reported=reported, keep=keep,
            )

        return await self._launch(duid, vacuum, reported, str(version), resolve)

    @property
    def other_versions_allowed(self) -> bool:
        ota = self._supervisor.config.ota
        return bool(ota.enable_install and getattr(ota, "allow_downgrade", False))

    async def start_version(self, duid: str, version: str = "") -> dict[str, Any]:
        """Installs a catalog version other than the robot's current one (older ones included), by default the one
        it ran before its last install. Proven on one Qrevo Curv 2 Flow only, so it needs its own opt-in."""
        supervisor = self._supervisor
        if not self.other_versions_allowed:
            return {"started": False, "reason": "Installing another firmware version is off ([ota] enable_install and allow_downgrade)"}
        if any(not task.done() for task in self._running.values()):
            return {"started": False, "reason": "Another firmware install is already running"}
        vacuum = self._vacuum(duid)
        if vacuum is None:
            return {"started": False, "reason": f"Unknown device {duid!r}"}
        model = self.model_of(duid, vacuum)
        reported = firmware_versions.reported_version(supervisor.context.snapshot_store, duid)
        if not model or not reported:
            return {"started": False, "reason": "The robot's model or its own firmware report is not known yet"}
        version = version or str((self.catalog.robot(duid) or {}).get("previous_version") or "")
        if not version:
            return {"started": False, "reason": "No previous version is remembered for this robot"}
        if version == reported:
            return {"started": False, "reason": f"The robot already runs {version}"}
        entry = self.catalog.entry(model, version)
        if entry is None:
            return {"started": False, "reason": f"{version} is not in the firmware catalog for {model}"}
        if not entry.get("md5"):
            entry = await self._learn(duid, model, version, entry["sources"][0] if entry.get("sources") else SOURCE_OFFER)
        if not entry or not entry.get("md5"):
            return {"started": False, "reason": f"The cloud gives no package for {version}"}

        async def resolve(keep: set[str]) -> dict[str, Any]:
            try:
                return await resolve_package(
                    supervisor.cloud_manager, duid, version, serve=True, cache_dir=self.cache_dir, known_url=entry["url"], keep=keep,
                )
            except PackageUnavailable:
                # The remembered address went stale: ask again, and only take the same package.
                url = await package_address(supervisor.cloud_manager, duid, version)
                if package_md5(url) != entry["md5"]:
                    raise PackageRefused(f"The remembered package of {version} is gone and the cloud has no matching one") from None
                return await resolve_package(
                    supervisor.cloud_manager, duid, version, serve=True, cache_dir=self.cache_dir, known_url=url, keep=keep,
                )

        return await self._launch(duid, vacuum, reported, version, resolve)

    def version_info(self, duid: str) -> dict[str, Any]:
        """The catalog versions for the robot's model, the current one marked, for LocalRock's firmware screen."""
        model = self.model_of(duid)
        reported = firmware_versions.reported_version(self._supervisor.context.snapshot_store, duid)
        allowed = self.other_versions_allowed and bool(reported)
        previous = str((self.catalog.robot(duid) or {}).get("previous_version") or "")
        info: dict[str, Any] = {"downgradeAllowed": allowed, "availableVersions": [
            {
                "version": entry["version"], "current": entry["version"] == reported,
                "installable": allowed and bool(entry.get("md5")) and entry["version"] != reported,
                "firstSeen": entry.get("first_seen"), "size": entry.get("size"),
            }
            for entry in (self.catalog.versions(model) if model else [])
        ]}
        if previous and previous != reported:
            info["previousVersion"] = previous
        return info

    async def _launch(self, duid: str, vacuum: dict[str, Any], reported: str, version: str, resolve: Any) -> dict[str, Any]:
        """Records the version the robot runs now, fetches the package and starts the install."""
        model = self.model_of(duid, vacuum)
        before = await self._learn(duid, model, reported, SOURCE_ROBOT) if model and reported and reported != version else None
        keep = {f"{before['md5']}.pkg"} if self._keep_packages and before and before.get("md5") else set()
        try:
            package = await resolve(keep)
        except PackageRefused as exc:
            return {"started": False, "reason": str(exc)}
        except Exception as exc:  # noqa: BLE001
            return {"started": False, "reason": f"Could not fetch the package: {exc}"}
        data = package.get("data")
        size = data.stat().st_size if isinstance(data, Path) else len(data or b"")
        if model:
            self.catalog.add(model, version, source=SOURCE_INSTALL, url=package["url"], md5=package["md5"], size=size or None)
        device = {"duid": duid, "localkey": str(vacuum.get("local_key") or "")}
        self.results.pop(duid, None)
        self._set_live(duid, "START")
        self._running[duid] = asyncio.create_task(self._install(device, package, version, model, reported, keep))
        return {"started": True, "version": version}

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

    async def _install(
        self, device: dict[str, str], package: dict[str, Any], version: str, model: str = "", previous: str = "",
        keep: set[str] | None = None,
    ) -> None:
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
        changed = bool(reported) and bool(previous) and reported != previous
        if model and previous and previous != version and result.get("ran") and (succeeded or changed):
            self.catalog.remember_install(duid, model, previous, version)
        if succeeded:
            # With keep_previous_package the packages before and after this install stay for a quick reinstall.
            clean_package_cache(self.cache_dir, keep={f"{package['md5']}.pkg", *(keep or ())} if self._keep_packages else ())
        logger.info("Firmware install of %s on %s finished: ran=%s final=%s", version, duid, result.get("ran"), result.get("final_state"))
