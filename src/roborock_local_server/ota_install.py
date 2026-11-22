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
from .firmware_scan import DEFAULT_MAX_EMPTY, FirmwareScan
from .ota_dry_run import (
    PackageRefused,
    clean_package_cache,
    package_address,
    package_family,
    package_md5,
    package_name_prefix,
    release_package,
    resolve_package,
)

# A child logger: only real_stack.<name> loggers have an output handler, plain real_stack drops INFO.
logger = logging.getLogger("real_stack.api")

BUSY_REASON = "Another firmware install is already starting or running"
# After the reboot the robot reports its version on its own; wait this long for the target version to show.
REPORT_WAIT_SECONDS = 180
REPORT_POLL_SECONDS = 3
_RUNNING_STATES = ("START", "DOWNLOADING", "INSTALLING", "WAIT_INSTALL")


class OtaInstaller:
    def __init__(self, supervisor: Any) -> None:
        self._supervisor = supervisor
        self._running: dict[str, asyncio.Task[None]] = {}
        # Set before the first await of a start, so a second press cannot begin while the first is still asking the cloud.
        self._claim = ""
        self.results: dict[str, dict[str, Any]] = {}
        # What the official app reads while an install runs: the cloud knows nothing of a local install, so
        # the app's status polls are answered from here. The app treats IDLE as success and an error as failure.
        self._live: dict[str, dict[str, Any]] = {}
        self._live_loaded = False
        self._catalog: FirmwareCatalog | None = None
        self._lookups: dict[tuple[str, str], asyncio.Task[Any]] = {}
        self.scan = FirmwareScan()

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

    async def start_scan(self, duid: str, max_empty: int = DEFAULT_MAX_EMPTY) -> tuple[int, dict[str, Any]]:
        """Starts the version scan for a robot; returns an HTTP status and the body."""
        if self.scan.running:
            return 409, {"success": False, "error": "A scan is already running", "scan": self.scan.state()}
        model = self.model_of(duid)
        if not model:
            return 404, {"success": False, "error": f"Unknown device {duid!r}"}
        current = firmware_versions.reported_version(self._supervisor.context.snapshot_store, duid)
        if len(firmware_versions.parse(current) or ()) != 3:
            try:
                info = await self._supervisor.cloud_manager.firmware_update_info(duid)
            except Exception:  # noqa: BLE001
                info = None
            current = str((info or {}).get("currentVersion") or "") if isinstance(info, dict) else ""
        if len(firmware_versions.parse(current) or ()) != 3:
            current = next((e["version"] for e in self.catalog.versions(model) if len(firmware_versions.parse(e["version"]) or ()) == 3), "")
        if not current:
            return 400, {"success": False, "error": "The robot's current firmware version is not known"}
        return 200, {"success": True, "scan": self.scan.start(self._supervisor.cloud_manager, self.catalog, duid, model, current, max_empty)}

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

    def _busy(self) -> bool:
        return bool(self._claim) or any(not task.done() for task in self._running.values())

    def owns(self, duid: str) -> bool:
        """Whether the robot is in this server's inventory, the one account whose robots the app may install on."""
        return self._vacuum(duid) is not None

    async def start(self, duid: str) -> dict[str, Any]:
        """Begins an install in the background, or says why not. One install runs at a time."""
        if self._busy():
            return {"started": False, "reason": BUSY_REASON}
        self._claim = duid
        try:
            return await self._start(duid)
        finally:
            self._claim = ""

    async def _start(self, duid: str) -> dict[str, Any]:
        supervisor = self._supervisor
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

    async def start_version(self, duid: str, version: str = "", confirm: bool = False, confirm_version: str = "") -> dict[str, Any]:
        """Installs a catalog version other than the robot's current one (older ones included), by default the one
        it ran before its last install. Opt-in; an older version also needs [confirm] and [confirm_version] naming it."""
        if not self.other_versions_allowed:
            return {"started": False, "reason": "Installing another firmware version is off ([ota] enable_install and allow_downgrade)"}
        if self._busy():
            return {"started": False, "reason": BUSY_REASON}
        self._claim = duid
        try:
            return await self._start_version(duid, version, confirm, confirm_version)
        finally:
            self._claim = ""

    @staticmethod
    def _is_downgrade(version: str, reported: str) -> bool:
        target, current = firmware_versions.parse(version), firmware_versions.parse(reported)
        return target is None or current is None or target < current

    async def _start_version(self, duid: str, version: str, confirm: bool, confirm_version: str) -> dict[str, Any]:
        supervisor = self._supervisor
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
        if firmware_versions.same(version, reported):
            return {"started": False, "reason": f"The robot already runs {version}"}
        entry = self.catalog.entry(model, version)
        if entry is None:
            return {"started": False, "reason": f"{version} is not in the firmware catalog for {model}"}
        if self._is_downgrade(version, reported) and not (confirm and confirm_version == version):
            return {
                "started": False, "needs_confirmation": True, "version": version,
                "reason": f"{version} is older than the {reported} the robot runs; resend with confirm_downgrade true and version {version}",
            }
        try:
            url = await self._robot_package_url(duid, model, version, reported, entry)
        except PackageRefused as exc:
            return {"started": False, "reason": str(exc)}

        async def resolve(keep: set[str]) -> dict[str, Any]:
            return await resolve_package(
                supervisor.cloud_manager, duid, version, serve=True, cache_dir=self.cache_dir, known_url=url, keep=keep,
            )

        return await self._launch(duid, vacuum, reported, version, resolve)

    async def _robot_package_url(self, duid: str, model: str, version: str, reported: str, entry: dict[str, Any]) -> str:
        """The package address the cloud gives THIS robot for [version], checked against the catalog and the robot's own
        hardware. The catalog is keyed by model, so what it remembers may have been learned from another robot."""
        cloud = self._supervisor.cloud_manager
        try:
            url = await package_address(cloud, duid, version)
        except Exception as exc:  # noqa: BLE001
            raise PackageRefused(f"Could not ask the cloud for the package of {version}: {exc}") from None
        if not url:
            raise PackageRefused(f"The cloud gives no package of {version} for this robot")
        if entry.get("md5") and entry["md5"] != package_md5(url):
            raise PackageRefused(f"The cloud's package of {version} for this robot differs from the catalog's; it may be another variant")
        try:
            own = await package_address(cloud, duid, reported)
        except Exception:  # noqa: BLE001
            own = ""
        own = own or str((self.catalog.entry(model, reported) or {}).get("url") or "")
        if not own:
            raise PackageRefused(f"The package address of the {reported} the robot runs is not known, so its hardware cannot be checked")
        if not (package_family(own) and package_family(url) and package_name_prefix(own) and package_name_prefix(url)):
            raise PackageRefused("The package address does not name its hardware, so the robot's hardware cannot be checked")
        if package_family(url) != package_family(own) or package_name_prefix(url) != package_name_prefix(own):
            raise PackageRefused(f"The package of {version} is for different hardware than the one the robot runs now")
        return url

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
                "released": entry.get("released"),
            }
            for entry in (self.catalog.versions(model) if model else [])
        ]}
        if previous and previous != reported:
            info["previousVersion"] = previous
        return info

    async def _launch(self, duid: str, vacuum: dict[str, Any], reported: str, version: str, resolve: Any) -> dict[str, Any]:
        """Answers at once and does the package fetch and the install in the background."""
        device = {"duid": duid, "localkey": str(vacuum.get("local_key") or "")}
        self.results.pop(duid, None)
        self._set_live(duid, "START")
        self._running[duid] = asyncio.create_task(self._prepare(device, vacuum, reported, version, resolve))
        return {"started": True, "version": version}

    async def _prepare(self, device: dict[str, str], vacuum: dict[str, Any], reported: str, version: str, resolve: Any) -> None:
        """Records the version the robot runs now, fetches the package (the slow part), then installs it."""
        duid = device["duid"]
        model = self.model_of(duid, vacuum)
        package: dict[str, Any] | None = None
        try:
            before = await self._learn(duid, model, reported, SOURCE_ROBOT) if model and reported and reported != version else None
            keep = {f"{before['md5']}.pkg"} if self._keep_packages and before and before.get("md5") else set()
            package = await resolve(keep)
            data = package.get("data")
            size = data.stat().st_size if isinstance(data, Path) else len(data or b"")
            if model:
                self.catalog.add(model, version, source=SOURCE_INSTALL, url=package["url"], md5=package["md5"], size=size or None)
        except Exception as exc:  # noqa: BLE001
            reason = str(exc) if isinstance(exc, PackageRefused) else f"Could not fetch the package: {exc}"
            logger.warning("Firmware install of %s on %s did not start: %s", version, duid, reason)
            self.results[duid] = {"ran": False, "reason": reason, "version": version, "firmware_version_reported": reported}
            self._set_live(duid, "FAILED", err_msg=reason, err_code=1)
            if package and isinstance(package.get("data"), Path):
                release_package(package["data"].name)
            return
        await self._install(device, package, version, model, reported, keep)

    _APP_STATES = {"downloading": "DOWNLOADING", "installing": "INSTALLING", "wait_install": "WAIT_INSTALL"}
    LIVE_SECONDS = 1800

    def _set_live(self, duid: str, status: str, progress: str = "", err_msg: str = "", err_code: int = 0) -> None:
        self._load_live()
        self._live[duid] = {
            "status": status, "progress": progress, "errCode": err_code, "errMsg": err_msg, "at": time.monotonic(), "wall": time.time(),
        }
        self._save_live()

    @property
    def _live_path(self) -> Path:
        return self._supervisor.paths.runtime_dir / "ota_live.json"

    def _save_live(self) -> None:
        try:
            self._live_path.parent.mkdir(parents=True, exist_ok=True)
            partial = self._live_path.with_name(self._live_path.name + ".tmp")
            partial.write_text(json.dumps(self._live), encoding="utf-8")
            partial.replace(self._live_path)
        except OSError as exc:
            logger.warning("Could not save the firmware install status: %s", exc)

    def _load_live(self) -> None:
        """Restores the saved statuses after a restart; one still running becomes FAILED, as nothing watches it now."""
        if self._live_loaded:
            return
        self._live_loaded = True
        try:
            saved = json.loads(self._live_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for duid, entry in (saved.items() if isinstance(saved, dict) else ()):
            if not isinstance(entry, dict) or not isinstance(entry.get("wall"), (int, float)) or not isinstance(entry.get("status"), str):
                continue
            kept = {
                "status": entry["status"], "progress": str(entry.get("progress") or ""), "errCode": int(entry.get("errCode") or 0),
                "errMsg": str(entry.get("errMsg") or ""), "wall": entry["wall"],
            }
            if kept["status"] in _RUNNING_STATES:
                kept.update(status="FAILED", errCode=1, errMsg="The server restarted during the install; check the robot's firmware version")
            self._live.setdefault(duid, {**kept, "at": time.monotonic() - max(0.0, time.time() - entry["wall"])})

    def _robot_state(self, duid: str, state: Any, progress: Any) -> None:
        """Mirrors the robot's own OTA state. A robot that is idle or silent keeps its last status; IDLE and FAILED
        are only set at the end, since the app reads IDLE as the update being done."""
        status = self._APP_STATES.get(str(state))
        if status is None:
            return
        text = "" if progress is None else str(progress)
        self._load_live()
        previous = self._live.get(duid)
        if status == "INSTALLING":
            # The robot reports no progress of its own while installing (its query answers 0 even though its
            # messages said 100 at the end of the download), so keep the download's last number.
            text = "100"
        elif previous is not None and previous.get("status") == status and previous.get("progress") not in (None, "", "0"):
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
        self._load_live()
        entry = self._live.get(duid)
        if entry is None:
            return None
        if time.monotonic() - entry["at"] > self.LIVE_SECONDS:
            if entry["status"] not in _RUNNING_STATES:
                return None
            # The app reads a missing status as done, so an install that went silent must not look finished.
            return {"status": "FAILED", "progress": entry["progress"], "errCode": 1, "errMsg": "The install status stopped updating; check the robot's firmware version"}
        return {key: value for key, value in entry.items() if key not in ("at", "wall")}

    @staticmethod
    def _failure(result: dict[str, Any]) -> str:
        """Why the watched install does not count as finished, or an empty string when it looks complete."""
        if not result.get("ran"):
            return str(result.get("reason") or "The robot did not finish the update")
        if not result.get("package_fully_fetched"):
            return "The robot never downloaded the whole package from this server"
        if result.get("final_state") != "idle" or not result.get("saw_offline"):
            return "The robot did not finish the update"
        return ""

    async def _wait_for_version(self, duid: str, version: str) -> None:
        """Gives the rebooted robot a while to report the version it now runs."""
        deadline = time.monotonic() + REPORT_WAIT_SECONDS
        store = self._supervisor.context.snapshot_store
        while not firmware_versions.same(firmware_versions.reported_version(store, duid), version) and time.monotonic() < deadline:
            await asyncio.sleep(REPORT_POLL_SECONDS)

    async def _install(self, device: dict[str, str], package: dict[str, Any], *args: Any, **kwargs: Any) -> None:
        """Runs the install; whatever goes wrong outside the watched part still ends as FAILED, never as a stale status."""
        duid = device["duid"]
        try:
            await self._install_run(device, package, *args, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Firmware install on %s failed unexpectedly: %s", duid, exc)
            reason = f"The install stopped unexpectedly: {exc}"
            self.results[duid] = {"ran": False, "reason": reason}
            self._set_live(duid, "FAILED", err_msg=reason, err_code=1)

    async def _install_run(
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
                on_state=lambda state, progress: self._robot_state(duid, state, progress), duid=duid,
            )
        except Exception as exc:  # noqa: BLE001
            result = {"ran": False, "reason": str(exc)}
        finally:
            if isinstance(package.get("data"), Path):
                release_package(package["data"].name)
            try:
                await client.close()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Closing the robot connection failed: %s", exc)
        failure = self._failure(result)
        if not failure:
            await self._wait_for_version(duid, version)
        reported = firmware_versions.reported_version(supervisor.context.snapshot_store, duid) or None
        if not failure and not firmware_versions.same(reported or "", version):
            failure = f"The robot reports firmware {reported or 'nothing'} after the update, not {version}"
        self.results[duid] = {**result, "version": version, "firmware_version_reported": reported}
        self._write_record(duid, self.results[duid])
        succeeded = not failure
        if succeeded:
            self._set_live(duid, "IDLE", "100")
        else:
            self._set_live(duid, "FAILED", err_msg=failure, err_code=1)
        changed = bool(reported) and bool(previous) and not firmware_versions.same(reported or "", previous)
        if model and previous and previous != version and result.get("ran") and (succeeded or changed):
            self.catalog.remember_install(duid, model, previous, version)
        if succeeded:
            # With keep_previous_package the packages before and after this install stay for a quick reinstall.
            clean_package_cache(self.cache_dir, keep={f"{package['md5']}.pkg", *(keep or ())} if self._keep_packages else ())
        logger.info("Firmware install of %s on %s finished: ran=%s final=%s", version, duid, result.get("ran"), result.get("final_state"))
