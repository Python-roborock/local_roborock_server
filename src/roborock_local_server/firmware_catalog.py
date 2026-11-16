"""Every firmware package this server has learned of, per robot model, so an older one can be installed again.

The cloud has no route that lists versions: it only gives a package address for a version asked for by name, and
only for versions that were released. The server therefore keeps each version it sees and never drops one.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import firmware_versions

logger = logging.getLogger("real_stack.api")

# Where an entry was learned: the version a robot ran before an install, a package installed, or a cloud offer.
SOURCE_ROBOT = "robot_reported"
SOURCE_INSTALL = "install"
SOURCE_PROBE = "probe"
SOURCE_OFFER = "cloud_offer"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _newest_first(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(entries, key=lambda entry: firmware_versions.parse(entry["version"]) or (), reverse=True)


class FirmwareCatalog:
    """A JSON file: ``{"models": {model: {version: entry}}, "robots": {duid: last install}}``."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def _load(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            data = {}
        except (OSError, ValueError) as exc:
            logger.warning("Could not read the firmware catalog %s: %s", self.path, exc)
            data = {}
        if not isinstance(data, dict):
            data = {}
        for key in ("models", "robots"):
            if not isinstance(data.get(key), dict):
                data[key] = {}
        return data

    def _save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        partial = self.path.with_name(self.path.name + ".tmp")
        partial.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        partial.replace(self.path)

    def add(
        self, model: str, version: str, *, source: str, url: str = "", md5: str = "", size: int | None = None,
    ) -> dict[str, Any] | None:
        """Adds or completes the entry for (model, version); an entry is never removed or given another checksum."""
        if not model or not version or firmware_versions.parse(version) is None:
            return None
        with self._lock:
            data = self._load()
            versions = data["models"].setdefault(model, {})
            entry = versions.get(version)
            if entry is None:
                entry = versions[version] = {"model": model, "version": version, "first_seen": _now(), "sources": []}
            if md5 and entry.get("md5") and entry["md5"] != md5:
                logger.warning("Firmware %s %s came with checksum %s, the catalog keeps %s", model, version, md5, entry["md5"])
            elif md5:
                entry["md5"], entry["url"] = md5, url
            if size and not entry.get("size"):
                entry["size"] = int(size)
            if source not in entry["sources"]:
                entry["sources"].append(source)
            self._save(data)
            return dict(entry)

    def entry(self, model: str, version: str) -> dict[str, Any] | None:
        found = self._load()["models"].get(model, {}).get(version)
        return dict(found) if isinstance(found, dict) else None

    def versions(self, model: str) -> list[dict[str, Any]]:
        """The model's versions, newest first."""
        return _newest_first([dict(entry) for entry in self._load()["models"].get(model, {}).values()])

    def models(self, model: str = "") -> dict[str, list[dict[str, Any]]]:
        models = self._load()["models"]
        names = [model] if model else sorted(models)
        return {name: _newest_first([dict(e) for e in models.get(name, {}).values()]) for name in names if name in models}

    def remember_install(self, duid: str, model: str, previous: str, installed: str) -> None:
        """What a robot ran before its last install, for the reinstall-previous shortcut."""
        with self._lock:
            data = self._load()
            data["robots"][duid] = {"model": model, "previous_version": previous, "installed_version": installed, "at": _now()}
            self._save(data)

    def robot(self, duid: str) -> dict[str, Any] | None:
        found = self._load()["robots"].get(duid)
        return dict(found) if isinstance(found, dict) else None
