"""The firmware version a robot says it runs, against what the cloud still believes.

The cloud learns a robot's version from the robot's own connection to it. A robot paired to this server never
reports there, so after a local update the cloud keeps offering the update. The robot's own report (protocol 203,
sent each time it connects) is the truth, and the answers the apps read are corrected with it.
"""

from __future__ import annotations

from typing import Any


def parse(version: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(part) for part in str(version).strip().split("."))
    except ValueError:
        return None


def at_least(reported: str, offered: str) -> bool:
    """True when the version the robot reports is the offered one or newer."""
    have, want = parse(reported), parse(offered)
    if have is None or want is None:
        return bool(reported) and reported == offered
    return have >= want


def reported_version(snapshot_store: Any, duid: str) -> str:
    """The version the robot last reported, or an empty string when it has not."""
    if snapshot_store is None or not duid:
        return ""
    try:
        entry = snapshot_store.get(duid)
    except Exception:  # noqa: BLE001
        return ""
    value = (entry or {}).get("firmware_version")
    return value if isinstance(value, str) else ""


def reconcile(info: Any, duid: str, snapshot_store: Any) -> Any:
    """An update answer for one robot with the robot's own version applied."""
    reported = reported_version(snapshot_store, duid)
    if not reported or not isinstance(info, dict):
        return info
    fixed = dict(info)
    fixed["currentVersion"] = reported
    if at_least(reported, str(fixed.get("version") or "")):
        fixed["updatable"] = False
    return fixed


def reconcile_result(result: Any, duid: str, snapshot_store: Any) -> Any:
    """Either answer shape: one robot's dict (the path style) or the list of per-robot rows (the query style)."""
    if isinstance(result, list):
        rows = []
        for row in result:
            if isinstance(row, dict) and isinstance(row.get("firmwareUpdateResponse"), dict):
                row = {**row, "firmwareUpdateResponse": reconcile(row["firmwareUpdateResponse"], str(row.get("duid") or ""), snapshot_store)}
            rows.append(row)
        return rows
    return reconcile(result, duid, snapshot_store)
