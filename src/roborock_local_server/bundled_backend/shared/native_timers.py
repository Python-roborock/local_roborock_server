"""Read the robot's get_server_timer entries, whichever layout the firmware answers with."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NativeTimer:
    name: str
    # What upd_server_timer and del_server_timer must be given: the name, or the whole entry string.
    entry_id: str
    # None when the entry does not say clearly.
    enabled: bool | None


def native_timer_name(entry_id: str) -> str:
    """The timer name inside an entry id such as 'Y <name> 1 1 <cron> app_start', else the id itself."""
    tokens = entry_id.split()
    return tokens[1] if len(tokens) >= 3 else entry_id


def parse_native_timers(timers: Any) -> list[NativeTimer]:
    """Reads [name, "on"|"off", ...] and the S6 MaxV form ["Y <name> 1 1 <cron> app_start", 0] (["Y ...", "off", 0] when off)."""
    found: list[NativeTimer] = []
    if not isinstance(timers, list):
        return found
    for entry in timers:
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            continue
        entry_id = entry[0]
        second = entry[1] if len(entry) > 1 else None
        if second in ("on", "off"):
            enabled: bool | None = second == "on"
        elif len(entry_id.split()) >= 3 and not isinstance(second, (str, bool)) and (second is None or isinstance(second, int)):
            enabled = True
        else:
            enabled = None
        found.append(NativeTimer(native_timer_name(entry_id), entry_id, enabled))
    return found
