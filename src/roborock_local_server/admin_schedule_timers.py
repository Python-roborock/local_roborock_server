"""Dashboard compatibility adapter for shared native schedule synchronization."""

from typing import Any, Callable

from shared.native_schedule_sync import TimerCommand, TimerSyncError, sync_timer as _sync_timer


async def sync_timer(
    supervisor: Any, duid: str, name: str, enabled: bool, *, check_current: Callable[[], None],
) -> str:
    return await _sync_timer(supervisor.context, duid, name, enabled, check_current=check_current)
