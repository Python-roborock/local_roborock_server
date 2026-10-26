"""Reconcile native schedule enablement independently of the client making a change."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from enum import StrEnum
import logging
import time
from typing import Any

from .inventory_io import load_inventory
from .schedule_store import SettingsError, list_jobs, native_timer_name, reconcile_native_enabled

_LOGGER = logging.getLogger(__name__)


class TimerSyncError(RuntimeError):
    def __init__(self, message: str, status: int = 503) -> None:
        super().__init__(message)
        self.status = status


class TimerCommand(StrEnum):
    GET = "get_server_timer"
    UPDATE = "upd_server_timer"


def _timer_state(timers: Any, name: str) -> str:
    if not isinstance(timers, list):
        raise TimerSyncError("The vacuum did not return a usable timer list. Refresh schedules and retry.")
    matches = [entry for entry in timers if isinstance(entry, list) and entry and entry[0] == name]
    if not matches:
        raise TimerSyncError("The linked robot timer is missing. Check this schedule in the Roborock app before retrying.", 409)
    if len(matches) != 1 or len(matches[0]) < 2 or matches[0][1] not in ("on", "off"):
        raise TimerSyncError("The linked robot timer is ambiguous. Check this schedule in the Roborock app before retrying.", 409)
    return matches[0][1]


async def sync_timer(
    context: Any, duid: str, name: str, enabled: bool, *, check_current: Callable[[], None],
) -> str:
    """Update only the named timer; a fresh read is the success criterion.

    The app sends upd_server_timer before its HTTP job update. A timed-out write
    may still have reached the vacuum, so read it back without repeating the
    write. Never create a timer or infer one from a cloud job's numeric ID.
    """
    from shared.routine_runner import _RoutineMqttClient

    device = context.runtime_credentials.resolve_device(duid=duid)
    if device is None or not device.get("localkey"):
        raise TimerSyncError("Connect this vacuum to the local server before changing its schedule.")
    desired = "on" if enabled else "off"
    client = None
    write_attempted = False
    try:
        async with asyncio.timeout(45):
            client = _RoutineMqttClient(context, device, logging.getLogger(__name__))
            await client.connect()
            current = _timer_state(await client.send_command(TimerCommand.GET, []), name)
            # Recheck the job after the network read, before changing the robot.
            check_current()
            if current != desired:
                write_attempted = True
                try:
                    await client.send_command(TimerCommand.UPDATE, [[name, desired]])
                except Exception:
                    # A read-back can confirm a write whose acknowledgement was
                    # lost. It cannot confirm a refused or unapplied write.
                    pass
                current = _timer_state(await client.send_command(TimerCommand.GET, []), name)
                if current != desired:
                    raise TimerSyncError("The vacuum did not confirm the requested timer setting. Refresh schedules and retry.")
            return current
    except TimerSyncError:
        raise
    except Exception as exc:
        message = (
            "The robot timer may have changed, but verification failed. Refresh schedules and retry."
            if write_attempted else
            "Could not read this vacuum's timer. Make sure it is connected locally, then retry."
        )
        raise TimerSyncError(message) from exc
    finally:
        if client is not None:
            try:
                async with asyncio.timeout(5):
                    await client.close()
            except Exception:
                logging.getLogger(__name__).warning("Unable to close schedule timer connection")


def timer_states(timers: Any) -> dict[str, bool]:
    """Ignore ambiguous/malformed entries; absence is not proof of disablement."""
    if not isinstance(timers, list):
        raise TimerSyncError("The vacuum did not return a usable timer list")
    states: dict[str, bool] = {}
    seen: set[str] = set()
    invalid: set[str] = set()
    for entry in timers:
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            continue
        name = entry[0]
        if name in seen or len(entry) < 2 or entry[1] not in ("on", "off"):
            invalid.add(name)
        else:
            states[name] = entry[1] == "on"
        seen.add(name)
    return {name: enabled for name, enabled in states.items() if name not in invalid}


class NativeScheduleSync:
    """One coordinator for API edits and read-only reconciliation from any client.

    Native RPCs still reach the robot unchanged. Observing a write only schedules
    a fresh read; no optimistic request or generic 'ok' reply mutates inventory.
    Periodic reads also catch LAN changes and recover after missed MQTT traffic.
    """

    INTERVAL = 30.0
    DEBOUNCE = 0.3

    def __init__(self, context: Any) -> None:
        self.context = context
        self._locks: dict[str, asyncio.Lock] = {}
        self._generation: dict[str, int] = {}
        self._enable_intent: dict[str, dict[str, tuple[float, Any]]] = {}
        self._dirty: set[str] = set()
        self._wake = asyncio.Event()
        self._slots = asyncio.Semaphore(2)

    def lock(self, duid: str) -> asyncio.Lock:
        return self._locks.setdefault(duid, asyncio.Lock())

    def changed(self, duid: str, *, enable_name: str | None = None) -> None:
        self._generation[duid] = self._generation.get(duid, 0) + 1
        if enable_name is not None:
            # Tie one-time re-enablement to the occurrence already consumed when
            # the request was observed, never one consumed after this request.
            claims = load_inventory(self.context).get("schedule_occurrences", {}).get(duid, {})
            for job in list_jobs(self.context, duid):
                try:
                    matches = native_timer_name(job) == enable_name
                except SettingsError:
                    continue
                if matches:
                    self._enable_intent.setdefault(duid, {})[enable_name] = (
                        time.monotonic() + 120, claims.get(str(job.get("id"))),
                    )
        self._dirty.add(duid)
        self._wake.set()

    def observe_request(self, duid: str, payload: bytes) -> None:
        from roborock.protocol import create_mqtt_decoder
        from .timer_rpc import _request_body

        device = self.context.runtime_credentials.resolve_device(duid=duid)
        if not device or not device.get("localkey"):
            return
        try:
            messages = create_mqtt_decoder(device["localkey"])(payload)
            for message in messages:
                if int(getattr(message.protocol, "value", message.protocol)) != 101:
                    continue
                request = _request_body(message)
                if not request or request.get("method") not in {
                    "upd_server_timer", "set_server_timer", "del_server_timer",
                }:
                    continue
                enable_name = None
                params = request.get("params")
                if (request.get("method") == "upd_server_timer" and isinstance(params, list)
                        and len(params) == 1 and isinstance(params[0], list)
                        and len(params[0]) == 2 and isinstance(params[0][0], str)):
                    name, state = params[0]
                    # A later off must invalidate an earlier on intent, too.
                    self._enable_intent.setdefault(duid, {}).pop(name, None)
                    if state == "on":
                        enable_name = name
                self.changed(duid, enable_name=enable_name)
        except Exception:  # Unrelated/unsupported frames must always pass through.
            return

    async def refresh(self, duid: str) -> list[Any]:
        from .routine_runner import _RoutineMqttClient

        async with self._slots, self.lock(duid):
            snapshot = list_jobs(self.context, duid)
            names = []
            for job in snapshot:
                try:
                    name = native_timer_name(job)
                except SettingsError:
                    continue
                if name is not None:
                    names.append(name)
            if not names:
                return []
            device = self.context.runtime_credentials.resolve_device(duid=duid)
            if not device or not device.get("localkey"):
                return []
            generation = self._generation.get(duid, 0)
            intents = {name: intent for name, intent in self._enable_intent.get(duid, {}).items()
                       if intent[0] > time.monotonic()}
            self._enable_intent[duid] = intents
            explicit_enable = {name: intent[1] for name, intent in intents.items()}
            client = None
            try:
                async with asyncio.timeout(15):
                    client = _RoutineMqttClient(self.context, device, _LOGGER)
                    await client.connect()
                    states = timer_states(await client.send_command(TimerCommand.GET, []))
                if self._generation.get(duid, 0) != generation:
                    # A newer native write overlapped the read. A later pass
                    # will confirm it; do not apply this older snapshot.
                    self._dirty.add(duid)
                    self._wake.set()
                    return []
                changed = reconcile_native_enabled(
                    self.context, duid, snapshot, states, explicit_enable=explicit_enable,
                )
                # A read can arrive before an outstanding command is applied.
                # Keep a bounded enable intent until it is actually observed on.
                self._enable_intent[duid] = {name: until for name, until in intents.items()
                                             if states.get(name) is not True}
                if changed:
                    _LOGGER.info("Synchronized native schedule enablement for %s: %d changed", duid, len(changed))
                return changed
            except (OSError, ValueError):
                _LOGGER.warning("Could not save native schedule reconciliation for %s", duid, exc_info=True)
                return []
            except Exception:
                # An offline/unsupported robot keeps its last saved state.
                _LOGGER.debug("Native schedule read unavailable for %s", duid, exc_info=True)
                return []
            finally:
                if client is not None:
                    try:
                        async with asyncio.timeout(5):
                            await client.close()
                    except Exception:
                        _LOGGER.debug("Could not close native schedule read for %s", duid, exc_info=True)

    async def run(self, stop_event: asyncio.Event) -> None:
        next_scan = 0.0
        while not stop_event.is_set():
            now = time.monotonic()
            due = set(self._dirty)
            self._dirty.clear()
            self._wake.clear()
            if now >= next_scan:
                schedules = load_inventory(self.context).get("schedules", {})
                if isinstance(schedules, dict):
                    due.update(str(duid) for duid in schedules)
                next_scan = now + self.INTERVAL
            if due:
                await asyncio.sleep(self.DEBOUNCE)
                results = await asyncio.gather(*(self.refresh(duid) for duid in sorted(due)), return_exceptions=True)
                for duid, result in zip(sorted(due), results):
                    if isinstance(result, Exception):
                        _LOGGER.warning("Native schedule reconciliation unavailable for %s: %s", duid, type(result).__name__)
            if self._dirty:
                continue
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=max(0.1, next_scan - time.monotonic()))
            except TimeoutError:
                pass
