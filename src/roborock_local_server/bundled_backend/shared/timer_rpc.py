"""Answer the vacuum's legacy timer RPCs (get/set/upd/del_timer) from the schedule store.

On cloud-managed robots the schedules live server-side, not on the robot, so
clients such as LocalRock that ask the robot for its timers would otherwise see
nothing and could never change the schedules the cloud imported. The topic
bridge hands matching requests here instead of forwarding them to the robot. Requests about a
timer the store does not own (a robot's own legacy timer, a patrol timer) still go to the robot,
and get_timer replies from the robot are merged with the store's entries.

Deliberately not handled here: get/set/upd/del_server_timer, the newer sibling
protocol some firmware speaks instead of (or alongside) this one. The robot
stores those entries itself and the official app reads them back from it, so
they must always forward to the robot untouched. Answering them from this store
instead, tried once, hid the robot's real schedules from every client reading
through the server, and the official app then deleted them (it removes
server_timer entries it does not recognize when its schedule screen opens).

What runs a server_timer schedule is the cloud's own record of it, the job the
official app also writes to /user/devices/{duid}/jobs, which ScheduleRunner
fires like any other. The robot was not seen to run them itself.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import TYPE_CHECKING, Any, NamedTuple

from roborock.protocol import create_mqtt_decoder, create_mqtt_encoder
from roborock.roborock_message import RoborockMessage, RoborockMessageProtocol

from .constants import DEFAULT_TIMEZONE
from .schedule_runner import CronError, parse_cron
from .schedule_store import (
    JOB_SETTING_KEYS,
    SettingsError,
    delete_job,
    has_native_timer,
    job_settings,
    list_jobs,
    merge_job_settings,
    set_enabled,
    upsert_job,
)

if TYPE_CHECKING:
    from .context import ServerContext

_LOGGER = logging.getLogger(__name__)

TIMER_METHODS = frozenset({"get_timer", "set_timer", "upd_timer", "del_timer"})
_OK = ["ok"]


class TimerRequestError(ValueError):
    """The request used a shape this handler cannot interpret."""


class ForwardToRobot(Exception):
    """The request is about a timer the store does not own; the robot must answer it."""


# Timers the robot runs itself; the store cannot start a patrol, so these always go to the robot.
_PATROL_ACTIONS = frozenset({"app_start_patrol", "start_patrol"})
_STATUS_WORDS = frozenset({"on", "off", "disable"})
_PENDING_SECONDS = 30.0
_NAME_RE = re.compile(r"[A-Za-z]{3}")
_MONTH_NUMBERS = {name: number for number, name in enumerate(
    ("JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"), 1)}
_DAY_NUMBERS = {name: number for number, name in enumerate(("SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"))}


class _SetTimer(NamedTuple):
    job_id: str
    enabled: bool
    cron: str
    settings: dict[str, Any]
    action: str


def device_cron(cron: str) -> str | None:
    """Cron in the robot's own 'm h dom month dow' form, with '?' written as '*'.

    A one-time schedule pins the day of the month and the month ('15 23 18 10 *'), exactly as
    the robot and the official app write it (confirmed live), so it is shown like any other.
    A job that pins only one of the two has no such form and is left out of get_timer rather
    than shown wrong.
    """
    fields = str(cron or "").split()
    if len(fields) != 5:
        return None
    minute, hour, dom, month, dow = (field if field != "?" else "*" for field in fields)
    if (dom == "*") != (month == "*"):
        return None
    # Robot clients read digits, so day and month names (MON-FRI) are written out as numbers.
    month = _NAME_RE.sub(lambda m: str(_MONTH_NUMBERS[m.group(0).upper()]), month)
    dow = _NAME_RE.sub(lambda m: str(_DAY_NUMBERS[m.group(0).upper()]), dow)
    return f"{minute} {hour} {dom} {month} {dow}"


def _timer_entry(job: dict[str, Any]) -> list[Any] | None:
    # Captured a15/a27 cloud jobs have native server timers while get_timer is
    # empty. Do not fabricate a second legacy timer for the same native job.
    if has_native_timer(job):
        return None
    cron = device_cron(str(job.get("cron") or ""))
    if cron is None:
        return None
    enabled = job.get("enabled", True)
    on = enabled not in (False, 0, "0", "false", "False")
    return [str(job.get("id")), "on" if on else "off", [cron, ["start_clean", job_settings(job)]]]


def _parse_set_timer(params: Any) -> _SetTimer:
    entry = params[0] if isinstance(params, list) and params and isinstance(params[0], list) else params
    if not isinstance(entry, list) or len(entry) < 2:
        raise TimerRequestError("set_timer needs [id, [status, [cron, action]]]")
    job_id = str(entry[0])
    status: Any = None
    if len(entry) >= 3 and isinstance(entry[1], str):
        status, detail = entry[1], entry[2]
    else:
        spec = entry[1]
        if not isinstance(spec, list) or len(spec) < 2:
            raise TimerRequestError("set_timer spec must be [status, [cron, action]] or [cron, action]")
        if isinstance(spec[0], str) and spec[0].lower() in _STATUS_WORDS and isinstance(spec[1], list):
            status, detail = spec[0], spec[1]
        else:
            # The official app's layout has no status element: [id, [cron, [action, {...}]]].
            detail = spec
    if not isinstance(detail, list) or not detail:
        raise TimerRequestError("set_timer is missing its cron")
    action = detail[1] if len(detail) > 1 else None
    action_name = str(action[0]) if isinstance(action, list) and action else ""
    settings = action[1] if isinstance(action, list) and len(action) > 1 and isinstance(action[1], dict) else {}
    # A timer written without a status starts on, as the official app's own timers do.
    enabled = True if status is None else str(status).lower() == "on"
    return _SetTimer(job_id, enabled, str(detail[0]), settings, action_name)


def _id_and_status(params: Any) -> tuple[str, str]:
    entry = params[0] if isinstance(params, list) and params and isinstance(params[0], list) else params
    if not isinstance(entry, list) or len(entry) < 2:
        raise TimerRequestError("upd_timer needs [id, status]")
    return str(entry[0]), str(entry[1]).lower()


def _single_id(params: Any) -> str:
    if isinstance(params, list) and params:
        first = params[0]
        return str(first[0]) if isinstance(first, list) and first else str(first)
    if params is None or params == []:
        raise TimerRequestError("del_timer needs a timer id")
    return str(params)


def handle_timer_request(
    ctx: ServerContext,
    duid: str,
    method: str,
    params: Any,
    *,
    default_timezone: str = "",
) -> Any:
    """Apply one timer RPC to the store and return the RPC ``result`` value."""
    if method == "get_timer":
        entries = (_timer_entry(job) for job in list_jobs(ctx, duid))
        return [entry for entry in entries if entry is not None]

    if method == "set_timer":
        job_id, enabled, cron, action_settings, action_name = _parse_set_timer(params)
        if action_name in _PATROL_ACTIONS:
            raise ForwardToRobot(f"{action_name} timers are run by the robot")
        try:
            parse_cron(cron)
        except CronError as exc:
            raise TimerRequestError(str(exc)) from exc
        # An empty action object (what older clients send) leaves the job's settings alone;
        # keys it does carry are merged in, so a client can change one option at a time.
        settings = {key: value for key, value in action_settings.items() if key in JOB_SETTING_KEYS}
        param = None
        if settings:
            existing = next((job for job in list_jobs(ctx, duid) if str(job.get("id")) == job_id), None)
            try:
                param = merge_job_settings(existing.get("param") if existing else None, settings)
            except SettingsError as exc:
                raise TimerRequestError(str(exc)) from exc
        zone = str(getattr(ctx, "timezone", "") or default_timezone or DEFAULT_TIMEZONE)
        upsert_job(ctx, duid, job_id=job_id, cron=cron, enabled=enabled, time_zone=zone, param=param)
        return list(_OK)

    if method == "upd_timer":
        job_id, status = _id_and_status(params)
        if status not in ("on", "off"):
            raise TimerRequestError(f"unknown timer status {status!r}")
        if not set_enabled(ctx, duid, job_id, status == "on"):
            raise ForwardToRobot(f"timer {job_id} is not in the schedule store")
        return list(_OK)

    if method == "del_timer":
        if not delete_job(ctx, duid, _single_id(params)):
            raise ForwardToRobot("timer is not in the schedule store")
        return list(_OK)

    raise TimerRequestError(f"not a timer method: {method!r}")


class TimerRpcInterceptor:
    """Bridge hook: turn an encrypted timer request into an encrypted reply, or None to forward."""

    def __init__(self, context: ServerContext, *, default_timezone: str = "") -> None:
        self._context = context
        self._default_timezone = default_timezone
        # get_timer requests forwarded to the robot whose reply needs the store's entries added.
        self._pending: dict[tuple[str, Any], tuple[float, list[Any]]] = {}

    def _localkey(self, duid: str) -> str:
        creds = self._context.runtime_credentials
        device = creds.resolve_device(duid=duid) if creds is not None else None
        key = str((device or {}).get("localkey") or "").strip()
        return key or str(getattr(self._context, "localkey", "") or "").strip()

    def __call__(self, duid: str, payload: bytes) -> bytes | None:
        localkey = self._localkey(duid)
        if not localkey:
            return None
        try:
            messages = create_mqtt_decoder(localkey)(payload)
        except Exception:  # noqa: BLE001
            return None
        if len(messages) != 1:
            return None
        message = messages[0]
        protocol = int(getattr(message.protocol, "value", message.protocol))
        if protocol != RoborockMessageProtocol.RPC_REQUEST.value or not message.payload:
            return None
        request = _dps_body(message, RoborockMessageProtocol.RPC_REQUEST)
        if request is None or request.get("method") not in TIMER_METHODS:
            return None

        request_id = request.get("id")
        method = str(request["method"])
        try:
            result = handle_timer_request(
                self._context, duid, method, request.get("params"), default_timezone=self._default_timezone,
            )
            body: dict[str, Any] = {"id": request_id, "result": result}
        except ForwardToRobot:
            return None
        except TimerRequestError as exc:
            _LOGGER.warning("Rejected %s for %s: %s", method, duid, exc)
            body = {"id": request_id, "error": {"code": -1, "message": str(exc)}}
        except OSError as exc:
            # A save that failed must be reported, not passed on to the robot as if it were fine.
            _LOGGER.warning("Could not save %s for %s: %s", method, duid, exc)
            body = {"id": request_id, "error": {"code": -1, "message": "unable to save the schedule"}}
        if method == "get_timer" and "result" in body:
            # The robot may hold legacy timers of its own: let it answer and add the store's entries.
            if body["result"]:
                self._remember_pending(duid, request_id, body["result"])
            return None
        return _encode_reply(localkey, message, body)

    def _remember_pending(self, duid: str, request_id: Any, entries: list[Any]) -> None:
        now = time.monotonic()
        self._pending = {key: value for key, value in self._pending.items() if value[0] > now}
        self._pending[(duid, request_id)] = (now + _PENDING_SECONDS, entries)

    def merge_response(self, duid: str, payload: bytes) -> bytes | None:
        """Add the store's timers to the robot's get_timer reply, or None to pass it on unchanged."""
        if not self._pending:
            return None
        localkey = self._localkey(duid)
        if not localkey:
            return None
        try:
            messages = create_mqtt_decoder(localkey)(payload)
        except Exception:  # noqa: BLE001
            return None
        if len(messages) != 1:
            return None
        message = messages[0]
        if int(getattr(message.protocol, "value", message.protocol)) != RoborockMessageProtocol.RPC_RESPONSE.value:
            return None
        body = _dps_body(message, RoborockMessageProtocol.RPC_RESPONSE)
        if body is None:
            return None
        pending = self._pending.get((duid, body.get("id")))
        if pending is None or pending[0] <= time.monotonic():
            return None
        theirs = body.get("result") if isinstance(body.get("result"), list) else []
        known = {str(entry[0]) for entry in theirs if isinstance(entry, list) and entry}
        merged = [*theirs, *(entry for entry in pending[1] if str(entry[0]) not in known)]
        return _encode_reply(localkey, message, {"id": body.get("id"), "result": merged})


def _encode_reply(localkey: str, request: RoborockMessage, body: dict[str, Any]) -> bytes:
    reply = RoborockMessage(
        protocol=RoborockMessageProtocol.RPC_RESPONSE,
        payload=json.dumps(
            {
                "t": int(time.time()),
                "dps": {str(RoborockMessageProtocol.RPC_RESPONSE.value): json.dumps(body)},
            },
            separators=(",", ":"),
        ).encode(),
        seq=request.seq,
        version=request.version,
    )
    return create_mqtt_encoder(localkey)(reply)


def _dps_body(message: RoborockMessage, protocol: RoborockMessageProtocol) -> dict[str, Any] | None:
    try:
        outer = json.loads(message.payload)
        inner = outer["dps"][str(protocol.value)]
        body = json.loads(inner) if isinstance(inner, str) else inner
    except (ValueError, KeyError, TypeError):
        return None
    return body if isinstance(body, dict) else None


def _request_body(message: RoborockMessage) -> dict[str, Any] | None:
    return _dps_body(message, RoborockMessageProtocol.RPC_REQUEST)
