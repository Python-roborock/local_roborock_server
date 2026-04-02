"""Execute saved Roborock routines over the local MQTT broker."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import logging
from pathlib import Path
import secrets
import sys
from typing import Any


def _ensure_local_python_roborock_on_path() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    local_python_roborock = repo_root / "python-roborock"
    if local_python_roborock.exists():
        local_path = str(local_python_roborock)
        if local_path not in sys.path:
            sys.path.insert(0, local_path)


_ensure_local_python_roborock_on_path()

from roborock.data import RRiot, Reference, RoborockInCleaning, StatusV2
from roborock.exceptions import RoborockUnsupportedFeature
from roborock.mqtt.roborock_session import create_mqtt_session
from roborock.protocol import create_mqtt_decoder, create_mqtt_encoder, create_mqtt_params
from roborock.protocols.v1_protocol import RequestMessage, create_security_data, decode_rpc_response
from roborock.roborock_message import RoborockDataProtocol, RoborockMessage, RoborockMessageProtocol
from roborock.roborock_typing import RoborockCommand

from .context import ServerContext

__all__ = [
    "RoutineCommand",
    "RoutineExecutionError",
    "RoutineRunner",
    "RoutineStep",
    "commands_for_step",
    "parse_scene_steps",
    "scene_device_id",
]

_LOGGER = logging.getLogger(__name__)

_COMMAND_TIMEOUT_SECONDS = 15.0
_STEP_START_TIMEOUT_SECONDS = 20.0
_STEP_COMPLETE_TIMEOUT_SECONDS = 4 * 60 * 60
_STEP_START_POLL_INTERVAL_SECONDS = 0.5
_STATUS_POLL_INTERVAL_SECONDS = 5.0
_ROUTINE_READY_STATES = {3, 8, 100}
_POST_STEP_SETTLE_SECONDS = 15.0
_POST_STEP_SETTLE_TIMEOUT_SECONDS = 10 * 60
from .inventory_io import WEB_API_INVENTORY_FILE
_SUPPORTED_METHODS = {
    "do_scenes_app_start",
    "do_scenes_segments",
    "do_scenes_zones",
}


class RoutineExecutionError(RuntimeError):
    """Raised when a saved scene cannot be executed as a local routine."""


@dataclass(frozen=True)
class RoutineCommand:
    command: RoborockCommand
    params: dict[str, Any] | list[Any] | None = None


@dataclass(frozen=True)
class RoutineStep:
    step_id: int
    name: str
    method: str
    params: dict[str, Any] | list[Any] | None
    finish_dp_ids: tuple[int, ...]


@dataclass
class _ActiveRoutine:
    task: asyncio.Task[None]
    scene_id: int
    scene_name: str
    cancel_requested: bool = False


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _scene_id(scene: dict[str, Any]) -> int:
    return _as_int(scene.get("id"), 0)


def _scene_name(scene: dict[str, Any]) -> str:
    name = str(scene.get("name") or "").strip()
    return name or f"Routine {_scene_id(scene)}"


def scene_device_id(scene: dict[str, Any]) -> str:
    for key in ("device_id", "deviceId", "duid"):
        candidate = str(scene.get(key) or "").strip()
        if candidate:
            return candidate
    return ""


def _scene_tid_entries(scene: dict[str, Any]) -> list[str]:
    raw_param = scene.get("param")
    if not isinstance(raw_param, str) or not raw_param.strip():
        return []
    try:
        outer = json.loads(raw_param)
    except json.JSONDecodeError:
        return []
    if not isinstance(outer, dict):
        return []

    action = outer.get("action")
    if not isinstance(action, dict):
        return []
    items = action.get("items")
    if not isinstance(items, list):
        return []

    tids: list[str] = []
    seen: set[str] = set()
    for raw_item in items:
        if not isinstance(raw_item, dict):
            continue
        inner_raw = raw_item.get("param")
        if isinstance(inner_raw, str):
            try:
                inner = json.loads(inner_raw)
            except json.JSONDecodeError:
                continue
        elif isinstance(inner_raw, dict):
            inner = inner_raw
        else:
            continue
        if not isinstance(inner, dict):
            continue

        params = inner.get("params")
        if not isinstance(params, dict):
            continue
        data = params.get("data")
        if not isinstance(data, list):
            continue
        for entry in data:
            if not isinstance(entry, dict):
                continue
            tid = str(entry.get("tid") or "").strip()
            if not tid or tid in seen:
                continue
            seen.add(tid)
            tids.append(tid)
    return tids


def parse_scene_steps(scene: dict[str, Any]) -> list[RoutineStep]:
    raw_param = scene.get("param")
    if not isinstance(raw_param, str) or not raw_param.strip():
        raise RoutineExecutionError(f"Scene {_scene_id(scene)} is missing param payload")
    try:
        outer = json.loads(raw_param)
    except json.JSONDecodeError as exc:
        raise RoutineExecutionError(f"Scene {_scene_id(scene)} has invalid param JSON") from exc
    if not isinstance(outer, dict):
        raise RoutineExecutionError(f"Scene {_scene_id(scene)} param payload is not an object")

    action = outer.get("action")
    if not isinstance(action, dict):
        raise RoutineExecutionError(f"Scene {_scene_id(scene)} is missing action payload")
    items = action.get("items")
    if not isinstance(items, list) or not items:
        raise RoutineExecutionError(f"Scene {_scene_id(scene)} has no action items")

    steps: list[RoutineStep] = []
    for raw_item in items:
        if not isinstance(raw_item, dict):
            raise RoutineExecutionError(f"Scene {_scene_id(scene)} contains a non-object action item")
        if str(raw_item.get("type") or "").strip().upper() != "CMD":
            raise RoutineExecutionError(
                f"Scene {_scene_id(scene)} contains unsupported action type {raw_item.get('type')!r}"
            )

        inner_raw = raw_item.get("param")
        step_id = _as_int(raw_item.get("id"), 0)
        if isinstance(inner_raw, str):
            try:
                inner = json.loads(inner_raw)
            except json.JSONDecodeError as exc:
                raise RoutineExecutionError(
                    f"Scene {_scene_id(scene)} step {step_id} has invalid nested JSON"
                ) from exc
        elif isinstance(inner_raw, (dict, list)):
            inner = inner_raw
        else:
            raise RoutineExecutionError(f"Scene {_scene_id(scene)} step {step_id} has invalid param type")

        if not isinstance(inner, dict):
            raise RoutineExecutionError(f"Scene {_scene_id(scene)} step {step_id} payload is not an object")

        method = str(inner.get("method") or "").strip()
        if method not in _SUPPORTED_METHODS:
            raise RoutineExecutionError(f"Scene {_scene_id(scene)} uses unsupported method {method!r}")

        finish_ids = tuple(_as_int(value, 0) for value in (raw_item.get("finishDpIds") or []))
        if any(value <= 0 for value in finish_ids):
            raise RoutineExecutionError(
                f"Scene {_scene_id(scene)} has invalid finishDpIds for method {method!r}"
            )

        steps.append(
            RoutineStep(
                step_id=step_id,
                name=str(raw_item.get("name") or "").strip(),
                method=method,
                params=inner.get("params"),
                finish_dp_ids=finish_ids,
            )
        )
    return steps


def _segment_ids(entry: dict[str, Any]) -> list[int]:
    raw_segments = entry.get("segs")
    if not isinstance(raw_segments, list) or not raw_segments:
        raise RoutineExecutionError("Scene segment step is missing segs[]")
    segment_ids = [
        _as_int(item.get("sid") if isinstance(item, dict) else item, 0)
        for item in raw_segments
    ]
    segment_ids = [segment_id for segment_id in segment_ids if segment_id > 0]
    if not segment_ids:
        raise RoutineExecutionError("Scene segment step did not resolve any valid segment ids")
    return segment_ids


def _zone_ids(entry: dict[str, Any]) -> list[dict[str, int]]:
    raw_zones = entry.get("zones")
    if not isinstance(raw_zones, list) or not raw_zones:
        raise RoutineExecutionError("Scene zone step is missing zones[]")
    zones: list[dict[str, int]] = []
    for raw_zone in raw_zones:
        if not isinstance(raw_zone, dict):
            raise RoutineExecutionError("Scene zone entry is not an object")
        zone_id = _as_int(raw_zone.get("zid"), 0)
        if zone_id < 0:
            raise RoutineExecutionError("Scene zone entry has invalid zid")
        zones.append(
            {
                "zid": zone_id,
                "repeat": max(1, _as_int(raw_zone.get("repeat"), 1)),
            }
        )
    return zones


def _scene_zone_sync_command(entry: dict[str, Any]) -> RoutineCommand | None:
    tid = str(entry.get("tid") or "").strip()
    if not tid:
        return None
    raw_zones = entry.get("zones")
    if not isinstance(raw_zones, list) or not raw_zones:
        return None
    zones_with_ranges: list[dict[str, Any]] = []
    for raw_zone in raw_zones:
        if not isinstance(raw_zone, dict):
            raise RoutineExecutionError("Scene zone entry is not an object")
        range_value = raw_zone.get("range")
        if not isinstance(range_value, list) or len(range_value) < 4:
            continue
        zone_id = _as_int(raw_zone.get("zid"), 0)
        if zone_id < 0:
            raise RoutineExecutionError("Scene zone entry has invalid zid")
        zones_with_ranges.append(
            {
                "zid": zone_id,
                "range": [_as_int(value, 0) for value in range_value[:4]],
            }
        )
    if not zones_with_ranges:
        return None
    return RoutineCommand(
        RoborockCommand.SET_SCENES_ZONES,
        {"data": [{"tid": tid, "zones": zones_with_ranges}]},
    )


def _single_data_entry(step: RoutineStep) -> dict[str, Any]:
    if not isinstance(step.params, dict):
        raise RoutineExecutionError(f"Step {step.step_id} params must be an object")
    data = step.params.get("data")
    if not isinstance(data, list) or not data:
        raise RoutineExecutionError(f"Step {step.step_id} is missing params.data")
    if len(data) != 1:
        raise RoutineExecutionError(f"Step {step.step_id} expected exactly one params.data entry")
    entry = data[0]
    if not isinstance(entry, dict):
        raise RoutineExecutionError(f"Step {step.step_id} params.data[0] is not an object")
    return entry


def _single_start_entry(step: RoutineStep) -> dict[str, Any]:
    if not isinstance(step.params, list) or not step.params:
        raise RoutineExecutionError(f"Step {step.step_id} start params must be a non-empty list")
    entry = step.params[0]
    if not isinstance(entry, dict):
        raise RoutineExecutionError(f"Step {step.step_id} start params[0] is not an object")
    return entry


def _settings_commands(entry: dict[str, Any]) -> list[RoutineCommand]:
    commands: list[RoutineCommand] = []
    if "fan_power" in entry:
        commands.append(
            RoutineCommand(
                RoborockCommand.SET_CUSTOM_MODE,
                [_as_int(entry.get("fan_power"), 0)],
            )
        )
    if "water_box_mode" in entry:
        commands.append(
            RoutineCommand(
                RoborockCommand.SET_WATER_BOX_CUSTOM_MODE,
                [_as_int(entry.get("water_box_mode"), 0)],
            )
        )
    if "mop_mode" in entry:
        commands.append(
            RoutineCommand(
                RoborockCommand.SET_MOP_MODE,
                [_as_int(entry.get("mop_mode"), 0)],
            )
        )
    if "mop_template_id" in entry:
        commands.append(
            RoutineCommand(
                RoborockCommand.SET_MOP_TEMPLATE_ID,
                [_as_int(entry.get("mop_template_id"), 0)],
            )
        )
    return commands


def commands_for_step(step: RoutineStep) -> list[RoutineCommand]:
    if step.method == "do_scenes_segments":
        entry = _single_data_entry(step)
        repeat = max(1, _as_int(entry.get("repeat"), 1))
        return [
            *_settings_commands(entry),
            RoutineCommand(
                RoborockCommand.APP_SEGMENT_CLEAN,
                [{"segments": _segment_ids(entry), "repeat": repeat}],
            ),
        ]
    if step.method == "do_scenes_zones":
        entry = _single_data_entry(step)
        repeat = max(1, _as_int(entry.get("repeat"), 1))
        sync_command = _scene_zone_sync_command(entry)
        return [
            *_settings_commands(entry),
            *([sync_command] if sync_command is not None else []),
            RoutineCommand(
                RoborockCommand.APP_ZONED_CLEAN,
                [{"zones": _zone_ids(entry), "repeat": repeat}],
            ),
        ]
    if step.method == "do_scenes_app_start":
        entry = _single_start_entry(step)
        repeat = max(1, _as_int(entry.get("repeat"), 1))
        return [
            *_settings_commands(entry),
            RoutineCommand(RoborockCommand.SET_CLEAN_REPEAT_TIMES, [repeat]),
            RoutineCommand(RoborockCommand.APP_START, None),
        ]
    raise RoutineExecutionError(f"Unsupported step method {step.method!r}")


def _is_optional_unsupported_command(command: RoborockCommand, exc: Exception) -> bool:
    return command == RoborockCommand.SET_MOP_TEMPLATE_ID and isinstance(exc, RoborockUnsupportedFeature)


def _response_dps(message: RoborockMessage) -> dict[str, Any] | None:
    if message.payload is None:
        return None
    try:
        payload = json.loads(message.payload.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    dps = payload.get("dps")
    return dps if isinstance(dps, dict) else None


def _enum_or_int_value(value: Any) -> int:
    if value is None:
        return -1
    return int(getattr(value, "value", value))


class _RoutineMqttClient:
    def __init__(
        self,
        context: ServerContext,
        device: dict[str, str],
        logger: logging.Logger | logging.LoggerAdapter,
    ) -> None:
        self._context = context
        self._device = device
        self._logger = logger
        self._session = None
        self._unsubscribe = None
        self._pending: dict[int, asyncio.Future[Any]] = {}

        localkey = str(device.get("localkey") or "").strip() or context.localkey
        self._rriot = self._create_rriot(localkey=localkey)
        self._mqtt_params = create_mqtt_params(self._rriot)
        self._security_data = create_security_data(self._rriot)
        self._encoder = create_mqtt_encoder(localkey)
        self._decoder = create_mqtt_decoder(localkey)

        mqtt_username = self._mqtt_params.username
        device_id = str(device.get("duid") or "").strip()
        self._publish_topic = f"rr/m/i/{self._rriot.u}/{mqtt_username}/{device_id}"
        self._response_topic = f"rr/m/o/{self._rriot.u}/{mqtt_username}/{device_id}"

    def _mqtt_backend_port(self) -> int:
        creds = self._context.runtime_credentials
        if creds is None:
            return 18830
        return _as_int(creds.bootstrap_value("mqtt_backend_port", 18830), 18830)

    def _create_rriot(self, *, localkey: str) -> RRiot:
        creds = self._context.runtime_credentials
        api_host = (
            str(creds.bootstrap_value("api_host", "") or "") if creds is not None else self._context.api_host
        ) or self._context.api_host
        wood_host = (
            str(creds.bootstrap_value("wood_host", "") or "") if creds is not None else self._context.wood_host
        ) or self._context.wood_host
        mqtt_usr = (
            str(creds.bootstrap_value("mqtt_usr", "") or "") if creds is not None else self._context.mqtt_usr
        ) or self._context.mqtt_usr
        mqtt_passwd = (
            str(creds.bootstrap_value("mqtt_passwd", "") or "") if creds is not None else self._context.mqtt_passwd
        ) or self._context.mqtt_passwd
        backend_port = self._mqtt_backend_port()

        return RRiot(
            u=mqtt_usr,
            s=mqtt_passwd,
            h=secrets.token_hex(5),
            k=localkey,
            r=Reference(
                r=self._context.region.upper(),
                a=f"https://{api_host}",
                m=f"tcp://127.0.0.1:{backend_port}",
                l=f"https://{wood_host}",
            ),
        )

    async def connect(self) -> None:
        self._session = await create_mqtt_session(self._mqtt_params)
        self._unsubscribe = await self._session.subscribe(self._response_topic, self._on_message)

    async def close(self) -> None:
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None
        if self._session is not None:
            await self._session.close()
            self._session = None

    def _on_message(self, payload: bytes) -> None:
        try:
            messages = self._decoder(payload)
        except Exception as exc:  # noqa: BLE001
            self._logger.warning("Failed to decode routine MQTT payload: %s", exc)
            return

        for message in messages:
            protocol_value = int(getattr(message.protocol, "value", message.protocol))
            if protocol_value != RoborockMessageProtocol.RPC_RESPONSE.value:
                continue
            dps = _response_dps(message)
            if dps is not None and str(RoborockMessageProtocol.RPC_RESPONSE.value) not in dps:
                continue
            try:
                response = decode_rpc_response(message)
            except Exception as exc:  # noqa: BLE001
                self._logger.warning("Failed to decode routine RPC response: %s", exc)
                continue

            future = self._pending.pop(response.request_id, None)
            if future is None or future.done():
                continue
            if response.api_error is not None:
                future.set_exception(response.api_error)
            else:
                future.set_result(response.data)

    async def send_command(
        self,
        command: RoborockCommand,
        params: dict[str, Any] | list[Any] | None = None,
    ) -> Any:
        if self._session is None:
            raise RoutineExecutionError("Routine MQTT client is not connected")

        request = RequestMessage(method=command, params=params)
        future = asyncio.get_running_loop().create_future()
        self._pending[request.request_id] = future
        message = request.encode_message(
            RoborockMessageProtocol.RPC_REQUEST,
            security_data=self._security_data,
        )
        encoded = self._encoder(message)

        try:
            await self._session.publish(self._publish_topic, encoded)
            return await asyncio.wait_for(future, timeout=_COMMAND_TIMEOUT_SECONDS)
        except TimeoutError as exc:
            raise RoutineExecutionError(
                f"Command {command.value} timed out after {_COMMAND_TIMEOUT_SECONDS}s"
            ) from exc
        finally:
            self._pending.pop(request.request_id, None)

    async def get_status(self) -> StatusV2:
        response = await self.send_command(RoborockCommand.GET_STATUS)
        if isinstance(response, list) and response:
            response = response[0]
        if not isinstance(response, dict):
            raise RoutineExecutionError(f"Unexpected get_status response: {response!r}")
        status = StatusV2.from_dict(response)
        if status is None:
            raise RoutineExecutionError(f"Unable to parse get_status response: {response!r}")
        return status

    async def wait_for_step_complete(self) -> None:
        last_observed = None
        loop = asyncio.get_running_loop()
        step_deadline = loop.time() + _STEP_COMPLETE_TIMEOUT_SECONDS
        start_deadline = loop.time() + _STEP_START_TIMEOUT_SECONDS
        saw_activity = False
        saw_cleaning = False

        try:
            while True:
                remaining = step_deadline - loop.time()
                if remaining <= 0:
                    raise TimeoutError

                status = await asyncio.wait_for(self.get_status(), timeout=remaining)
                state = _enum_or_int_value(status.state)
                in_cleaning = _enum_or_int_value(status.in_cleaning)
                observed = (state, in_cleaning)
                if observed != last_observed:
                    self._logger.info(
                        "Routine wait status state=%s in_cleaning=%s",
                        state,
                        in_cleaning,
                    )
                    last_observed = observed

                if in_cleaning != RoborockInCleaning.complete.value:
                    saw_cleaning = True

                is_ready = (
                    in_cleaning == RoborockInCleaning.complete.value
                    and state in _ROUTINE_READY_STATES
                )
                if not is_ready:
                    saw_activity = True
                elif saw_cleaning:
                    return
                elif saw_activity:
                    self._logger.info(
                        "Routine wait: dock activity cycle ended (no cleaning observed), resetting"
                    )
                    saw_activity = False
                    start_deadline = loop.time() + _STEP_START_TIMEOUT_SECONDS

                if not saw_activity and loop.time() >= start_deadline:
                    raise RoutineExecutionError(
                        f"Step did not leave ready state after {_STEP_START_TIMEOUT_SECONDS}s"
                    )

                await asyncio.sleep(
                    _STATUS_POLL_INTERVAL_SECONDS if saw_activity else _STEP_START_POLL_INTERVAL_SECONDS
                )
        except TimeoutError as exc:
            raise RoutineExecutionError(
                f"Timed out waiting for ready state after {_STEP_COMPLETE_TIMEOUT_SECONDS}s"
            ) from exc


    async def wait_for_dock_settle(self) -> None:
        """Wait for automatic dock activities (e.g. bin emptying) to finish
        before sending the next step.

        After a cleaning step completes the robot may start dock maintenance
        (state 22 = emptying bin, state 15 = docking, etc.).  If we send the
        next cleaning command immediately the robot can ACK it but then let the
        dock activity preempt it, effectively dropping the command.

        Strategy: sleep a short grace period, then poll.  If the robot is busy,
        keep polling until it is ready again (with a timeout).
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _POST_STEP_SETTLE_TIMEOUT_SECONDS

        self._logger.info(
            "Post-step settle: waiting %.0fs before checking dock activity",
            _POST_STEP_SETTLE_SECONDS,
        )
        await asyncio.sleep(_POST_STEP_SETTLE_SECONDS)

        last_observed = None
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                self._logger.warning(
                    "Post-step settle: timed out after %.0fs waiting for dock activity to finish",
                    _POST_STEP_SETTLE_TIMEOUT_SECONDS,
                )
                break

            status = await asyncio.wait_for(self.get_status(), timeout=remaining)
            state = _enum_or_int_value(status.state)
            in_cleaning = _enum_or_int_value(status.in_cleaning)
            observed = (state, in_cleaning)

            is_ready = (
                in_cleaning == RoborockInCleaning.complete.value
                and state in _ROUTINE_READY_STATES
            )

            if is_ready:
                self._logger.info("Post-step settle: robot is ready")
                return

            if observed != last_observed:
                self._logger.info(
                    "Post-step settle: robot busy state=%s in_cleaning=%s, waiting",
                    state,
                    in_cleaning,
                )
                last_observed = observed

            await asyncio.sleep(_STATUS_POLL_INTERVAL_SECONDS)


class RoutineRunner:
    def __init__(self, context: ServerContext) -> None:
        self._context = context
        self._tasks_by_device: dict[str, _ActiveRoutine] = {}
        self._logger = (
            context.loggers.get("api")
            or context.loggers.get("unknown")
            or _LOGGER
        )

    def start_scene(self, scene: dict[str, Any]) -> dict[str, Any]:
        device_id = scene_device_id(scene)
        if not device_id:
            raise RoutineExecutionError(f"Scene {_scene_id(scene)} is missing device_id")
        scene_id = _scene_id(scene)
        scene_name = _scene_name(scene)
        steps = parse_scene_steps(scene)
        existing = self._tasks_by_device.get(device_id)
        if existing is not None:
            if existing.task.done():
                self._tasks_by_device.pop(device_id, None)
            elif existing.scene_id == scene_id:
                if not existing.cancel_requested:
                    existing.cancel_requested = True
                    existing.task.cancel()
                    stop_task = asyncio.get_running_loop().create_task(
                        self._stop_scene(
                            device_id=device_id,
                            scene_id=existing.scene_id,
                            scene_name=existing.scene_name,
                        ),
                        name=f"routine-stop-{existing.scene_id}-{device_id}",
                    )
                    stop_task.add_done_callback(
                        lambda finished: self._on_stop_done(
                            device_id=device_id,
                            scene_id=existing.scene_id,
                            task=finished,
                        )
                    )
                return {
                    "accepted": True,
                    "status": "cancel_requested",
                    "sceneId": scene_id,
                    "deviceId": device_id,
                    "sceneName": scene_name,
                }
            else:
                return {
                    "accepted": False,
                    "status": "routine_in_progress",
                    "sceneId": scene_id,
                    "deviceId": device_id,
                    "sceneName": scene_name,
                    "activeSceneId": existing.scene_id,
                    "activeSceneName": existing.scene_name,
                }

        task = asyncio.get_running_loop().create_task(
            self._run_scene(scene=dict(scene), steps=steps),
            name=f"routine-scene-{scene_id}-{device_id}",
        )
        self._tasks_by_device[device_id] = _ActiveRoutine(
            task=task,
            scene_id=scene_id,
            scene_name=scene_name,
        )
        task.add_done_callback(lambda finished: self._on_scene_done(device_id, finished))
        return {
            "accepted": True,
            "status": "started",
            "sceneId": scene_id,
            "deviceId": device_id,
            "sceneName": scene_name,
            "stepCount": len(steps),
        }

    def _on_scene_done(self, device_id: str, task: asyncio.Task[None]) -> None:
        current = self._tasks_by_device.get(device_id)
        if current is not None and current.task is task:
            self._tasks_by_device.pop(device_id, None)
        if task.cancelled():
            if current is not None and current.cancel_requested:
                self._logger.info(
                    "Routine task cancelled after cancel request device=%s scene=%s",
                    device_id,
                    current.scene_name,
                )
            else:
                self._logger.warning("Routine task cancelled for device=%s", device_id)
            return
        exc = task.exception()
        if exc is not None:
            self._logger.error("Routine task failed for device=%s: %s", device_id, exc)

    def _on_stop_done(self, *, device_id: str, scene_id: int, task: asyncio.Task[None]) -> None:
        if task.cancelled():
            self._logger.warning(
                "Routine stop task cancelled for device=%s scene=%s",
                device_id,
                scene_id,
            )
            return
        exc = task.exception()
        if exc is not None:
            self._logger.error(
                "Routine stop task failed for device=%s scene=%s: %s",
                device_id,
                scene_id,
                exc,
            )

    def _device_record(self, device_id: str) -> dict[str, str]:
        creds = self._context.runtime_credentials
        if creds is None:
            return {
                "did": "",
                "duid": device_id,
                "name": device_id,
                "model": "",
                "localkey": self._context.localkey,
            }

        device = creds.device_for_selector(device_id)
        if device is None:
            raise RoutineExecutionError(f"Device {device_id} not found in runtime credentials")
        localkey = str(device.get("localkey") or "").strip()
        if not localkey:
            raise RoutineExecutionError(f"Device {device_id} is missing localkey in runtime credentials")
        return device

    def _inventory_scene_tids(self, *, device_id: str, current_scene: dict[str, Any]) -> list[str]:
        tids: list[str] = []
        seen: set[str] = set()

        def add_scene(candidate: dict[str, Any]) -> None:
            candidate_device_id = scene_device_id(candidate)
            if candidate_device_id and candidate_device_id != device_id:
                return
            for tid in _scene_tid_entries(candidate):
                if tid in seen:
                    continue
                seen.add(tid)
                tids.append(tid)

        inventory_path = self._context.http_jsonl.parent / WEB_API_INVENTORY_FILE
        try:
            parsed = json.loads(inventory_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            parsed = {}

        scenes_value = parsed.get("scenes")
        if isinstance(scenes_value, list):
            for candidate in scenes_value:
                if isinstance(candidate, dict):
                    add_scene(candidate)

        add_scene(current_scene)
        return tids

    async def _sync_scene_tids(
        self,
        *,
        client: _RoutineMqttClient,
        scene: dict[str, Any],
        device_id: str,
        logger: logging.LoggerAdapter,
    ) -> None:
        tids = self._inventory_scene_tids(device_id=device_id, current_scene=scene)
        if not tids:
            return
        logger.info("Syncing routine scenes count=%s device=%s", len(tids), device_id)
        await client.send_command(
            RoborockCommand.REUNION_SCENES,
            {"data": [{"tid": tid} for tid in tids]},
        )

    async def _stop_scene(self, *, device_id: str, scene_id: int, scene_name: str) -> None:
        device = self._device_record(device_id)
        logger = logging.LoggerAdapter(
            self._logger,
            {
                "scene_id": scene_id,
                "scene_name": scene_name,
                "device_id": device_id,
            },
        )
        logger.info("Stopping routine scene=%s device=%s", scene_name, device_id)
        client = _RoutineMqttClient(self._context, device, logger)
        await client.connect()
        try:
            await client.send_command(RoborockCommand.APP_STOP, [])
        finally:
            await client.close()

    async def _run_scene(self, *, scene: dict[str, Any], steps: list[RoutineStep]) -> None:
        device_id = scene_device_id(scene)
        device = self._device_record(device_id)
        logger = logging.LoggerAdapter(
            self._logger,
            {
                "scene_id": _scene_id(scene),
                "scene_name": _scene_name(scene),
                "device_id": device_id,
            },
        )

        logger.info(
            "Starting routine scene=%s steps=%d device=%s",
            _scene_name(scene),
            len(steps),
            device_id,
        )

        client = _RoutineMqttClient(self._context, device, logger)
        await client.connect()
        try:
            await self._sync_scene_tids(client=client, scene=scene, device_id=device_id, logger=logger)
            for step_index, step in enumerate(steps):
                commands = commands_for_step(step)
                waits_for_step_complete = RoborockDataProtocol.TASK_COMPLETE.value in step.finish_dp_ids
                for routine_command in commands:
                    logger.info(
                        "Routine step=%s method=%s command=%s params=%s",
                        step.step_id,
                        step.method,
                        routine_command.command.value,
                        routine_command.params,
                    )
                    try:
                        await client.send_command(routine_command.command, routine_command.params)
                    except RoborockUnsupportedFeature as exc:
                        if not _is_optional_unsupported_command(routine_command.command, exc):
                            raise
                        logger.warning(
                            "Skipping unsupported routine command step=%s method=%s command=%s: %s",
                            step.step_id,
                            step.method,
                            routine_command.command.value,
                            exc,
                        )
                if waits_for_step_complete:
                    logger.info("Waiting for ready state step=%s scene=%s", step.step_id, _scene_name(scene))
                    await client.wait_for_step_complete()
                    if step_index < len(steps) - 1:
                        await client.wait_for_dock_settle()
        finally:
            await client.close()

        logger.info("Completed routine scene=%s device=%s", _scene_name(scene), device_id)
