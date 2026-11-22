import asyncio
import json
import logging
from pathlib import Path

import pytest

from roborock.data import StatusV2
from roborock.exceptions import RoborockException, RoborockUnsupportedFeature
from roborock_local_server.bundled_backend.shared.context import ServerContext
import roborock_local_server.bundled_backend.shared.routine_runner as routine_runner_module
from roborock_local_server.bundled_backend.shared.routine_runner import RoutineRunner, parse_scene_steps
from roborock.roborock_typing import RoborockCommand


def _test_context(tmp_path: Path) -> ServerContext:
    return ServerContext(
        api_host="api.example.com",
        mqtt_host="mqtt.example.com",
        wood_host="wood.example.com",
        region="us",
        protocol_login_email="user@example.com",
        localkey="local-key",
        duid="default-duid",
        mqtt_usr="mqtt-user",
        mqtt_passwd="mqtt-pass",
        mqtt_clientid="mqtt-client",
        https_port=443,
        mqtt_tls_port=8883,
        http_jsonl=tmp_path / "http.jsonl",
        mqtt_jsonl=tmp_path / "mqtt.jsonl",
        loggers={"api": logging.getLogger("test-routine-runner")},
    )


def _scene(*, scene_id: int, device_id: str, name: str) -> dict[str, object]:
    return {
        "id": scene_id,
        "name": name,
        "device_id": device_id,
        "param": (
            '{"action":{"items":[{"id":1,"type":"CMD","name":"Start",'
            '"finishDpIds":[130],"param":{"method":"do_scenes_app_start","params":[{"repeat":1}]}}]}}'
        ),
    }


def _scene_with_zone_tid(
    *,
    scene_id: int,
    device_id: str,
    name: str,
    tid: str,
    zid: int,
    range_coords: list[int] | None = None,
) -> dict[str, object]:
    zone_payload: dict[str, object] = {"zid": zid, "repeat": 1}
    if range_coords is not None:
        zone_payload["range"] = list(range_coords)
    return {
        "id": scene_id,
        "name": name,
        "device_id": device_id,
        "param": json.dumps(
            {
                "action": {
                    "items": [
                        {
                            "id": 1,
                            "type": "CMD",
                            "name": name,
                            "finishDpIds": [130],
                            "param": json.dumps(
                                {
                                    "method": "do_scenes_zones",
                                    "params": {
                                        "data": [
                                            {
                                                "tid": tid,
                                                "zones": [zone_payload],
                                                "fan_power": 108,
                                                "repeat": 1,
                                            }
                                        ]
                                    },
                                },
                                separators=(",", ":"),
                            ),
                        }
                    ]
                }
            },
            separators=(",", ":"),
        ),
    }


def _force_translated_steps(monkeypatch) -> None:
    """Pin the runner to the translated command path these tests cover."""

    async def no_native(self: RoutineRunner, **_: object) -> bool:
        _ = self
        return False

    monkeypatch.setattr(RoutineRunner, "_start_step_natively", no_native)


def test_repeating_scene_execute_requests_cancel(tmp_path: Path, monkeypatch) -> None:
    async def exercise() -> None:
        runner = RoutineRunner(_test_context(tmp_path))
        started = asyncio.Event()
        hold = asyncio.Event()
        stop_calls: list[tuple[str, int, str]] = []

        async def fake_run_scene(self: RoutineRunner, *, scene: dict[str, object], steps: list[object]) -> None:
            _ = self, scene, steps
            started.set()
            await hold.wait()

        async def fake_stop_scene(
            self: RoutineRunner,
            *,
            device_id: str,
            scene_id: int,
            scene_name: str,
        ) -> None:
            _ = self
            stop_calls.append((device_id, scene_id, scene_name))

        monkeypatch.setattr(RoutineRunner, "_run_scene", fake_run_scene)
        monkeypatch.setattr(RoutineRunner, "_stop_scene", fake_stop_scene)

        scene = _scene(scene_id=4491073, device_id="6HL2zfniaoYYV01CkVuhkO", name="After dinner")

        first = runner.start_scene(scene)
        assert first["accepted"] is True
        assert first["status"] == "started"

        await started.wait()

        second = runner.start_scene(scene)
        assert second["accepted"] is True
        assert second["status"] == "cancel_requested"

        await asyncio.sleep(0)
        await asyncio.sleep(0)

        assert stop_calls == [("6HL2zfniaoYYV01CkVuhkO", 4491073, "After dinner")]

    asyncio.run(exercise())


def test_different_scene_on_busy_device_stays_in_progress(tmp_path: Path, monkeypatch) -> None:
    async def exercise() -> None:
        runner = RoutineRunner(_test_context(tmp_path))
        started = asyncio.Event()
        hold = asyncio.Event()
        stop_calls: list[tuple[str, int, str]] = []

        async def fake_run_scene(self: RoutineRunner, *, scene: dict[str, object], steps: list[object]) -> None:
            _ = self, scene, steps
            started.set()
            await hold.wait()

        async def fake_stop_scene(
            self: RoutineRunner,
            *,
            device_id: str,
            scene_id: int,
            scene_name: str,
        ) -> None:
            _ = self
            stop_calls.append((device_id, scene_id, scene_name))

        monkeypatch.setattr(RoutineRunner, "_run_scene", fake_run_scene)
        monkeypatch.setattr(RoutineRunner, "_stop_scene", fake_stop_scene)

        first_scene = _scene(scene_id=4491073, device_id="6HL2zfniaoYYV01CkVuhkO", name="After dinner")
        second_scene = _scene(scene_id=4491074, device_id="6HL2zfniaoYYV01CkVuhkO", name="Kitchen")

        first = runner.start_scene(first_scene)
        assert first["accepted"] is True
        assert first["status"] == "started"

        await started.wait()

        second = runner.start_scene(second_scene)
        assert second["accepted"] is False
        assert second["status"] == "routine_in_progress"
        assert second["activeSceneId"] == 4491073
        assert second["activeSceneName"] == "After dinner"

        hold.set()
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        assert stop_calls == []

    asyncio.run(exercise())


def test_run_scene_syncs_scene_tids_before_step_commands(tmp_path: Path, monkeypatch) -> None:
    async def exercise() -> None:
        inventory_path = tmp_path / "web_api_inventory.json"
        device_id = "6HL2zfniaoYYV01CkVuhkO"
        current_scene = _scene_with_zone_tid(
            scene_id=4491073,
            device_id=device_id,
            name="After dinner",
            tid="1773791700088",
            zid=8,
            range_coords=[32800, 22750, 34550, 25350],
        )
        inventory_path.write_text(
            json.dumps(
                {
                    "scenes": [
                        _scene_with_zone_tid(
                            scene_id=4491072,
                            device_id=device_id,
                            name="Night living room",
                            tid="1756774254605",
                            zid=5,
                        ),
                        current_scene,
                        _scene_with_zone_tid(
                            scene_id=4499999,
                            device_id="other-device",
                            name="Other device scene",
                            tid="999",
                            zid=1,
                        ),
                    ]
                }
            ),
            encoding="utf-8",
        )

        sent_commands: list[tuple[RoborockCommand, object]] = []

        class FakeRoutineClient:
            def __init__(self, context, device, logger) -> None:
                _ = context, device, logger

            async def connect(self) -> None:
                return None

            async def close(self) -> None:
                return None

            async def send_command(self, command, params=None):
                sent_commands.append((command, params))
                return ["ok"]

            async def wait_for_step_complete(self) -> None:
                return None

        monkeypatch.setattr(routine_runner_module, "_RoutineMqttClient", FakeRoutineClient)
        _force_translated_steps(monkeypatch)

        runner = RoutineRunner(_test_context(tmp_path))
        await runner._run_scene(scene=current_scene, steps=parse_scene_steps(current_scene))

        assert sent_commands[0] == (
            RoborockCommand.REUNION_SCENES,
            {"data": [{"tid": "1756774254605"}, {"tid": "1773791700088"}]},
        )
        assert sent_commands[1] == (RoborockCommand.SET_CUSTOM_MODE, [108])
        assert sent_commands[2] == (
            RoborockCommand.APP_ZONED_CLEAN,
            [[32800, 22750, 34550, 25350, 1]],
        )

    asyncio.run(exercise())


def test_run_scene_sends_repeat_times_as_object_before_app_start(
    tmp_path: Path, monkeypatch
) -> None:
    """The repeat-times setting must precede APP_START in the accepted form.

    Firmware answers the list form with -10007 invalid params. Because the
    command sits immediately before APP_START, a rejection aborts the routine
    and the vacuum never starts, which is why the object form is asserted here.
    """
    async def exercise() -> None:
        device_id = "6HL2zfniaoYYV01CkVuhkO"
        scene = _scene(scene_id=4491073, device_id=device_id, name="Start")

        sent_commands: list[tuple[RoborockCommand, object]] = []

        class FakeRoutineClient:
            def __init__(self, context, device, logger) -> None:
                _ = context, device, logger

            async def connect(self) -> None:
                return None

            async def close(self) -> None:
                return None

            async def send_command(self, command, params=None):
                sent_commands.append((command, params))
                return ["ok"]

            async def wait_for_step_complete(self) -> None:
                return None

        monkeypatch.setattr(routine_runner_module, "_RoutineMqttClient", FakeRoutineClient)
        _force_translated_steps(monkeypatch)

        runner = RoutineRunner(_test_context(tmp_path))
        await runner._run_scene(scene=scene, steps=parse_scene_steps(scene))

        repeat_commands = [
            (command, params)
            for command, params in sent_commands
            if command == RoborockCommand.SET_CLEAN_REPEAT_TIMES
        ]
        assert repeat_commands == [(RoborockCommand.SET_CLEAN_REPEAT_TIMES, {"repeat": 1})]
        assert all(
            not isinstance(params, list)
            for command, params in repeat_commands
        )

        # The setting is useless if APP_START never follows it.
        app_start_index = next(
            index
            for index, (command, _) in enumerate(sent_commands)
            if command == RoborockCommand.APP_START
        )
        repeat_index = next(
            index
            for index, (command, _) in enumerate(sent_commands)
            if command == RoborockCommand.SET_CLEAN_REPEAT_TIMES
        )
        assert repeat_index < app_start_index

    asyncio.run(exercise())


def test_run_scene_retries_step_start_when_device_is_action_locked(tmp_path: Path, monkeypatch) -> None:
    async def exercise() -> None:
        device_id = "6HL2zfniaoYYV01CkVuhkO"
        scene = {
            "id": 4491073,
            "name": "Night clean",
            "device_id": device_id,
            "param": json.dumps(
                {
                    "action": {
                        "items": [
                            {
                                "id": 1,
                                "type": "CMD",
                                "name": "Step 1",
                                "finishDpIds": [130],
                                "param": json.dumps(
                                    {
                                        "method": "do_scenes_segments",
                                        "params": {
                                            "data": [
                                                {
                                                    "tid": "1755507280460",
                                                    "segs": [{"sid": 18}],
                                                    "fan_power": 108,
                                                    "repeat": 1,
                                                }
                                            ]
                                        },
                                    },
                                    separators=(",", ":"),
                                ),
                            },
                            {
                                "id": 2,
                                "type": "CMD",
                                "name": "Step 2",
                                "finishDpIds": [130],
                                "param": json.dumps(
                                    {
                                        "method": "do_scenes_segments",
                                        "params": {
                                            "data": [
                                                {
                                                    "tid": "1755507296636",
                                                    "segs": [{"sid": 19}],
                                                    "fan_power": 103,
                                                    "repeat": 1,
                                                }
                                            ]
                                        },
                                    },
                                    separators=(",", ":"),
                                ),
                            },
                        ]
                    }
                },
                separators=(",", ":"),
            ),
        }

        sent_commands: list[tuple[RoborockCommand, object]] = []
        settle_calls: list[float] = []
        segment_attempts = 0

        class FakeRoutineClient:
            def __init__(self, context, device, logger) -> None:
                _ = context, device, logger

            async def connect(self) -> None:
                return None

            async def close(self) -> None:
                return None

            async def send_command(self, command, params=None):
                nonlocal segment_attempts
                sent_commands.append((command, params))
                if command == RoborockCommand.APP_SEGMENT_CLEAN:
                    segment_attempts += 1
                    if segment_attempts == 2:
                        raise RoborockException({"code": -10003, "message": "action locked"})
                return ["ok"]

            async def wait_for_step_complete(self) -> None:
                return None

            async def wait_for_dock_settle(self, *, initial_delay_seconds=15.0) -> None:
                settle_calls.append(float(initial_delay_seconds))

        monkeypatch.setattr(routine_runner_module, "_RoutineMqttClient", FakeRoutineClient)
        _force_translated_steps(monkeypatch)

        runner = RoutineRunner(_test_context(tmp_path))
        await runner._run_scene(scene=scene, steps=parse_scene_steps(scene))

        assert sent_commands == [
            (
                RoborockCommand.REUNION_SCENES,
                {"data": [{"tid": "1755507280460"}, {"tid": "1755507296636"}]},
            ),
            (RoborockCommand.SET_CUSTOM_MODE, [108]),
            (RoborockCommand.APP_SEGMENT_CLEAN, [{"segments": [18], "repeat": 1}]),
            (RoborockCommand.SET_CUSTOM_MODE, [103]),
            (RoborockCommand.APP_SEGMENT_CLEAN, [{"segments": [19], "repeat": 1}]),
            (RoborockCommand.APP_SEGMENT_CLEAN, [{"segments": [19], "repeat": 1}]),
        ]
        assert settle_calls == [15.0, 5.0]

    asyncio.run(exercise())


# ---------------------------------------------------------------------------
# wait_for_step_complete tests
# ---------------------------------------------------------------------------


class _ScriptedStatusClient:
    """Minimal stand-in for _RoutineMqttClient that replays a status sequence."""

    def __init__(self, status_sequence: list[dict]) -> None:
        self._statuses = [StatusV2.from_dict(s) for s in status_sequence]
        self._index = 0
        self._logger = logging.getLogger("test-wait")
        self.sent_commands: list[tuple[RoborockCommand, list | dict | None]] = []

    async def get_status(self) -> StatusV2:
        if self._index < len(self._statuses):
            status = self._statuses[self._index]
            self._index += 1
            return status
        return self._statuses[-1]

    async def send_command(self, command: RoborockCommand, params=None) -> None:
        self.sent_commands.append((command, params))


_ScriptedStatusClient.wait_for_step_complete = (
    routine_runner_module._RoutineMqttClient.wait_for_step_complete
)
_ScriptedStatusClient.wait_for_dock_settle = (
    routine_runner_module._RoutineMqttClient.wait_for_dock_settle
)


def _set_fast_wait_constants(monkeypatch, *, confirm_seconds: float = 0.0) -> None:
    monkeypatch.setattr(routine_runner_module, "_STEP_COMPLETE_CONFIRM_SECONDS", confirm_seconds)


def test_wait_for_step_complete_dock_activity_does_not_end_step(monkeypatch) -> None:
    """Dock activity (emptying bin) followed by ready must not declare step complete."""
    _set_fast_wait_constants(monkeypatch)
    monkeypatch.setattr(routine_runner_module, "_STEP_START_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(routine_runner_module, "_STEP_START_POLL_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(routine_runner_module, "_STATUS_POLL_INTERVAL_SECONDS", 0.0)

    async def exercise() -> None:
        client = _ScriptedStatusClient([
            {"state": 22, "in_cleaning": 0},  # emptying bin
            {"state": 15, "in_cleaning": 0},  # docking
            {"state": 8, "in_cleaning": 0},   # charging — should NOT end step
            {"state": 8, "in_cleaning": 0},
            {"state": 8, "in_cleaning": 0},
            {"state": 8, "in_cleaning": 0},
            {"state": 8, "in_cleaning": 0},
            {"state": 8, "in_cleaning": 0},
        ])
        with pytest.raises(routine_runner_module.RoutineExecutionError, match="did not leave ready state"):
            await client.wait_for_step_complete()

    asyncio.run(exercise())


def test_wait_for_step_complete_actual_cleaning_completes(monkeypatch) -> None:
    """Step completes when in_cleaning becomes non-zero then robot returns to ready."""
    _set_fast_wait_constants(monkeypatch)
    monkeypatch.setattr(routine_runner_module, "_STEP_START_POLL_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(routine_runner_module, "_STATUS_POLL_INTERVAL_SECONDS", 0.0)

    async def exercise() -> None:
        client = _ScriptedStatusClient([
            {"state": 18, "in_cleaning": 3},  # segment cleaning
            {"state": 18, "in_cleaning": 3},
            {"state": 6, "in_cleaning": 3},   # returning home
            {"state": 8, "in_cleaning": 0},   # charging — step complete
        ])
        await client.wait_for_step_complete()

    asyncio.run(exercise())


def test_wait_for_step_complete_waits_for_ready_after_returning_non_cleaning(monkeypatch) -> None:
    """Returning/dock activity with in_cleaning=0 must not release the next step early."""
    _set_fast_wait_constants(monkeypatch)
    monkeypatch.setattr(routine_runner_module, "_STEP_START_POLL_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(routine_runner_module, "_STATUS_POLL_INTERVAL_SECONDS", 0.0)

    async def exercise() -> None:
        client = _ScriptedStatusClient([
            {"state": 18, "in_cleaning": 3},  # segment cleaning
            {"state": 6, "in_cleaning": 0},   # returning, but not ready
            {"state": 6, "in_cleaning": 0},
            {"state": 8, "in_cleaning": 0},   # charging, possible dock cycle race
            {"state": 22, "in_cleaning": 0},  # emptying bin starts after ready
            {"state": 15, "in_cleaning": 0},  # docking
            {"state": 8, "in_cleaning": 0},   # ready again
            {"state": 8, "in_cleaning": 0},
        ])
        await client.wait_for_step_complete()
        assert client._index >= 8

    asyncio.run(exercise())


def test_wait_for_step_complete_dock_then_cleaning_completes(monkeypatch) -> None:
    """Dock activity followed by actual cleaning should complete after cleaning finishes."""
    _set_fast_wait_constants(monkeypatch)
    monkeypatch.setattr(routine_runner_module, "_STEP_START_POLL_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(routine_runner_module, "_STATUS_POLL_INTERVAL_SECONDS", 0.0)

    async def exercise() -> None:
        client = _ScriptedStatusClient([
            {"state": 22, "in_cleaning": 0},  # emptying bin
            {"state": 15, "in_cleaning": 0},  # docking
            {"state": 8, "in_cleaning": 0},   # charging — dock cycle ends, reset
            {"state": 18, "in_cleaning": 3},  # actual cleaning starts
            {"state": 18, "in_cleaning": 3},
            {"state": 6, "in_cleaning": 3},   # returning home
            {"state": 8, "in_cleaning": 0},   # step complete
        ])
        await client.wait_for_step_complete()

    asyncio.run(exercise())


def test_wait_for_step_complete_start_timeout(monkeypatch) -> None:
    """Raises RoutineExecutionError when robot stays in ready state past start deadline."""
    _set_fast_wait_constants(monkeypatch)
    monkeypatch.setattr(routine_runner_module, "_STEP_START_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(routine_runner_module, "_STEP_START_POLL_INTERVAL_SECONDS", 0.0)

    async def exercise() -> None:
        client = _ScriptedStatusClient([
            {"state": 8, "in_cleaning": 0},
            {"state": 8, "in_cleaning": 0},
            {"state": 8, "in_cleaning": 0},
            {"state": 8, "in_cleaning": 0},
            {"state": 8, "in_cleaning": 0},
            {"state": 8, "in_cleaning": 0},
        ])
        with pytest.raises(routine_runner_module.RoutineExecutionError, match="did not leave ready state"):
            await client.wait_for_step_complete()

    asyncio.run(exercise())


def test_wait_for_step_complete_resume_after_mid_clean_charge(monkeypatch) -> None:
    """Robot returns to dock mid-clean with low battery, charges, gets resumed, completes."""
    _set_fast_wait_constants(monkeypatch)
    monkeypatch.setattr(routine_runner_module, "_STEP_START_POLL_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(routine_runner_module, "_STATUS_POLL_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(routine_runner_module, "_RESUME_BATTERY_THRESHOLD", 80)

    async def exercise() -> None:
        client = _ScriptedStatusClient([
            {"state": 18, "in_cleaning": 3, "battery": 55},  # segment cleaning
            {"state": 26, "in_cleaning": 3, "battery": 30},  # going to wash mop
            {"state": 6, "in_cleaning": 3, "battery": 14},   # returning home (low battery)
            {"state": 8, "in_cleaning": 3, "battery": 14},   # charging mid-clean, too low
            {"state": 8, "in_cleaning": 3, "battery": 50},   # still too low
            {"state": 8, "in_cleaning": 3, "battery": 80},   # threshold reached → resume sent
            {"state": 18, "in_cleaning": 3, "battery": 80},  # cleaning resumes
            {"state": 18, "in_cleaning": 3, "battery": 60},
            {"state": 6, "in_cleaning": 3, "battery": 40},   # returning home
            {"state": 8, "in_cleaning": 0, "battery": 40},   # step complete
        ])
        await client.wait_for_step_complete()
        assert len(client.sent_commands) == 1
        assert client.sent_commands[0] == (RoborockCommand.RESUME_SEGMENT_CLEAN, [])

    asyncio.run(exercise())


def test_wait_for_step_complete_resume_zoned_clean(monkeypatch) -> None:
    """Resume uses correct command for zone cleaning."""
    _set_fast_wait_constants(monkeypatch)
    monkeypatch.setattr(routine_runner_module, "_STEP_START_POLL_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(routine_runner_module, "_STATUS_POLL_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(routine_runner_module, "_RESUME_BATTERY_THRESHOLD", 80)

    async def exercise() -> None:
        client = _ScriptedStatusClient([
            {"state": 18, "in_cleaning": 2, "battery": 50},  # zone cleaning
            {"state": 8, "in_cleaning": 2, "battery": 80},   # charging mid-clean → resume
            {"state": 18, "in_cleaning": 2, "battery": 80},  # resumes
            {"state": 8, "in_cleaning": 0, "battery": 60},   # step complete
        ])
        await client.wait_for_step_complete()
        assert len(client.sent_commands) == 1
        assert client.sent_commands[0] == (RoborockCommand.RESUME_ZONED_CLEAN, [])

    asyncio.run(exercise())


def test_wait_for_step_complete_no_resume_when_battery_low(monkeypatch) -> None:
    """No resume sent while battery is below threshold."""
    _set_fast_wait_constants(monkeypatch)
    monkeypatch.setattr(routine_runner_module, "_STEP_START_POLL_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(routine_runner_module, "_STATUS_POLL_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(routine_runner_module, "_STEP_COMPLETE_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(routine_runner_module, "_RESUME_BATTERY_THRESHOLD", 80)

    async def exercise() -> None:
        client = _ScriptedStatusClient([
            {"state": 18, "in_cleaning": 3, "battery": 50},  # cleaning
            {"state": 8, "in_cleaning": 3, "battery": 14},   # charging, below threshold
            {"state": 8, "in_cleaning": 3, "battery": 50},   # still below
            {"state": 8, "in_cleaning": 3, "battery": 79},   # still below
        ])
        with pytest.raises(routine_runner_module.RoutineExecutionError, match="Timed out"):
            await client.wait_for_step_complete()
        assert len(client.sent_commands) == 0

    asyncio.run(exercise())


def test_wait_for_step_complete_resume_only_sent_once(monkeypatch) -> None:
    """Resume command is only sent once even if robot returns to dock again."""
    _set_fast_wait_constants(monkeypatch)
    monkeypatch.setattr(routine_runner_module, "_STEP_START_POLL_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(routine_runner_module, "_STATUS_POLL_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(routine_runner_module, "_RESUME_BATTERY_THRESHOLD", 80)

    async def exercise() -> None:
        client = _ScriptedStatusClient([
            {"state": 18, "in_cleaning": 3, "battery": 95},  # cleaning
            {"state": 8, "in_cleaning": 3, "battery": 80},   # charging → resume sent
            {"state": 18, "in_cleaning": 3, "battery": 80},  # cleaning resumes
            {"state": 8, "in_cleaning": 3, "battery": 80},   # back to charging again → second resume sent
            {"state": 18, "in_cleaning": 3, "battery": 80},  # cleaning resumes again
            {"state": 8, "in_cleaning": 0, "battery": 60},   # step complete
        ])
        await client.wait_for_step_complete()
        assert len(client.sent_commands) == 2

    asyncio.run(exercise())


def test_wait_for_step_complete_requires_stable_non_cleaning_state(monkeypatch) -> None:
    """A brief non-cleaning status must not end the step if cleaning resumes."""
    monkeypatch.setattr(routine_runner_module, "_STEP_COMPLETE_CONFIRM_SECONDS", 0.02)
    monkeypatch.setattr(routine_runner_module, "_STEP_START_POLL_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(routine_runner_module, "_STATUS_POLL_INTERVAL_SECONDS", 0.01)

    async def exercise() -> None:
        client = _ScriptedStatusClient([
            {"state": 18, "in_cleaning": 3},
            {"state": 8, "in_cleaning": 0},   # transient non-cleaning state
            {"state": 18, "in_cleaning": 3},  # cleaning resumes, so step is not done
            {"state": 18, "in_cleaning": 3},
            {"state": 8, "in_cleaning": 0},
            {"state": 8, "in_cleaning": 0},
            {"state": 8, "in_cleaning": 0},
        ])
        await client.wait_for_step_complete()

    asyncio.run(exercise())


def test_wait_for_dock_settle_timeout_raises(monkeypatch) -> None:
    _set_fast_wait_constants(monkeypatch)
    monkeypatch.setattr(routine_runner_module, "_POST_STEP_SETTLE_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(routine_runner_module, "_STATUS_POLL_INTERVAL_SECONDS", 0.0)

    async def exercise() -> None:
        client = _ScriptedStatusClient([
            {"state": 18, "in_cleaning": 3},
            {"state": 18, "in_cleaning": 3},
            {"state": 18, "in_cleaning": 3},
        ])
        with pytest.raises(routine_runner_module.RoutineExecutionError, match="dock activity"):
            await client.wait_for_dock_settle(initial_delay_seconds=0.0)

    asyncio.run(exercise())


def _app_start_scene(*, scene_id: int, device_id: str, settings: dict[str, object]) -> dict[str, object]:
    return {
        "id": scene_id,
        "name": "Start",
        "device_id": device_id,
        "param": json.dumps(
            {
                "action": {
                    "items": [
                        {
                            "id": 1,
                            "type": "CMD",
                            "name": "Start",
                            "finishDpIds": [130],
                            "param": json.dumps(
                                {"method": "do_scenes_app_start", "params": [{**settings, "repeat": 1}]},
                                separators=(",", ":"),
                            ),
                        }
                    ]
                }
            },
            separators=(",", ":"),
        ),
    }


def test_commands_for_step_skips_unset_settings() -> None:
    """-1 marks a setting the user did not configure; it must not be sent."""
    scene = _app_start_scene(
        scene_id=1001,
        device_id="device-a",
        settings={"fan_power": 104, "water_box_mode": 200, "mop_mode": -1, "mop_template_id": -1},
    )
    [step] = parse_scene_steps(scene)

    commands = routine_runner_module.commands_for_step(step)

    assert [(command.command, command.params) for command in commands] == [
        (RoborockCommand.SET_CUSTOM_MODE, [104]),
        (RoborockCommand.SET_WATER_BOX_CUSTOM_MODE, [200]),
        (RoborockCommand.SET_CLEAN_REPEAT_TIMES, {"repeat": 1}),
        (RoborockCommand.APP_START, None),
    ]


def test_run_scene_with_unset_mop_mode_reaches_app_start(tmp_path: Path, monkeypatch) -> None:
    async def exercise() -> None:
        scene = _app_start_scene(
            scene_id=1002,
            device_id="device-a",
            settings={"fan_power": 104, "water_box_mode": 200, "mop_mode": -1},
        )
        sent_commands: list[tuple[RoborockCommand, object]] = []

        class FakeRoutineClient:
            def __init__(self, context, device, logger) -> None:
                _ = context, device, logger

            async def connect(self) -> None:
                return None

            async def close(self) -> None:
                return None

            async def send_command(self, command, params=None):
                # Firmware rejects out-of-range settings such as [-1].
                if params == [-1]:
                    raise RoborockException({"code": -10007, "message": "invalid params"})
                sent_commands.append((command, params))
                return ["ok"]

            async def wait_for_step_complete(self) -> None:
                return None

        monkeypatch.setattr(routine_runner_module, "_RoutineMqttClient", FakeRoutineClient)
        _force_translated_steps(monkeypatch)

        runner = RoutineRunner(_test_context(tmp_path))
        await runner._run_scene(scene=scene, steps=parse_scene_steps(scene))

        assert RoborockCommand.SET_MOP_MODE not in [command for command, _ in sent_commands]
        assert sent_commands[-1] == (RoborockCommand.APP_START, None)

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "unsupported_command",
    [
        RoborockCommand.SET_MOP_MODE,
        RoborockCommand.SET_MOP_TEMPLATE_ID,
        RoborockCommand.SET_CLEAN_REPEAT_TIMES,
    ],
)
def test_run_scene_skips_unsupported_setting_and_still_starts(
    tmp_path: Path, monkeypatch, unsupported_command: RoborockCommand
) -> None:
    async def exercise() -> None:
        scene = _app_start_scene(
            scene_id=1003,
            device_id="device-a",
            settings={"fan_power": 104, "mop_mode": 300, "mop_template_id": 1},
        )
        sent_commands: list[RoborockCommand] = []

        class FakeRoutineClient:
            def __init__(self, context, device, logger) -> None:
                _ = context, device, logger

            async def connect(self) -> None:
                return None

            async def close(self) -> None:
                return None

            async def send_command(self, command, params=None):
                if command == unsupported_command:
                    raise RoborockUnsupportedFeature("The method called is not recognized by the device.")
                sent_commands.append(command)
                return ["ok"]

            async def wait_for_step_complete(self) -> None:
                return None

        monkeypatch.setattr(routine_runner_module, "_RoutineMqttClient", FakeRoutineClient)
        _force_translated_steps(monkeypatch)

        runner = RoutineRunner(_test_context(tmp_path))
        await runner._run_scene(scene=scene, steps=parse_scene_steps(scene))

        assert unsupported_command not in sent_commands
        assert sent_commands[-1] == RoborockCommand.APP_START

    asyncio.run(exercise())


def test_run_scene_aborts_when_start_command_is_unsupported(tmp_path: Path, monkeypatch) -> None:
    async def exercise() -> None:
        scene = _app_start_scene(scene_id=1004, device_id="device-a", settings={"fan_power": 104})

        class FakeRoutineClient:
            def __init__(self, context, device, logger) -> None:
                _ = context, device, logger

            async def connect(self) -> None:
                return None

            async def close(self) -> None:
                return None

            async def send_command(self, command, params=None):
                if command == RoborockCommand.APP_START:
                    raise RoborockUnsupportedFeature("The method called is not recognized by the device.")
                return ["ok"]

            async def wait_for_step_complete(self) -> None:
                return None

        monkeypatch.setattr(routine_runner_module, "_RoutineMqttClient", FakeRoutineClient)
        _force_translated_steps(monkeypatch)

        runner = RoutineRunner(_test_context(tmp_path))
        with pytest.raises(RoborockUnsupportedFeature):
            await runner._run_scene(scene=scene, steps=parse_scene_steps(scene))

    asyncio.run(exercise())


# ---------------------------------------------------------------------------
# native do_scenes_* step tests
# ---------------------------------------------------------------------------


def _customize_segment_scene(device_id: str) -> dict[str, object]:
    step_params = {
        "data": [
            {
                "tid": "1795105757294",
                "segs": [{"sid": 1}],
                "map_flag": 0,
                "fan_power": 106,
                "water_box_mode": 204,
                "mop_mode": 302,
                "mop_template_id": 302,
                "repeat": 1,
                "clean_order_mode": 1,
                "new_segments": [
                    {
                        "id": 1,
                        "repeat": 1,
                        "need_wash": 1,
                        "wash_mode": 2,
                        "fan_power": 105,
                        "water_box_mode": 245,
                        "mop_mode": 303,
                        "seq_type": 0,
                    }
                ],
                "auto_dry": 1,
                "auto_dustCollection": 1,
                "region_num": 1,
                "seq_type": 0,
            }
        ],
        "source": 101,
    }
    item = {
        "id": 1,
        "type": "CMD",
        "name": "Kitchen",
        "finishDpIds": [130],
        "param": json.dumps({"id": 1, "method": "do_scenes_segments", "params": step_params}),
    }
    return {
        "id": 1,
        "name": "Kitchen mop",
        "device_id": device_id,
        "param": json.dumps({"action": {"type": "S", "items": [item, dict(item, id=2)]}}),
    }


class _RecordingClient:
    """Fake _RoutineMqttClient: records commands, answers with a scripted error per method."""

    sent: list[tuple[object, object]] = []
    errors: dict[str, Exception] = {}

    def __init__(self, context, device, logger) -> None:
        _ = context, device, logger

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def send_command(self, command, params=None):
        type(self).sent.append((command, params))
        name = command.value if isinstance(command, RoborockCommand) else command
        error = type(self).errors.get(name)
        if error is not None:
            raise error
        return ["ok"]

    async def wait_for_step_complete(self) -> None:
        return None

    async def wait_for_dock_settle(self, *, initial_delay_seconds: float = 15.0) -> None:
        _ = initial_delay_seconds


def _recording_client(monkeypatch, errors: dict[str, Exception] | None = None) -> type[_RecordingClient]:
    client = type("RecordingClient", (_RecordingClient,), {"sent": [], "errors": dict(errors or {})})
    monkeypatch.setattr(routine_runner_module, "_RoutineMqttClient", client)
    return client


def test_run_scene_sends_customize_step_natively(tmp_path: Path, monkeypatch) -> None:
    """Per-room customize settings (new_segments) reach the device unchanged."""
    client = _recording_client(monkeypatch)
    scene = _customize_segment_scene("6HL2zfniaoYYV01CkVuhkO")
    steps = parse_scene_steps(scene)

    asyncio.run(RoutineRunner(_test_context(tmp_path))._run_scene(scene=scene, steps=steps))

    assert client.sent[0][0] == RoborockCommand.REUNION_SCENES
    assert client.sent[1:] == [("do_scenes_segments", steps[0].params), ("do_scenes_segments", steps[1].params)]
    assert client.sent[1][1]["data"][0]["new_segments"][0]["fan_power"] == 105


def test_native_zone_step_drops_hydrated_ranges(tmp_path: Path, monkeypatch) -> None:
    client = _recording_client(monkeypatch)
    scene = _scene_with_zone_tid(
        scene_id=7,
        device_id="6HL2zfniaoYYV01CkVuhkO",
        name="Zone",
        tid="1795108470001",
        zid=1,
        range_coords=[23100, 21400, 24600, 22900],
    )
    steps = parse_scene_steps(scene)

    asyncio.run(RoutineRunner(_test_context(tmp_path))._run_scene(scene=scene, steps=steps))

    assert client.sent[1] == (
        "do_scenes_zones",
        {"data": [{"tid": "1795108470001", "zones": [{"zid": 1, "repeat": 1}], "fan_power": 108, "repeat": 1}]},
    )
    # The stored step keeps its range for the translated fallback.
    assert steps[0].params["data"][0]["zones"][0]["range"] == [23100, 21400, 24600, 22900]


def test_unknown_native_method_falls_back_and_is_remembered(tmp_path: Path, monkeypatch) -> None:
    client = _recording_client(
        monkeypatch,
        {"do_scenes_segments": RoborockUnsupportedFeature("The method called is not recognized by the device.")},
    )
    scene = _customize_segment_scene("6HL2zfniaoYYV01CkVuhkO")
    runner = RoutineRunner(_test_context(tmp_path))

    asyncio.run(runner._run_scene(scene=scene, steps=parse_scene_steps(scene)))
    native_attempts = [c for c, _ in client.sent if c == "do_scenes_segments"]
    segment_cleans = [p for c, p in client.sent if c == RoborockCommand.APP_SEGMENT_CLEAN]
    assert len(native_attempts) == 1
    assert segment_cleans == [[{"segments": [1], "repeat": 1}]] * 2

    client.sent.clear()
    asyncio.run(runner._run_scene(scene=scene, steps=parse_scene_steps(scene)))
    assert all(c != "do_scenes_segments" for c, _ in client.sent)


def test_rejected_native_step_falls_back_for_that_step_only(tmp_path: Path, monkeypatch) -> None:
    client = _recording_client(
        monkeypatch,
        {"do_scenes_segments": RoborockException({"code": -10005, "message": "param error"})},
    )
    scene = _customize_segment_scene("6HL2zfniaoYYV01CkVuhkO")

    asyncio.run(RoutineRunner(_test_context(tmp_path))._run_scene(scene=scene, steps=parse_scene_steps(scene)))

    native_attempts = [c for c, _ in client.sent if c == "do_scenes_segments"]
    segment_cleans = [p for c, p in client.sent if c == RoborockCommand.APP_SEGMENT_CLEAN]
    assert len(native_attempts) == 2
    assert len(segment_cleans) == 2


def test_native_step_is_retried_when_action_locked(tmp_path: Path, monkeypatch) -> None:
    attempts = 0

    class LockedOnce(_RecordingClient):
        sent: list[tuple[object, object]] = []
        errors: dict[str, Exception] = {}

        async def send_command(self, command, params=None):
            nonlocal attempts
            if command == "do_scenes_segments":
                attempts += 1
                if attempts == 1:
                    type(self).sent.append((command, params))
                    raise RoborockException({"code": -10003, "message": "action locked"})
            return await super().send_command(command, params)

    monkeypatch.setattr(routine_runner_module, "_RoutineMqttClient", LockedOnce)
    scene = _customize_segment_scene("6HL2zfniaoYYV01CkVuhkO")

    asyncio.run(RoutineRunner(_test_context(tmp_path))._run_scene(scene=scene, steps=parse_scene_steps(scene)))

    assert [c for c, _ in LockedOnce.sent if c == "do_scenes_segments"] == ["do_scenes_segments"] * 3
    assert all(c != RoborockCommand.APP_SEGMENT_CLEAN for c, _ in LockedOnce.sent)
