"""Tests for the local two-key camera activation helper.

Models such as the Saros 10R and QX Revo Ultra 2 only enable remote viewing after
``set_camera_status`` is written with the two request bits (bit 5, then bit 12) and
the Power button is pressed on the robot. These tests pin the bit arithmetic and
the "did the monitor bit appear" poll loop without touching MQTT.
"""

from __future__ import annotations

import asyncio

from roborock.roborock_typing import RoborockCommand

from roborock_local_server.camera import (
    activate_camera,
    activation_writes,
    monitor_enabled,
)


class _FakeCameraClient:
    """Records ``set_camera_status`` writes and replays ``get_camera_status`` reads."""

    def __init__(self, statuses: list[int]) -> None:
        self._statuses = list(statuses)
        self.writes: list[object] = []

    async def send_command(self, command: RoborockCommand, params: object = None) -> list[object]:
        if command == RoborockCommand.GET_CAMERA_STATUS:
            value = self._statuses.pop(0) if len(self._statuses) > 1 else self._statuses[0]
            return [value]
        self.writes.append(params)
        return ["ok"]


def test_activation_writes_arm_the_request_bits_in_order() -> None:
    assert activation_writes(385) == [417, 4513]


def test_activation_writes_keep_bits_that_are_already_set() -> None:
    assert activation_writes(419) == [419, 4515]


def test_monitor_enabled_reads_the_view_authorization_bit() -> None:
    assert monitor_enabled(8613)
    assert not monitor_enabled(4513)
    assert not monitor_enabled(417)


def test_already_activated_robot_is_not_rewritten() -> None:
    client = _FakeCameraClient([8613])

    result = asyncio.run(activate_camera(client, timeout_seconds=0.05))

    assert result.activated
    assert result.initial_status == 8613
    assert client.writes == []


def test_activation_succeeds_when_the_robot_sets_the_monitor_bit() -> None:
    client = _FakeCameraClient([417, 4513, 8613])

    result = asyncio.run(activate_camera(client, timeout_seconds=1.0, poll_interval_seconds=0.01))

    assert result.activated
    assert result.initial_status == 417
    assert result.final_status == 8613
    assert client.writes == [[417], [4513]]


def test_activation_reports_timeout_when_power_is_not_pressed() -> None:
    client = _FakeCameraClient([417])

    result = asyncio.run(activate_camera(client, timeout_seconds=0.05, poll_interval_seconds=0.01))

    assert not result.activated
    assert result.initial_status == 417
    assert result.final_status == 417
    assert client.writes == [[417], [4513]]


def test_cli_exposes_camera_activate() -> None:
    # Importing the backend bridge puts the bundled_backend dir on sys.path.
    import roborock_local_server.backend as backend  # noqa: F401

    from roborock_local_server.server import build_arg_parser

    args = build_arg_parser().parse_args(
        ["camera-activate", "--config", "config.toml", "--duid", "1103842126955", "--timeout", "30"]
    )

    assert args.command == "camera-activate"
    assert args.duid == "1103842126955"
    assert args.timeout == 30
