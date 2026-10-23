"""Local two-key camera activation.

Some models (Saros 10R, QX Revo Ultra 2) do not enable live view from
``set_homesec_password`` alone. The firmware expects the remote-view app to write
``set_camera_status`` twice — first with the request bit 5, then with bit 12 — and
then a physical Power press on the robot within about a minute. The firmware
clears bit 12 and sets the read-only monitor bit 2, which authorizes
``start_camera_preview``.

Only bits 5 and 12 are added; the firmware truncates/validates anything else, and
writing bit 2 or bit 13 directly is rejected.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import time
from typing import Any

from roborock.roborock_typing import RoborockCommand

#: Read-only "view authorized" bit the firmware sets after a successful press.
MONITOR_BIT = 0x4
#: First and second request bits, in the order the app writes them.
REQUEST_BITS = (0x20, 0x1000)


@dataclass(frozen=True)
class ActivationResult:
    initial_status: int
    final_status: int
    activated: bool


def activation_writes(current_status: int) -> list[int]:
    """Return the ``set_camera_status`` values that arm the two-key request.

    Each write carries the previous one forward: the firmware sees bit 5 on the
    first write and bit 5 plus bit 12 on the second.
    """

    status = current_status
    writes: list[int] = []
    for bit in REQUEST_BITS:
        status |= bit
        writes.append(status)
    return writes


def monitor_enabled(status: int) -> bool:
    """True once the firmware has granted view authorization."""

    return bool(status & MONITOR_BIT)


async def _read_camera_status(client: Any) -> int:
    result = await client.send_command(RoborockCommand.GET_CAMERA_STATUS)
    value = result[0] if isinstance(result, list) and result else result
    return int(value)


async def activate_camera(
    client: Any,
    *,
    timeout_seconds: float = 90.0,
    poll_interval_seconds: float = 1.0,
) -> ActivationResult:
    """Arm the two-key request and wait for the monitor bit.

    The caller must press Power on the robot while this is polling. Returns once
    the robot reports the monitor bit or the timeout expires.
    """

    initial = await _read_camera_status(client)
    if monitor_enabled(initial):
        return ActivationResult(initial_status=initial, final_status=initial, activated=True)

    for value in activation_writes(initial):
        await client.send_command(RoborockCommand.SET_CAMERA_STATUS, [value])

    deadline = time.monotonic() + timeout_seconds
    while True:
        status = await _read_camera_status(client)
        if monitor_enabled(status):
            return ActivationResult(initial_status=initial, final_status=status, activated=True)
        if time.monotonic() >= deadline:
            return ActivationResult(initial_status=initial, final_status=status, activated=False)
        await asyncio.sleep(poll_interval_seconds)
