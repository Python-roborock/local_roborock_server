"""Home card specs (CardSpecV2) per product category.

The Android app only shows the scene quick-start tiles of a device when its
category carries a card spec (RRDeviceBeanV2.supportScene() returns false when
CategoryEntity.cardSpec is null). CardSpecV2 holds four data points directly
as fields - state, extra, battery, offline - each {"dps", "desc", "value"}.
Note that the template bundled with the app wraps these in {"data": {...}};
the API field holds the inner object.

Labels are English only. The app's bundled template carries ~30 languages.
"""

from __future__ import annotations

import copy
from typing import Any


def _state(label: str, *codes: int) -> dict[str, Any]:
    return {"desc": {"en": label}, "value": list(codes)}


_ROBOT_VACUUM_CARD_SPEC: dict[str, Any] = {
    "state": {
        "dps": 121,
        "desc": {"en": "State"},
        "value": [
            _state("Sleeping", 2),
            _state("Ready", 3),
            _state("Cleaning", 5, 11, 17, 18, 102, 103, 104),
            _state("Return to the dock", 6),
            _state("Remote Control", 7, 39),
            _state("Charging", 8),
            _state("Charging error", 9),
            _state("Pause", 10),
            _state("Error", 12),
            _state("Washing the mop", 13),
            _state("Updating", 14),
            _state("Return to the dock", 15),
            _state("Pin n Go", 16),
            _state("Emptying", 22),
            _state("Washing the mop", 23),
            _state("Return to the dock", 26),
            _state("In call", 28),
            _state("Mapping", 29),
            _state("On cruise", 32),
            _state("Reinstalling mop cloth mounts", 33),
            _state("Detaching mop cloth mounts", 34),
            _state("Demo Mode", 36, 37),
            _state("Housework in progress", 38),
            _state("Emergency Stop", 40),
            _state("Positioning", 101),
            _state("Charge Pending", 108),
        ],
    },
    "extra": {"dps": 128},
    "battery": {"dps": 122},
    "offline": {
        "dps": 135,
        "desc": {"en": "Offline State"},
        "value": [
            _state("Manual Shutdown", 1),
            _state("Sleep & Powered Off", 2, 34),
            _state("Low Battery & Powered Off", 3, 51),
            _state("Updating & Restarting", 4, 103),
        ],
    },
}

CATEGORY_CARD_SPECS: dict[str, dict[str, Any]] = {
    "robot.vacuum.cleaner": _ROBOT_VACUUM_CARD_SPEC,
}


def card_spec_for_category(category_name: str) -> dict[str, Any] | None:
    spec = CATEGORY_CARD_SPECS.get(category_name)
    return copy.deepcopy(spec) if spec is not None else None
