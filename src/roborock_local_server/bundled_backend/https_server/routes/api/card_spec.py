"""Home card specs per product category.

The Android app only shows the scene quick-start tiles of a device when its
category carries a card spec (RRDeviceBeanV2.supportScene() returns false when
CategoryEntity.cardSpec is null). The app reads the JSON field ``cardspec`` of
the category as a string and decodes it as CardSpecV2Data, i.e. the spec
wrapped in ``{"data": {...}}``. The Roborock cloud sends it the same way.

The vacuum spec follows the cloud's /api/v5/product answer (EU, Nov 2026) and
the template bundled with the app (assets/cardSpec/robot.vacuum.cleaner.json).
The state and offline codes that only the bundled template has are kept.

Labels are English only. The cloud and the bundled template carry more than
20 languages.
"""

from __future__ import annotations

import json
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
            _state("Returning to Dock", 6),
            _state("Remote Control", 7, 39),
            _state("Charging", 8),
            _state("Charging Error", 9),
            _state("Pause", 10),
            _state("Error", 12),
            _state("Washing the mop", 13),
            _state("Updating", 14),
            _state("Returning to Dock", 15),
            _state("Pin n Go", 16),
            _state("Emptying", 22),
            _state("Washing the mop", 23),
            _state("Going to wash the mop", 26),
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
            _state("Powered Off Manually", 1),
            # The cloud lists only 34, 51 and 103; the app's bundled template
            # also maps 2, 3 and 4 to these labels.
            _state("Sleep & Powered Off", 2, 34),
            _state("Low Battery & Powered Off", 3, 51),
            _state("Updating & Restarting", 4, 103),
        ],
    },
    "offpeak": {"dps": 133},
}

CATEGORY_CARD_SPECS: dict[str, dict[str, Any]] = {
    "robot.vacuum.cleaner": _ROBOT_VACUUM_CARD_SPEC,
}


def card_spec_for_category(category_name: str) -> str | None:
    """Return the category's ``cardspec`` value as the app expects it.

    That is a JSON string holding ``{"data": <spec>}``, or None when the
    category has no known spec.
    """
    spec = CATEGORY_CARD_SPECS.get(category_name)
    if spec is None:
        return None
    return json.dumps({"data": spec}, ensure_ascii=False, separators=(",", ":"))
