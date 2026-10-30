from __future__ import annotations

from typing import Any

from shared.context import ServerContext
from shared.data_helpers import get_value

from ...auth.service import ok
from ...user.homes.service import home_payload

# Agreement types reported per device in userPluginAgreementList. The Android
# app keeps this list as raw JSON and reads each entry's "type" as a string
# (JsonPrimitive.content) before handing it to the device plugin; the plugin
# bundle and the app's AgreementInfo bean use the string constants
# USER_AGREEMENT and PRIVACY_POLICY for agreement types.
PLUGIN_AGREEMENT_TYPES = ("USER_AGREEMENT", "PRIVACY_POLICY")
PLUGIN_AGREEMENT_VERSION = 1


def match_check_app_agreement(path: str) -> bool:
    return path.rstrip("/") == "/api/v1/checkAppAgreement"


def _home_device_ids(ctx: ServerContext) -> list[str]:
    devices_value = home_payload(ctx).get("devices")
    devices = devices_value if isinstance(devices_value, list) else []
    device_ids: list[str] = []
    for device in devices:
        if not isinstance(device, dict):
            continue
        duid = str(get_value(device, "duid", "did", default="")).strip()
        if duid and duid not in device_ids:
            device_ids.append(duid)
    return device_ids


def plugin_agreements(ctx: ServerContext) -> list[dict[str, Any]]:
    """One accepted plugin agreement per agreement type and home device.

    Entry shape follows the Android app's UserPreferenceRepository:
    {"deviceId": <duid>, "type": <str>, "version": <int>, "extra": <str>}.
    """
    return [
        {
            "deviceId": duid,
            "type": agreement_type,
            "version": PLUGIN_AGREEMENT_VERSION,
            "extra": "",
        }
        for duid in _home_device_ids(ctx)
        for agreement_type in PLUGIN_AGREEMENT_TYPES
    ]


def build_check_app_agreement(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    _body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    # UserAgreementInfoV1. Every field has a default in the app, so the generic
    # catch-all payload deserializes silently into "nothing agreed" and the
    # device plugin stops after getPluginAgreements ("no data <duid>").
    return ok(
        {
            "userAndPrivacyAgree": True,
            "improvementPlanAgree": True,
            "recommendationAgree": True,
            "userPluginAgreementList": plugin_agreements(ctx),
        }
    )
