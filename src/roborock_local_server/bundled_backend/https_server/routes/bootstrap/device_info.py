"""Acknowledge signed firmware metadata uploads and update known devices.

The G10S rriot_rr upload callback accepts HTTP 200/201 and ignores the response
body. Its form is RSA PKCS#1 v1.5/SHA-256 signed in the field order below. See
docs/device-info.md for firmware evidence and the limits of this contract.
"""

from __future__ import annotations

import base64
import logging
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from shared.context import ServerContext
from shared.inventory_io import WEB_API_INVENTORY_FILE, inventory_transaction, load_inventory, write_inventory

from .catchall import build as _build_catchall

_PATH = re.compile(r"/devices/([0-9]+)/info/?")
_FIELDS = ("did", "featureset", "newfeatureset", "pid", "sn")
_SAFE_VALUE = re.compile(r"[A-Za-z0-9._-]{1,128}")
_LOGGER = logging.getLogger(__name__)


def match(path: str, method: str = "POST") -> bool:
    return method.upper() == "POST" and _PATH.fullmatch(path) is not None


def _verified_report(
    ctx: ServerContext, params: dict[str, list[str]], did: str
) -> tuple[dict[str, str] | None, str]:
    # Duplicates and extra fields would make reconstructing the signed message
    # ambiguous. Unsupported forms retain the acknowledgement but cannot write.
    if set(params) != {*_FIELDS, "signature"} or any(len(v) != 1 for v in params.values()):
        return None, "malformed_fields"
    fields = {name: params[name][0] for name in _FIELDS}
    if fields["did"] != did:
        return None, "did_mismatch"
    if any(_SAFE_VALUE.fullmatch(v) is None for v in fields.values()):
        return None, "unsupported_values"
    if not fields["featureset"].isdigit() or re.fullmatch(r"[0-9a-fA-F]+", fields["newfeatureset"]) is None:
        return None, "unsupported_values"
    key = ctx.device_public_key(did)
    if key is None:
        return None, "missing_key"
    canonical = "&".join(f"{name}={fields[name]}" for name in _FIELDS)
    try:
        signature = base64.b64decode(params["signature"][0], validate=True)
        key.verify(signature, canonical.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError, TypeError):
        return None, "invalid_signature"
    return fields, "verified"


def build(
    ctx: ServerContext,
    _query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    path_match = _PATH.fullmatch(clean_path)
    assert path_match is not None  # Route matcher already checked the path.
    did = path_match.group(1)
    report, outcome = _verified_report(ctx, body_params, did)
    updated_count = 0
    if report is not None:
        identities = {did}
        if ctx.runtime_credentials is not None:
            device = ctx.runtime_credentials.resolve_device(did=did)
            if device and device.get("duid"):
                identities.add(device["duid"])
        with inventory_transaction(ctx.http_jsonl.parent / WEB_API_INVENTORY_FILE):
            inventory = load_inventory(ctx)
            matched_count = 0
            for collection in ("devices", "received_devices", "receivedDevices"):
                devices = inventory.get(collection)
                if not isinstance(devices, list):
                    continue
                for device in devices:
                    if not isinstance(device, dict):
                        continue
                    if not any(str(device.get(key, "")) in identities for key in ("did", "duid")):
                        continue
                    matched_count += 1
                    update: dict[str, Any] = {
                        "sn": report["sn"],
                        "featureSet": report["featureset"],
                        "newFeatureSet": report["newfeatureset"],
                    }
                    # Inventory readers also accept snake_case fields, with some
                    # readers preferring them. Keep existing aliases consistent.
                    for alias, field in (("feature_set", "featureset"), ("new_feature_set", "newfeatureset")):
                        if alias in device:
                            update[alias] = report[field]
                    if any(device.get(key) != value for key, value in update.items()):
                        device.update(update)
                        updated_count += 1
            outcome = "unchanged" if matched_count else "unmatched"
            if updated_count:
                if write_inventory(ctx, inventory):
                    outcome = "stored"
                else:
                    outcome, updated_count = "write_failed", 0
    _LOGGER.info("Device info did=%s outcome=%s updated=%d", did, outcome, updated_count)
    # No response data is consumed by the verified firmware. Continue accepting
    # unsupported/unverifiable reports without allowing them to alter inventory.
    return _build_catchall(ctx, _query_params, body_params, clean_path)
