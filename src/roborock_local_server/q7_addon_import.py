"""One-time, owner-supplied Q7 identity import from the add-on config mount.

Home Assistant mounts ``addon_config`` at /config and the app's persistent
state at /data. A pending file is deliberately explicit and consumed once.
The import replaces only Q7 identity rows; other vacuum state is preserved.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any


SCHEMA = "q7-cloud-identity-import-v1"
MODEL = "roborock.vacuum.sc05"
PENDING_NAME = "q7-current-import.json"
MARKER_NAME = "q7-current-import-applied.json"
HEX_LENGTHS = {"mqtt_clientid": 16, "mqtt_usr": 16, "mqtt_passwd": 32}


def _sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _write_atomic(path: Path, blob: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, staged = tempfile.mkstemp(prefix=".q7-import-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(blob)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staged, path)
    finally:
        if os.path.exists(staged):
            os.unlink(staged)


def _validate(raw: object) -> dict[str, str]:
    required = {"schema", "model", "duid", "local_key", "sn", "fv", *HEX_LENGTHS}
    if not isinstance(raw, dict) or set(raw) != required:
        raise ValueError("Q7 import must contain exactly the required fields")
    values = {key: str(value).strip() for key, value in raw.items()}
    if values["schema"] != SCHEMA or values["model"] != MODEL:
        raise ValueError("Q7 import schema or model does not match")
    if not values["duid"] or not values["sn"] or values["fv"] != "03.01.74":
        raise ValueError("Q7 import identity or firmware is incomplete")
    if len(values["local_key"].encode("ascii")) != 16:
        raise ValueError("Q7 cloud local key must be 16 ASCII bytes")
    for field, size in HEX_LENGTHS.items():
        if not re.fullmatch(rf"[0-9a-f]{{{size}}}", values[field]):
            raise ValueError(f"Q7 {field} must be {size} lower-case hex characters")
    return values


def _updated_payloads(original_inventory: bytes, original_credentials: bytes,
                      values: dict[str, str]) -> tuple[bytes, bytes, dict[str, int]]:
    inventory = json.loads(original_inventory)
    credentials = json.loads(original_credentials)
    if not isinstance(inventory, dict) or not isinstance(inventory.get("devices"), list):
        raise ValueError("Live inventory is not a device list")
    if not isinstance(credentials, dict) or not isinstance(credentials.get("devices"), list):
        raise ValueError("Live credential store is not a device list")

    duid = values["duid"]
    inventory_devices = inventory["devices"]
    old_q7 = [item for item in inventory_devices if isinstance(item, dict) and item.get("model") == MODEL]
    if len(old_q7) > 2:
        raise ValueError("More than two Q7 inventory rows; inspect manually")
    template = dict(old_q7[0]) if old_q7 else {"name": "Q7", "model": MODEL}
    template.update({
        "duid": duid, "local_key": values["local_key"], "sn": values["sn"],
        "fv": values["fv"], "online": False,
    })
    if old_q7:
        first = next(i for i, item in enumerate(inventory_devices) if item is old_q7[0])
        inventory_devices[:] = [item for item in inventory_devices
                                if not (isinstance(item, dict) and item.get("model") == MODEL)]
        inventory_devices.insert(first, template)
    else:
        inventory_devices.append(template)
    for field in ("received_devices", "receivedDevices"):
        items = inventory.get(field)
        if isinstance(items, list):
            items[:] = [item for item in items if not (
                isinstance(item, dict) and item.get("model") == MODEL and item.get("duid") != duid
            )]

    runtime_devices = credentials["devices"]
    old_non_q7 = [item for item in runtime_devices
                  if not (isinstance(item, dict) and item.get("model") == MODEL)]
    current = [item for item in runtime_devices if isinstance(item, dict)
               and item.get("model") == MODEL and item.get("duid") == duid]
    if len(current) > 1:
        raise ValueError("Current Q7 runtime identity is duplicated")
    if any(isinstance(item, dict) and item.get("device_mqtt_usr") == values["mqtt_usr"]
           for item in old_non_q7):
        raise ValueError("Reserved Q7 MQTT username collides with another device")
    q7_record: dict[str, Any] = dict(current[0]) if current else {}
    q7_record.update({
        "did": "", "duid": duid, "name": template.get("name", "Q7"), "model": MODEL,
        "product_id": template.get("product_id", ""),
        "localkey": values["local_key"], "local_key_source": "inventory_cloud",
        "device_mqtt_usr": values["mqtt_usr"],
        "device_mqtt_pass": values["mqtt_passwd"],
        "migration_mqtt_clientid": values["mqtt_clientid"],
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "last_nc_at": "", "last_mqtt_seen_at": "",
    })
    q7_record.pop("migration_did_verified", None)
    credentials["devices"] = old_non_q7 + [q7_record]
    return (
        (json.dumps(inventory, indent=2) + "\n").encode(),
        (json.dumps(credentials, indent=2) + "\n").encode(),
        {"old_inventory_q7": len(old_q7),
         "old_runtime_q7": len(runtime_devices) - len(old_non_q7),
         "non_q7_preserved": len(old_non_q7)},
    )


def apply_pending_q7_import(*, config_dir: Path = Path("/config"),
                            data_dir: Path = Path("/data")) -> dict[str, object] | None:
    pending = config_dir / PENDING_NAME
    if not pending.exists():
        return None
    blob = pending.read_bytes()
    values = _validate(json.loads(blob))
    state_dir = data_dir / "state"
    marker = state_dir / MARKER_NAME
    payload_hash = _sha256(blob)
    if marker.exists():
        previous = json.loads(marker.read_text())
        if previous.get("payload_sha256") == payload_hash:
            pending.unlink()
            return {"already_applied": True}
        raise ValueError("A different Q7 import was already applied")

    runtime_dir = data_dir / "runtime"
    inventory_path = runtime_dir / "web_api_inventory.json"
    credentials_path = runtime_dir / "runtime_credentials.json"
    inventory_before = inventory_path.read_bytes()
    credentials_before = credentials_path.read_bytes()
    inventory_after, credentials_after, counts = _updated_payloads(
        inventory_before, credentials_before, values
    )

    backup_dir = state_dir / "q7-current-import-backup"
    backup_dir.mkdir(parents=True, exist_ok=False)
    _write_atomic(backup_dir / inventory_path.name, inventory_before)
    _write_atomic(backup_dir / credentials_path.name, credentials_before)
    try:
        _write_atomic(inventory_path, inventory_after)
        _write_atomic(credentials_path, credentials_after)
        marker_data = {
            "schema": SCHEMA, "payload_sha256": payload_hash,
            "duid_sha256_12": _sha256(values["duid"].encode())[:12],
            "inventory_before_sha256": _sha256(inventory_before),
            "credentials_before_sha256": _sha256(credentials_before),
            "counts": counts,
        }
        _write_atomic(marker, (json.dumps(marker_data, indent=2) + "\n").encode())
    except Exception:
        _write_atomic(inventory_path, inventory_before)
        _write_atomic(credentials_path, credentials_before)
        raise
    pending.unlink()
    return {"applied": True, "duid_sha256_12": marker_data["duid_sha256_12"], **counts}
