"""Persistent runtime credentials with per-device local keys."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import threading
from typing import Any
from urllib.parse import parse_qs

from .data_helpers import utcnow_iso


def _clean_str(value: Any) -> str:
    return str(value or "").strip()


def _pick_newer_iso(first: str, second: str) -> str:
    if not first:
        return second
    if not second:
        return first
    try:
        first_dt = datetime.fromisoformat(first.replace("Z", "+00:00"))
    except ValueError:
        return second
    try:
        second_dt = datetime.fromisoformat(second.replace("Z", "+00:00"))
    except ValueError:
        return first
    return first if first_dt >= second_dt else second


def _load_json(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _extract_pid_from_key_state_item(item: dict[str, Any]) -> str:
    direct_pid = _clean_str(item.get("pid") or item.get("model"))
    if direct_pid:
        return direct_pid

    def _extract_from_query(query: str) -> str:
        parsed = parse_qs(query, keep_blank_values=True)
        for key in ("pid", "m", "model"):
            values = parsed.get(key) or []
            for value in values:
                candidate = _clean_str(value)
                if candidate:
                    return candidate
        return ""

    for sample_key in ("samples", "header_samples"):
        sample_list = item.get(sample_key)
        if not isinstance(sample_list, list):
            continue
        for sample in sample_list:
            if not isinstance(sample, dict):
                continue
            for source_key in ("canonical", "query"):
                raw = sample.get(source_key)
                if not isinstance(raw, str) or not raw:
                    continue
                found = _extract_from_query(raw)
                if found:
                    return found
    return ""


def _decode_remaining_length(data: bytes, start: int) -> tuple[int | None, int]:
    multiplier = 1
    value = 0
    consumed = 0
    idx = start
    while idx < len(data):
        byte_val = data[idx]
        consumed += 1
        value += (byte_val & 0x7F) * multiplier
        if (byte_val & 0x80) == 0:
            return value, consumed
        multiplier *= 128
        idx += 1
        if consumed >= 4:
            break
    return None, 0


def _decode_mqtt_string(packet: bytes, cursor: int) -> tuple[str | None, int]:
    if cursor + 2 > len(packet):
        return None, cursor
    length = int.from_bytes(packet[cursor : cursor + 2], "big")
    start = cursor + 2
    end = start + length
    if end > len(packet):
        return None, cursor
    return packet[start:end].decode("utf-8", errors="replace"), end


def _decode_mqtt_binary(packet: bytes, cursor: int) -> tuple[bytes | None, int]:
    if cursor + 2 > len(packet):
        return None, cursor
    length = int.from_bytes(packet[cursor : cursor + 2], "big")
    start = cursor + 2
    end = start + length
    if end > len(packet):
        return None, cursor
    return packet[start:end], end


def parse_mqtt_connect_packet(packet: bytes) -> dict[str, Any] | None:
    if not packet or (packet[0] >> 4) != 1:
        return None
    remaining_len, remaining_len_bytes = _decode_remaining_length(packet, 1)
    if remaining_len is None or remaining_len_bytes == 0:
        return None
    cursor = 1 + remaining_len_bytes
    protocol_name, cursor = _decode_mqtt_string(packet, cursor)
    if protocol_name is None or cursor + 4 > len(packet):
        return None
    protocol_level = packet[cursor]
    connect_flags = packet[cursor + 1]
    cursor += 4
    if protocol_level == 5:
        property_len, property_len_bytes = _decode_remaining_length(packet, cursor)
        if property_len is None or property_len_bytes == 0:
            return None
        cursor += property_len_bytes + property_len
    client_id, cursor = _decode_mqtt_string(packet, cursor)
    if client_id is None:
        return None

    will_flag = (connect_flags & 0x04) != 0
    username_flag = (connect_flags & 0x80) != 0
    password_flag = (connect_flags & 0x40) != 0
    if will_flag:
        if protocol_level == 5:
            property_len, property_len_bytes = _decode_remaining_length(packet, cursor)
            if property_len is None or property_len_bytes == 0:
                return None
            cursor += property_len_bytes + property_len
        _, cursor = _decode_mqtt_string(packet, cursor)
        _, cursor = _decode_mqtt_binary(packet, cursor)
        if cursor > len(packet):
            return None

    username = ""
    password = ""
    if username_flag:
        decoded_username, cursor = _decode_mqtt_string(packet, cursor)
        if decoded_username is None:
            return None
        username = decoded_username
    if password_flag:
        decoded_password, cursor = _decode_mqtt_binary(packet, cursor)
        if decoded_password is None:
            return None
        password = decoded_password.decode("utf-8", errors="replace")

    return {
        "protocol_name": protocol_name,
        "protocol_level": protocol_level,
        "client_id": client_id,
        "username": username,
        "password": password,
    }


class RuntimeCredentialsStore:
    """Persists stack credentials and per-device onboarding keys."""

    _BASE_KEYS = (
        "api_host",
        "mqtt_host",
        "wood_host",
        "region",
        "localkey",
        "duid",
        "mqtt_usr",
        "mqtt_passwd",
        "mqtt_clientid",
        "https_port",
        "mqtt_tls_port",
        "mqtt_backend_port",
    )

    def __init__(
        self,
        path: str | Path,
        *,
        inventory_path: str | Path | None = None,
        key_state_file: str | Path | None = None,
    ) -> None:
        self.path = Path(path)
        self.inventory_path = Path(inventory_path) if inventory_path is not None else None
        self.key_state_file = Path(key_state_file) if key_state_file is not None else None

        self._lock = threading.RLock()
        self._base: dict[str, Any] = {"schema_version": 2}
        self._devices: list[dict[str, str]] = []

        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        parsed = _load_json(self.path)
        for key in self._BASE_KEYS:
            if key in parsed:
                self._base[key] = parsed[key]

        raw_devices = parsed.get("devices")
        if isinstance(raw_devices, dict):
            raw_items = list(raw_devices.values())
        elif isinstance(raw_devices, list):
            raw_items = raw_devices
        else:
            raw_items = []

        loaded: list[dict[str, str]] = []
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            normalized = self._normalize_device(raw)
            if normalized:
                loaded.append(normalized)
        self._devices = loaded

    @staticmethod
    def _normalize_device(raw: dict[str, Any]) -> dict[str, str]:
        did = _clean_str(raw.get("did"))
        duid = _clean_str(raw.get("duid") or raw.get("device_id"))
        if not did and not duid:
            return {}
        device = {
            "did": did,
            "duid": duid,
            "name": _clean_str(raw.get("name")),
            "model": _clean_str(raw.get("model")),
            "product_id": _clean_str(raw.get("product_id") or raw.get("productId")),
            "localkey": _clean_str(raw.get("localkey") or raw.get("local_key") or raw.get("localKey") or raw.get("k")),
            "local_key_source": _clean_str(raw.get("local_key_source") or raw.get("source")),
            "device_mqtt_usr": _clean_str(raw.get("device_mqtt_usr") or raw.get("mqtt_usr")),
            "device_mqtt_pass": _clean_str(raw.get("device_mqtt_pass") or raw.get("mqtt_pass") or raw.get("mqtt_password")),
            "updated_at": _clean_str(raw.get("updated_at")),
            "last_nc_at": _clean_str(raw.get("last_nc_at")),
            "last_mqtt_seen_at": _clean_str(raw.get("last_mqtt_seen_at")),
        }
        return device

    def _save_locked(self) -> None:
        payload = dict(self._base)
        payload["schema_version"] = 2
        payload["updated_at"] = utcnow_iso()
        payload["devices"] = self.devices()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def bootstrap_value(self, key: str, default: Any = "") -> Any:
        with self._lock:
            return self._base.get(key, default)

    def update_base(self, **kwargs: Any) -> None:
        with self._lock:
            changed = False
            for key in self._BASE_KEYS:
                if key not in kwargs:
                    continue
                value = kwargs[key]
                if self._base.get(key) == value:
                    continue
                self._base[key] = value
                changed = True
            if changed:
                self._save_locked()

    def devices(self) -> list[dict[str, str]]:
        with self._lock:
            devices = [dict(device) for device in self._devices]
        devices.sort(key=lambda item: (item.get("name") or "", item.get("duid") or item.get("did") or ""))
        return devices

    def _bootstrap_device_locked(self) -> dict[str, str] | None:
        duid = _clean_str(self._base.get("duid"))
        localkey = _clean_str(self._base.get("localkey"))
        if not duid and not localkey:
            return None
        return {
            "did": "",
            "duid": duid,
            "name": "",
            "model": "",
            "product_id": "",
            "localkey": localkey,
            "local_key_source": "bootstrap",
            "device_mqtt_usr": "",
            "device_mqtt_pass": "",
            "updated_at": "",
            "last_nc_at": "",
            "last_mqtt_seen_at": "",
        }

    def _find_index_by_did_locked(self, did: str) -> int | None:
        normalized_did = _clean_str(did)
        if not normalized_did:
            return None
        for index, device in enumerate(self._devices):
            if device.get("did") == normalized_did:
                return index
        return None

    def _find_index_by_duid_locked(self, duid: str) -> int | None:
        normalized_duid = _clean_str(duid)
        if not normalized_duid:
            return None
        for index, device in enumerate(self._devices):
            if device.get("duid") == normalized_duid:
                return index
        return None

    def _find_unique_model_index_locked(self, model: str) -> int | None:
        normalized_model = _clean_str(model).lower()
        if not normalized_model:
            return None
        matches = [
            index
            for index, device in enumerate(self._devices)
            if _clean_str(device.get("model")).lower() == normalized_model
        ]
        if len(matches) == 1:
            return matches[0]
        return None

    def _find_index_locked(self, *, did: str = "", duid: str = "", model: str = "") -> int | None:
        did_index = self._find_index_by_did_locked(did)
        if did_index is not None:
            return did_index
        duid_index = self._find_index_by_duid_locked(duid)
        if duid_index is not None:
            return duid_index
        if _clean_str(duid):
            return None
        return self._find_unique_model_index_locked(model)

    def _merge_device_records_locked(self, primary_index: int, secondary_index: int) -> tuple[dict[str, str], bool]:
        if primary_index == secondary_index:
            return self._devices[primary_index], False
        primary = self._devices[primary_index]
        secondary = self._devices[secondary_index]
        changed = False

        for key in (
            "did",
            "duid",
            "name",
            "model",
            "product_id",
            "localkey",
            "local_key_source",
            "device_mqtt_usr",
            "device_mqtt_pass",
        ):
            if primary.get(key) or not secondary.get(key):
                continue
            primary[key] = secondary[key]
            changed = True

        for key in ("last_nc_at", "last_mqtt_seen_at", "updated_at"):
            merged_value = _pick_newer_iso(
                _clean_str(primary.get(key)),
                _clean_str(secondary.get(key)),
            )
            if merged_value and primary.get(key) != merged_value:
                primary[key] = merged_value
                changed = True

        self._devices.pop(secondary_index)
        return primary, True

    @staticmethod
    def _generate_localkey() -> str:
        return secrets.token_hex(8)

    def ensure_device(
        self,
        *,
        did: str = "",
        duid: str = "",
        name: str = "",
        model: str = "",
        product_id: str = "",
        localkey: str = "",
        local_key_source: str = "",
        device_mqtt_usr: str = "",
        device_mqtt_pass: str = "",
        last_nc_at: str = "",
        last_mqtt_seen_at: str = "",
        assign_localkey: bool = False,
    ) -> dict[str, str]:
        normalized_did = _clean_str(did)
        normalized_duid = _clean_str(duid)
        normalized_name = _clean_str(name)
        normalized_model = _clean_str(model)
        normalized_product_id = _clean_str(product_id)
        normalized_localkey = _clean_str(localkey)
        normalized_source = _clean_str(local_key_source)
        normalized_device_mqtt_usr = _clean_str(device_mqtt_usr)
        normalized_device_mqtt_pass = _clean_str(device_mqtt_pass)
        normalized_last_nc_at = _clean_str(last_nc_at)
        normalized_last_mqtt_seen_at = _clean_str(last_mqtt_seen_at)

        with self._lock:
            did_index = self._find_index_by_did_locked(normalized_did)
            duid_index = self._find_index_by_duid_locked(normalized_duid)
            changed = False

            if did_index is not None and duid_index is not None and did_index != duid_index:
                primary_index = duid_index if normalized_duid and duid_index is not None else did_index
                secondary_index = did_index if primary_index == duid_index else duid_index
                device, merge_changed = self._merge_device_records_locked(primary_index, secondary_index)
                changed = changed or merge_changed
            else:
                index = did_index
                if index is None:
                    index = duid_index
                if index is None and not normalized_duid:
                    index = self._find_unique_model_index_locked(normalized_model)
                device = self._devices[index] if index is not None else None

            if device is None:
                device = {
                    "did": normalized_did,
                    "duid": normalized_duid,
                    "name": normalized_name,
                    "model": normalized_model,
                    "product_id": normalized_product_id,
                    "localkey": "",
                    "local_key_source": "",
                    "device_mqtt_usr": "",
                    "device_mqtt_pass": "",
                    "updated_at": "",
                    "last_nc_at": "",
                    "last_mqtt_seen_at": "",
                }
                self._devices.append(device)
                changed = True

            for key, value in (
                ("did", normalized_did),
                ("duid", normalized_duid),
                ("name", normalized_name),
                ("model", normalized_model),
                ("product_id", normalized_product_id),
                ("device_mqtt_usr", normalized_device_mqtt_usr),
                ("device_mqtt_pass", normalized_device_mqtt_pass),
                ("last_nc_at", normalized_last_nc_at),
                ("last_mqtt_seen_at", normalized_last_mqtt_seen_at),
            ):
                if not value or device.get(key) == value:
                    continue
                device[key] = value
                changed = True

            if normalized_localkey and device.get("localkey") != normalized_localkey:
                device["localkey"] = normalized_localkey
                changed = True
            if normalized_source and device.get("local_key_source") != normalized_source:
                device["local_key_source"] = normalized_source
                changed = True

            if assign_localkey and not device.get("localkey"):
                device["localkey"] = self._generate_localkey()
                if not device.get("local_key_source"):
                    device["local_key_source"] = "server_assigned"
                changed = True

            if changed:
                device["updated_at"] = utcnow_iso()
                self._save_locked()
            return dict(device)

    def link_did_to_duid(
        self,
        *,
        did: str,
        duid: str,
        name: str = "",
        model: str = "",
        product_id: str = "",
    ) -> tuple[dict[str, str] | None, str]:
        normalized_did = _clean_str(did)
        normalized_duid = _clean_str(duid)
        if not normalized_did or not normalized_duid:
            return None, "Both did and duid are required."

        with self._lock:
            did_index = self._find_index_by_did_locked(normalized_did)
            if did_index is not None:
                existing_duid = _clean_str(self._devices[did_index].get("duid"))
                if existing_duid and existing_duid != normalized_duid:
                    return None, (
                        f"Runtime DID {normalized_did} is already linked to DUID {existing_duid}; "
                        "not reassigning it automatically."
                    )

            duid_index = self._find_index_by_duid_locked(normalized_duid)
            if duid_index is not None:
                existing_did = _clean_str(self._devices[duid_index].get("did"))
                if existing_did and existing_did != normalized_did:
                    return None, (
                        f"Selected DUID {normalized_duid} is already linked to DID {existing_did}; "
                        "not reassigning it automatically."
                    )

        merged = self.ensure_device(
            did=normalized_did,
            duid=normalized_duid,
            name=name,
            model=model,
            product_id=product_id,
            assign_localkey=False,
        )
        return merged, ""

    def resolve_device_localkey(
        self,
        *,
        did: str = "",
        duid: str = "",
        model: str = "",
        name: str = "",
        product_id: str = "",
        assign_if_missing: bool = True,
        source: str = "",
    ) -> str:
        device = self.ensure_device(
            did=did,
            duid=duid,
            name=name,
            model=model,
            product_id=product_id,
            assign_localkey=assign_if_missing,
            local_key_source=source,
        )
        return _clean_str(device.get("localkey"))

    def resolve_device(self, *, did: str = "", duid: str = "", model: str = "") -> dict[str, str] | None:
        with self._lock:
            index = self._find_index_locked(did=_clean_str(did), duid=_clean_str(duid), model=_clean_str(model))
            if index is None:
                return None
            return dict(self._devices[index])

    def resolve_device_by_mqtt_username(self, username: str) -> dict[str, str] | None:
        normalized_username = _clean_str(username)
        if not normalized_username:
            return None
        with self._lock:
            for device in self._devices:
                if _clean_str(device.get("device_mqtt_usr")) == normalized_username:
                    return dict(device)
        return None

    def device_for_selector(self, selector: str = "") -> dict[str, str] | None:
        normalized = _clean_str(selector).lower()
        devices = self.devices()
        if not devices:
            with self._lock:
                bootstrap_device = self._bootstrap_device_locked()
            if bootstrap_device is not None:
                devices = [bootstrap_device]
        if not devices:
            return None
        if not normalized:
            for device in devices:
                if device.get("duid") and device.get("localkey"):
                    return device
            return devices[0]
        exact_fields = ("did", "duid", "name", "model")
        for device in devices:
            if any(_clean_str(device.get(field)).lower() == normalized for field in exact_fields):
                return device
        for device in devices:
            if normalized in " ".join(_clean_str(device.get(field)).lower() for field in exact_fields):
                return device
        return None

    def localkey_for_topic(self, topic: str) -> str:
        normalized_topic = _clean_str(topic)
        if normalized_topic.startswith("rr/d/"):
            parts = normalized_topic.split("/")
            if len(parts) >= 5:
                device = self.resolve_device(did=parts[3])
                return _clean_str(device.get("localkey")) if device else ""
        if normalized_topic.startswith("rr/m/"):
            parts = normalized_topic.split("/")
            if len(parts) >= 6:
                device = self.resolve_device(duid=parts[5])
                return _clean_str(device.get("localkey")) if device else ""
        return ""

    def record_mqtt_topic(self, *, topic: str) -> None:
        normalized_topic = _clean_str(topic)
        now = utcnow_iso()
        if normalized_topic.startswith("rr/d/"):
            parts = normalized_topic.split("/")
            if len(parts) >= 5:
                self.ensure_device(
                    did=parts[3],
                    device_mqtt_usr=parts[4],
                    last_mqtt_seen_at=now,
                    assign_localkey=False,
                )

    def verify_device_mqtt_credentials(self, *, username: str, password: str) -> tuple[bool, str, dict[str, str] | None]:
        normalized_username = _clean_str(username)
        normalized_password = _clean_str(password)
        if not normalized_username or not normalized_password:
            return False, "missing_mqtt_credentials", None

        with self._lock:
            for device in self._devices:
                if _clean_str(device.get("device_mqtt_usr")) != normalized_username:
                    continue
                stored_password = _clean_str(device.get("device_mqtt_pass"))
                if not stored_password:
                    return False, "device_mqtt_password_missing", dict(device)
                if stored_password == normalized_password:
                    return True, "device_mqtt_user", dict(device)
                return False, "invalid_device_mqtt_password", dict(device)
        return False, "unknown_device_mqtt_username", None

    def recover_device_mqtt_password(self, *, username: str, password: str) -> dict[str, str] | None:
        normalized_username = _clean_str(username)
        normalized_password = _clean_str(password)
        if not normalized_username or not normalized_password:
            return None
        with self._lock:
            for device in self._devices:
                if _clean_str(device.get("device_mqtt_usr")) != normalized_username:
                    continue
                if _clean_str(device.get("device_mqtt_pass")):
                    return dict(device)
                device["device_mqtt_pass"] = normalized_password
                device["updated_at"] = utcnow_iso()
                self._save_locked()
                return dict(device)
        return None

    def recovery_pending_devices(self) -> list[dict[str, str]]:
        with self._lock:
            pending = [
                dict(device)
                for device in self._devices
                if _clean_str(device.get("device_mqtt_usr")) and not _clean_str(device.get("device_mqtt_pass"))
            ]
        pending.sort(key=lambda item: (item.get("name") or "", item.get("duid") or item.get("did") or ""))
        return pending

    def backfill_device_mqtt_passwords(self, log_path: str | Path) -> int:
        path = Path(log_path)
        if not path.exists():
            return 0
        changed = 0
        with self._lock:
            pending_usernames = {
                _clean_str(device.get("device_mqtt_usr"))
                for device in self._devices
                if _clean_str(device.get("device_mqtt_usr")) and not _clean_str(device.get("device_mqtt_pass"))
            }
        if not pending_usernames:
            return 0

        recovered_by_username: dict[str, str] = {}
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for raw_line in handle:
                    line = str(raw_line or "")
                    if " CONNECT " not in line or " hex=" not in line:
                        continue
                    hex_value = line.rsplit(" hex=", 1)[-1].strip()
                    if not hex_value:
                        continue
                    try:
                        packet = bytes.fromhex(hex_value)
                    except ValueError:
                        continue
                    parsed = parse_mqtt_connect_packet(packet)
                    if parsed is None:
                        continue
                    username = _clean_str(parsed.get("username"))
                    password = _clean_str(parsed.get("password"))
                    if username in pending_usernames and password:
                        recovered_by_username[username] = password
        except OSError:
            return 0

        with self._lock:
            for username, password in recovered_by_username.items():
                for device in self._devices:
                    if _clean_str(device.get("device_mqtt_usr")) != username:
                        continue
                    if _clean_str(device.get("device_mqtt_pass")):
                        break
                    device["device_mqtt_pass"] = password
                    device["updated_at"] = utcnow_iso()
                    changed += 1
                    break
            if changed:
                self._save_locked()
        return changed

    def sync_inventory(self) -> None:
        inventory_devices = self._load_inventory_devices()
        key_models_by_did = self._load_key_models_by_did()
        inventory_model_counts = Counter(
            _clean_str(item.get("model")).lower()
            for item in inventory_devices
            if _clean_str(item.get("model"))
        )
        did_model_counts = Counter(model for model in key_models_by_did.values() if model)

        with self._lock:
            changed = False
            for item in inventory_devices:
                device_changed = False
                duid = _clean_str(item.get("duid"))
                model = _clean_str(item.get("model"))
                index = self._find_index_locked(duid=duid, model=model)
                if index is None:
                    self._devices.append(
                        {
                            "did": "",
                            "duid": duid,
                            "name": _clean_str(item.get("name")),
                            "model": model,
                            "product_id": _clean_str(item.get("product_id")),
                            "localkey": "",
                            "local_key_source": "",
                            "device_mqtt_usr": "",
                            "device_mqtt_pass": "",
                            "updated_at": "",
                            "last_nc_at": "",
                            "last_mqtt_seen_at": "",
                        }
                    )
                    index = len(self._devices) - 1
                    changed = True
                    device_changed = True
                device = self._devices[index]
                for key, value in (
                    ("duid", duid),
                    ("name", _clean_str(item.get("name"))),
                    ("model", model),
                    ("product_id", _clean_str(item.get("product_id"))),
                ):
                    if value and device.get(key) != value:
                        device[key] = value
                        changed = True
                        device_changed = True

                inventory_localkey = _clean_str(item.get("localkey"))
                if inventory_localkey:
                    if device.get("localkey") != inventory_localkey:
                        device["localkey"] = inventory_localkey
                        changed = True
                        device_changed = True
                    if device.get("local_key_source") != "inventory_cloud":
                        device["local_key_source"] = "inventory_cloud"
                        changed = True
                        device_changed = True

                normalized_model = model.lower()
                if (
                    normalized_model
                    and inventory_model_counts.get(normalized_model, 0) == 1
                    and did_model_counts.get(normalized_model, 0) == 1
                ):
                    did = next(
                        (
                            candidate_did
                            for candidate_did, candidate_model in key_models_by_did.items()
                            if candidate_model == normalized_model
                        ),
                        "",
                    )
                    if did and device.get("did") != did:
                        device["did"] = did
                        changed = True
                        device_changed = True

                if not device.get("localkey"):
                    device["localkey"] = self._generate_localkey()
                    device["local_key_source"] = "server_assigned"
                    changed = True
                    device_changed = True

                if device_changed:
                    device["updated_at"] = utcnow_iso()

            if changed:
                self._save_locked()

    def _load_inventory_devices(self) -> list[dict[str, str]]:
        if self.inventory_path is None or not self.inventory_path.exists():
            return []
        parsed = _load_json(self.inventory_path)
        devices: list[dict[str, str]] = []
        for source_key in ("devices", "received_devices", "receivedDevices"):
            source = parsed.get(source_key)
            if not isinstance(source, list):
                continue
            for raw in source:
                if not isinstance(raw, dict):
                    continue
                duid = _clean_str(raw.get("duid") or raw.get("did") or raw.get("device_id"))
                if not duid:
                    continue
                devices.append(
                    {
                        "duid": duid,
                        "name": _clean_str(raw.get("name") or raw.get("device_name")),
                        "model": _clean_str(raw.get("model")),
                        "product_id": _clean_str(raw.get("product_id") or raw.get("productId")),
                        "localkey": _clean_str(raw.get("local_key") or raw.get("localKey") or raw.get("k")),
                    }
                )
        return devices

    def _load_key_models_by_did(self) -> dict[str, str]:
        if self.key_state_file is None or not self.key_state_file.exists():
            return {}
        parsed = _load_json(self.key_state_file)
        devices = parsed.get("devices")
        if not isinstance(devices, dict):
            return {}
        out: dict[str, str] = {}
        for did, item in devices.items():
            if not isinstance(did, str) or not isinstance(item, dict):
                continue
            pid = _extract_pid_from_key_state_item(item).lower()
            if pid:
                out[did] = pid
        return out
