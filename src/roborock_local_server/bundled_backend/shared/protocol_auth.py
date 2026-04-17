"""Protocol auth helpers shared by the HTTPS server and MQTT proxy."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import threading
import time
from typing import Any, Mapping


def _clean_str(value: Any) -> str:
    return str(value or "").strip()


def _md5hex(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def _parse_json_body_param_map(body_params: dict[str, list[str]]) -> dict[str, Any]:
    for raw in body_params.get("__json") or []:
        try:
            parsed = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def _normalize_param_values(params: dict[str, list[str]], *, include_json: bool = False) -> dict[str, Any]:
    json_values = _parse_json_body_param_map(params) if include_json else {}
    normalized: dict[str, Any] = dict(json_values)
    for key, values in params.items():
        if str(key).startswith("__") or not values:
            continue
        if json_values and values == [""] and str(key).lstrip().startswith(("{", "[")):
            continue
        normalized[str(key)] = values[0] if len(values) == 1 else list(values)
    return normalized


def _process_extra_hawk_values(values: dict[str, Any] | None) -> str:
    if not values:
        return ""
    result: list[str] = []
    for key in sorted(values):
        result.append(f"{key}={values.get(key)}")
    return _md5hex("&".join(result))


def _build_hawk_mac(
    *,
    hawk_id: str,
    hawk_session: str,
    hawk_key: str,
    path: str,
    query_values: dict[str, Any] | None,
    form_values: dict[str, Any] | None,
    timestamp: int,
    nonce: str,
) -> str:
    prestr = ":".join(
        [
            hawk_id,
            hawk_session,
            nonce,
            str(timestamp),
            _md5hex(path),
            _process_extra_hawk_values(query_values),
            _process_extra_hawk_values(form_values),
        ]
    )
    return base64.b64encode(hmac.new(hawk_key.encode(), prestr.encode(), hashlib.sha256).digest()).decode()


def _parse_hawk_authorization(value: str) -> dict[str, str] | None:
    raw = _clean_str(value)
    if not raw or not raw.lower().startswith("hawk "):
        return None
    attributes: dict[str, str] = {}
    for item in raw[5:].split(","):
        if "=" not in item:
            continue
        key, raw_value = item.split("=", 1)
        normalized_key = _clean_str(key).lower()
        normalized_value = _clean_str(raw_value)
        if normalized_value.startswith('"') and normalized_value.endswith('"') and len(normalized_value) >= 2:
            normalized_value = normalized_value[1:-1]
        attributes[normalized_key] = normalized_value
    required = {"id", "s", "ts", "nonce", "mac"}
    if not required.issubset(attributes):
        return None
    return attributes


@dataclass(frozen=True)
class ProtocolUserData:
    token: str
    rruid: str
    hawk_id: str
    hawk_session: str
    hawk_key: str
    mqtt_username: str
    mqtt_password: str


@dataclass(frozen=True)
class ProtocolAvailability:
    user: ProtocolUserData | None
    reason: str
    missing_fields: tuple[str, ...] = ()


def build_hawk_authorization(
    *,
    user: ProtocolUserData,
    path: str,
    query_values: dict[str, Any] | None = None,
    form_values: dict[str, Any] | None = None,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> str:
    ts = int(time.time() if timestamp is None else timestamp)
    normalized_nonce = _clean_str(nonce) or secrets.token_urlsafe(6)
    mac = _build_hawk_mac(
        hawk_id=user.hawk_id,
        hawk_session=user.hawk_session,
        hawk_key=user.hawk_key,
        path=path,
        query_values=query_values,
        form_values=form_values,
        timestamp=ts,
        nonce=normalized_nonce,
    )
    return (
        f'Hawk id="{user.hawk_id}",s="{user.hawk_session}",ts="{ts}",'
        f'nonce="{normalized_nonce}",mac="{mac}"'
    )


class ProtocolAuthStore:
    """Loads protocol auth state from the persisted cloud snapshot."""

    def __init__(
        self,
        snapshot_path: str | Path,
        *,
        hawk_clock_skew_seconds: int = 300,
        hawk_nonce_ttl_seconds: int = 600,
    ) -> None:
        self.snapshot_path = Path(snapshot_path)
        self.hawk_clock_skew_seconds = hawk_clock_skew_seconds
        self.hawk_nonce_ttl_seconds = hawk_nonce_ttl_seconds
        self._lock = threading.RLock()
        self._snapshot_mtime_ns: int | None = None
        self._availability = ProtocolAvailability(user=None, reason="missing_snapshot_or_user_data")
        self._nonces: dict[str, float] = {}

    @staticmethod
    def _missing_user_fields(user_data: dict[str, Any]) -> list[str]:
        missing: list[str] = []
        if not _clean_str(user_data.get("token")):
            missing.append("token")
        if not _clean_str(user_data.get("rruid")):
            missing.append("rruid")
        rriot = user_data.get("rriot")
        if not isinstance(rriot, dict):
            missing.append("rriot")
            return missing
        if not _clean_str(rriot.get("u")):
            missing.append("rriot.u")
        if not _clean_str(rriot.get("s")):
            missing.append("rriot.s")
        if not _clean_str(rriot.get("h")):
            missing.append("rriot.h")
        if not _clean_str(rriot.get("k")):
            missing.append("rriot.k")
        return missing

    @staticmethod
    def _build_user(user_data: dict[str, Any]) -> ProtocolUserData:
        rriot = dict(user_data.get("rriot") or {})
        hawk_id = _clean_str(rriot.get("u"))
        hawk_session = _clean_str(rriot.get("s"))
        mqtt_key = _clean_str(rriot.get("k"))
        return ProtocolUserData(
            token=_clean_str(user_data.get("token")),
            rruid=_clean_str(user_data.get("rruid")),
            hawk_id=hawk_id,
            hawk_session=hawk_session,
            hawk_key=_clean_str(rriot.get("h")),
            mqtt_username=_md5hex(f"{hawk_id}:{mqtt_key}")[2:10],
            mqtt_password=_md5hex(f"{hawk_session}:{mqtt_key}")[16:],
        )

    def _refresh_locked(self) -> None:
        try:
            stat = self.snapshot_path.stat()
        except OSError:
            self._snapshot_mtime_ns = None
            self._availability = ProtocolAvailability(user=None, reason="missing_snapshot_or_user_data")
            return

        if self._snapshot_mtime_ns == stat.st_mtime_ns:
            return

        self._snapshot_mtime_ns = stat.st_mtime_ns
        try:
            parsed = json.loads(self.snapshot_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._availability = ProtocolAvailability(user=None, reason="missing_snapshot_or_user_data")
            return
        if not isinstance(parsed, dict):
            self._availability = ProtocolAvailability(user=None, reason="missing_snapshot_or_user_data")
            return

        user_data = parsed.get("user_data")
        if not isinstance(user_data, dict):
            self._availability = ProtocolAvailability(user=None, reason="missing_snapshot_or_user_data")
            return

        missing_fields = tuple(self._missing_user_fields(user_data))
        if missing_fields:
            self._availability = ProtocolAvailability(
                user=None,
                reason="incomplete_cloud_user_data",
                missing_fields=missing_fields,
            )
            return

        self._availability = ProtocolAvailability(user=self._build_user(user_data), reason="ok")

    def availability(self) -> ProtocolAvailability:
        with self._lock:
            self._refresh_locked()
            return self._availability

    def expected_user_mqtt_credentials(self) -> tuple[str, str] | None:
        availability = self.availability()
        if availability.user is None:
            return None
        return availability.user.mqtt_username, availability.user.mqtt_password

    def verify_token(self, headers: Mapping[str, str]) -> tuple[bool, str]:
        availability = self.availability()
        user = availability.user
        if user is None:
            return False, availability.reason

        authorization = _clean_str(headers.get("authorization"))
        if not authorization:
            return False, "missing_authorization"
        if authorization.lower().startswith("bearer "):
            authorization = authorization[7:].strip()
        if authorization != user.token:
            return False, "invalid_token"

        header_username = _clean_str(headers.get("header_username"))
        if header_username and header_username != user.rruid:
            return False, "invalid_header_username"
        return True, "ok"

    def verify_hawk(
        self,
        *,
        path: str,
        query_params: dict[str, list[str]],
        body_params: dict[str, list[str]],
        headers: Mapping[str, str],
        now_ts: float | None = None,
    ) -> tuple[bool, str]:
        availability = self.availability()
        user = availability.user
        if user is None:
            return False, availability.reason

        hawk = _parse_hawk_authorization(headers.get("authorization", ""))
        if hawk is None:
            return False, "missing_authorization"
        if hawk.get("id") != user.hawk_id:
            return False, "invalid_hawk_id"
        if hawk.get("s") != user.hawk_session:
            return False, "invalid_hawk_session"

        try:
            timestamp = int(_clean_str(hawk.get("ts")))
        except ValueError:
            return False, "invalid_hawk_timestamp"
        current_ts = int(time.time() if now_ts is None else now_ts)
        if abs(current_ts - timestamp) > self.hawk_clock_skew_seconds:
            return False, "stale_hawk_timestamp"

        nonce = _clean_str(hawk.get("nonce"))
        if not nonce:
            return False, "missing_hawk_nonce"

        expected_mac = _build_hawk_mac(
            hawk_id=user.hawk_id,
            hawk_session=user.hawk_session,
            hawk_key=user.hawk_key,
            path=path,
            query_values=_normalize_param_values(query_params),
            form_values=_normalize_param_values(body_params, include_json=True),
            timestamp=timestamp,
            nonce=nonce,
        )
        if not hmac.compare_digest(_clean_str(hawk.get("mac")), expected_mac):
            return False, "invalid_hawk_mac"

        nonce_key = f"{user.hawk_id}:{user.hawk_session}:{timestamp}:{nonce}"
        expires_at = float(current_ts + self.hawk_nonce_ttl_seconds)
        with self._lock:
            stale_keys = [key for key, value in self._nonces.items() if value <= current_ts]
            for key in stale_keys:
                self._nonces.pop(key, None)
            if nonce_key in self._nonces:
                return False, "replayed_hawk_nonce"
            self._nonces[nonce_key] = expires_at
        return True, "ok"
