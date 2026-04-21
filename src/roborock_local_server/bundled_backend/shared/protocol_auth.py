"""Protocol auth helpers shared by the HTTPS server and MQTT proxy."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
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
    source: str = ""
    updated_at_utc: str = ""


@dataclass(frozen=True)
class ProtocolAvailability:
    user: ProtocolUserData | None
    reason: str
    users: tuple[ProtocolUserData, ...] = ()
    missing_fields: tuple[str, ...] = ()


def _session_identity(user_data: Mapping[str, Any]) -> tuple[str, str]:
    rriot = user_data.get("rriot")
    if not isinstance(rriot, Mapping):
        return "", ""
    return _clean_str(rriot.get("u")), _clean_str(rriot.get("s"))


def _minimal_session_user_data(user_data: Mapping[str, Any], *, source: str = "", updated_at_utc: str = "") -> dict[str, Any]:
    rriot = dict(user_data.get("rriot") or {})
    normalized: dict[str, Any] = {
        "uid": user_data.get("uid"),
        "token": _clean_str(user_data.get("token")),
        "rruid": _clean_str(user_data.get("rruid")),
        "rriot": {
            "u": _clean_str(rriot.get("u")),
            "s": _clean_str(rriot.get("s")),
            "h": _clean_str(rriot.get("h")),
            "k": _clean_str(rriot.get("k")),
        },
    }
    if source:
        normalized["source"] = source
    if updated_at_utc:
        normalized["updated_at_utc"] = updated_at_utc
    return normalized


def _clone_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _clone_json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clone_json_value(item) for item in value]
    return value


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
    """Loads protocol auth state from the persisted cloud snapshot and session store."""

    def __init__(
        self,
        snapshot_path: str | Path,
        *,
        session_store_path: str | Path | None = None,
        max_persisted_sessions: int = 8,
        hawk_clock_skew_seconds: int = 300,
        hawk_nonce_ttl_seconds: int = 600,
    ) -> None:
        self.snapshot_path = Path(snapshot_path)
        self.session_store_path = Path(session_store_path) if session_store_path is not None else None
        self.max_persisted_sessions = max(1, int(max_persisted_sessions))
        self.hawk_clock_skew_seconds = hawk_clock_skew_seconds
        self.hawk_nonce_ttl_seconds = hawk_nonce_ttl_seconds
        self._lock = threading.RLock()
        self._snapshot_mtime_ns: int | None = None
        self._session_store_mtime_ns: int | None = None
        self._persisted_session_records: tuple[dict[str, Any], ...] = ()
        self._availability = ProtocolAvailability(user=None, reason="missing_snapshot_or_user_data", users=())
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
            source=_clean_str(user_data.get("source")),
            updated_at_utc=_clean_str(user_data.get("updated_at_utc")),
        )

    def _load_snapshot_user_locked(self) -> tuple[ProtocolUserData | None, str, tuple[str, ...]]:
        try:
            stat = self.snapshot_path.stat()
        except OSError:
            self._snapshot_mtime_ns = None
            return None, "missing_snapshot_or_user_data", ()

        if self._snapshot_mtime_ns == stat.st_mtime_ns:
            availability = self._availability
            snapshot_user = availability.user if availability.reason == "ok" else None
            snapshot_identity = (
                (snapshot_user.hawk_id, snapshot_user.hawk_session)
                if snapshot_user is not None
                else ("", "")
            )
            for user in availability.users:
                if (user.hawk_id, user.hawk_session) == snapshot_identity:
                    return user, "ok", ()
            if snapshot_user is not None:
                return snapshot_user, "ok", ()
            return None, availability.reason, availability.missing_fields

        self._snapshot_mtime_ns = stat.st_mtime_ns
        try:
            parsed = json.loads(self.snapshot_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None, "missing_snapshot_or_user_data", ()
        if not isinstance(parsed, dict):
            return None, "missing_snapshot_or_user_data", ()

        user_data = parsed.get("user_data")
        if not isinstance(user_data, dict):
            return None, "missing_snapshot_or_user_data", ()

        missing_fields = tuple(self._missing_user_fields(user_data))
        if missing_fields:
            return None, "incomplete_cloud_user_data", missing_fields

        return self._build_user(user_data), "ok", ()

    def _load_persisted_session_records_locked(self) -> tuple[dict[str, Any], ...]:
        if self.session_store_path is None:
            self._session_store_mtime_ns = None
            self._persisted_session_records = ()
            return ()

        try:
            stat = self.session_store_path.stat()
        except OSError:
            self._session_store_mtime_ns = None
            self._persisted_session_records = ()
            return ()

        if self._session_store_mtime_ns == stat.st_mtime_ns:
            return self._persisted_session_records

        self._session_store_mtime_ns = stat.st_mtime_ns
        try:
            parsed = json.loads(self.session_store_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._persisted_session_records = ()
            return ()

        sessions = parsed.get("sessions") if isinstance(parsed, dict) else None
        if not isinstance(sessions, list):
            self._persisted_session_records = ()
            return ()

        normalized_records: list[dict[str, Any]] = []
        for raw_record in sessions:
            if isinstance(raw_record, dict):
                user_data = raw_record.get("user_data") if isinstance(raw_record.get("user_data"), dict) else raw_record
                if isinstance(user_data, dict):
                    normalized_records.append(dict(raw_record))
        self._persisted_session_records = tuple(normalized_records)
        return self._persisted_session_records

    def _persist_session_records_locked(self, records: list[dict[str, Any]]) -> None:
        if self.session_store_path is None:
            return
        payload = {"version": 1, "sessions": records[: self.max_persisted_sessions]}
        self.session_store_path.parent.mkdir(parents=True, exist_ok=True)
        self.session_store_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        try:
            stat = self.session_store_path.stat()
        except OSError:
            self._session_store_mtime_ns = None
        else:
            self._session_store_mtime_ns = stat.st_mtime_ns
        self._persisted_session_records = tuple(payload["sessions"])

    def _persisted_users_locked(self) -> list[ProtocolUserData]:
        records = self._load_persisted_session_records_locked()
        users: list[ProtocolUserData] = []
        seen: set[tuple[str, str]] = set()
        for raw_record in records:
            user_data = raw_record.get("user_data") if isinstance(raw_record.get("user_data"), dict) else raw_record
            if not isinstance(user_data, dict):
                continue
            missing_fields = self._missing_user_fields(user_data)
            if missing_fields:
                continue
            user = self._build_user(user_data)
            identity = (user.hawk_id, user.hawk_session)
            if identity in seen:
                continue
            seen.add(identity)
            users.append(user)
        return users

    def _refresh_locked(self) -> None:
        snapshot_user, snapshot_reason, snapshot_missing_fields = self._load_snapshot_user_locked()
        persisted_users = self._persisted_users_locked()

        users: list[ProtocolUserData] = []
        seen: set[tuple[str, str]] = set()
        for candidate in [snapshot_user, *persisted_users]:
            if candidate is None:
                continue
            identity = (candidate.hawk_id, candidate.hawk_session)
            if identity in seen:
                continue
            seen.add(identity)
            users.append(candidate)

        if users:
            self._availability = ProtocolAvailability(
                user=users[0],
                users=tuple(users),
                reason="ok",
            )
            return

        self._availability = ProtocolAvailability(
            user=None,
            users=(),
            reason=snapshot_reason,
            missing_fields=snapshot_missing_fields,
        )

    def availability(self) -> ProtocolAvailability:
        with self._lock:
            self._refresh_locked()
            return self._availability

    def persisted_sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            records = self._load_persisted_session_records_locked()
            return [_clone_json_value(dict(record)) for record in records]

    def remove_session(self, *, hawk_id: str, hawk_session: str) -> bool:
        normalized_identity = (_clean_str(hawk_id), _clean_str(hawk_session))
        if not all(normalized_identity):
            return False

        with self._lock:
            existing_records = list(self._load_persisted_session_records_locked())
            filtered_records: list[dict[str, Any]] = []
            removed = False
            for existing_record in existing_records:
                existing_user = (
                    existing_record.get("user_data")
                    if isinstance(existing_record.get("user_data"), dict)
                    else existing_record
                )
                if isinstance(existing_user, Mapping) and _session_identity(existing_user) == normalized_identity:
                    removed = True
                    continue
                filtered_records.append(existing_record)
            if not removed:
                return False
            self._persist_session_records_locked(filtered_records)
            self._refresh_locked()
            return True

    def expected_user_mqtt_credentials(self) -> tuple[str, str] | None:
        availability = self.availability()
        if availability.user is None:
            return None
        return availability.user.mqtt_username, availability.user.mqtt_password

    def verify_user_mqtt_credentials(self, username: str, password: str) -> tuple[bool, str, ProtocolUserData | None]:
        availability = self.availability()
        if not availability.users:
            return False, availability.reason, None
        for user in availability.users:
            if username == user.mqtt_username and password == user.mqtt_password:
                return True, "user_hash", user
        return False, "invalid_mqtt_credentials", None

    def upsert_user_data(self, user_data: Mapping[str, Any], *, source: str = "") -> ProtocolUserData:
        normalized_user_data = dict(user_data)
        missing_fields = tuple(self._missing_user_fields(normalized_user_data))
        if missing_fields:
            raise ValueError(f"incomplete protocol user_data: {', '.join(missing_fields)}")

        updated_at_utc = datetime.now(timezone.utc).isoformat()
        persisted_user_data = _minimal_session_user_data(
            normalized_user_data,
            source=source,
            updated_at_utc=updated_at_utc,
        )
        persisted_record = {
            "updated_at_utc": updated_at_utc,
            "source": _clean_str(source),
            "user_data": persisted_user_data,
        }
        identity = _session_identity(persisted_user_data)

        with self._lock:
            existing_records = list(self._load_persisted_session_records_locked())
            filtered_records: list[dict[str, Any]] = []
            for existing_record in existing_records:
                existing_user = (
                    existing_record.get("user_data")
                    if isinstance(existing_record.get("user_data"), dict)
                    else existing_record
                )
                if isinstance(existing_user, Mapping) and _session_identity(existing_user) == identity:
                    continue
                filtered_records.append(existing_record)
            filtered_records.insert(0, persisted_record)
            self._persist_session_records_locked(filtered_records)
            self._refresh_locked()

        return self._build_user(persisted_user_data)

    def issue_local_session(self, base_user_data: Mapping[str, Any], *, source: str = "") -> dict[str, Any]:
        if not isinstance(base_user_data, Mapping):
            raise ValueError("base_user_data must be a mapping")

        issued_user_data = _clone_json_value(dict(base_user_data))
        if not isinstance(issued_user_data, dict):
            raise ValueError("base_user_data must be a mapping")

        rruid = _clean_str(issued_user_data.get("rruid"))
        if not rruid:
            raise ValueError("base_user_data is missing rruid")

        issued_user_data["token"] = f"rr{secrets.token_hex(16)}"
        rriot_value = issued_user_data.get("rriot")
        rriot = dict(rriot_value) if isinstance(rriot_value, dict) else {}
        rriot["u"] = secrets.token_hex(11)
        rriot["s"] = secrets.token_hex(6)
        rriot["h"] = secrets.token_hex(16)
        rriot["k"] = secrets.token_hex(16)
        issued_user_data["rriot"] = rriot

        self.upsert_user_data(issued_user_data, source=source or "local_issued")
        return issued_user_data

    def upsert_snapshot_user(self, *, source: str = "cloud_snapshot") -> ProtocolUserData:
        with self._lock:
            try:
                parsed = json.loads(self.snapshot_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError("missing_snapshot_or_user_data") from exc
            if not isinstance(parsed, dict) or not isinstance(parsed.get("user_data"), dict):
                raise ValueError("missing_snapshot_or_user_data")
            return self.upsert_user_data(parsed["user_data"], source=source)

    def verify_token(self, headers: Mapping[str, str]) -> tuple[bool, str]:
        availability = self.availability()
        if not availability.users:
            return False, availability.reason

        authorization = _clean_str(headers.get("authorization"))
        if not authorization:
            return False, "missing_authorization"
        if authorization.lower().startswith("bearer "):
            authorization = authorization[7:].strip()
        matched_user = next((user for user in availability.users if authorization == user.token), None)
        if matched_user is None:
            return False, "invalid_token"

        header_username = _clean_str(headers.get("header_username"))
        if header_username and header_username != matched_user.rruid:
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
        if not availability.users:
            return False, availability.reason

        hawk = _parse_hawk_authorization(headers.get("authorization", ""))
        if hawk is None:
            return False, "missing_authorization"

        hawk_id = _clean_str(hawk.get("id"))
        matching_id_users = [user for user in availability.users if user.hawk_id == hawk_id]
        if not matching_id_users:
            return False, "invalid_hawk_id"

        hawk_session = _clean_str(hawk.get("s"))
        user = next((candidate for candidate in matching_id_users if candidate.hawk_session == hawk_session), None)
        if user is None:
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
