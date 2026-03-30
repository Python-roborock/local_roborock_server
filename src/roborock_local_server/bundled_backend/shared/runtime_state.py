"""Thread-safe runtime state used by the local stack dashboard."""

from __future__ import annotations

import base64
from collections import deque
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import threading
from typing import Any
from urllib.parse import parse_qs

REQUIRED_ONBOARDING_STEPS = ("region", "nc_prepare")
ONBOARDING_STEP_LABELS = {
    "region": "Region",
    "nc_prepare": "NC Prepare",
    "login_key_sign": "Key Sign",
}
PAIRING_STEP_LABELS = {
    "region": "Region",
    "nc": "Nc",
    "public_key": "Public key",
    "connected": "Connected",
}
_TRACKED_ONBOARDING_STEPS = set(ONBOARDING_STEP_LABELS.keys())
_D_TOPIC_RE = re.compile(r"^rr/d/[io]/([^/]+)/([^/]+)$")
_M_TOPIC_RE = re.compile(r"^rr/m/[io]/[^/]+/[^/]+/([^/]+)$")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _extract_ip(remote: str | None) -> str:
    if not remote:
        return ""
    # Handles "ip:port" and bare host values.
    if remote.count(":") == 1:
        return remote.split(":", 1)[0].strip()
    return remote.strip()


def _parse_iso(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_newer_timestamp(candidate: str | None, current: str | None) -> bool:
    candidate_dt = _parse_iso(candidate)
    if candidate_dt is None:
        return False
    current_dt = _parse_iso(current)
    if current_dt is None:
        return True
    return candidate_dt > current_dt


def _is_same_or_newer_timestamp(candidate: str | None, current: str | None) -> bool:
    candidate_dt = _parse_iso(candidate)
    if candidate_dt is None:
        return False
    current_dt = _parse_iso(current)
    if current_dt is None:
        return True
    return candidate_dt >= current_dt


class RuntimeState:
    """Stores mutable runtime state for UI/health endpoints."""

    def __init__(self, *, log_dir: Path, key_state_file: Path | None) -> None:
        self.log_dir = log_dir
        self.key_state_file = key_state_file

        self._lock = threading.RLock()
        self._services: dict[str, dict[str, Any]] = {}
        self._vacuums: dict[str, dict[str, Any]] = {}
        self._pending_steps_by_ip: dict[str, dict[str, str]] = {}
        self._mqtt_connections: dict[str, dict[str, Any]] = {}
        self._conn_to_vacuums: dict[str, set[str]] = {}
        self._recent_events: deque[dict[str, Any]] = deque(maxlen=1500)
        self._cloud_request: dict[str, Any] | None = None
        self._pairing_session: dict[str, Any] | None = None
        self._key_cache_mtime_ns: int | None = None
        self._key_cache_dids: set[str] = set()
        self._key_cache_models: dict[str, str] = {}
        self._key_cache_details: dict[str, dict[str, Any]] = {}

    def set_service(
        self,
        name: str,
        *,
        running: bool,
        required: bool = True,
        enabled: bool = True,
        detail: str | None = None,
    ) -> None:
        with self._lock:
            existing = self._services.get(name, {})
            self._services[name] = {
                "name": name,
                "running": bool(running),
                "required": bool(required),
                "enabled": bool(enabled),
                "detail": existing.get("detail", "") if detail is None else detail,
                "updated_at": _utcnow_iso(),
            }

    def upsert_vacuum(
        self,
        duid: str,
        *,
        name: str | None = None,
        local_key: str | None = None,
        source: str | None = None,
        did: str | None = None,
        id_kind: str | None = None,
        last_mqtt_at: str | None = None,
        last_nc_at: str | None = None,
        restored_activity: bool = False,
    ) -> None:
        with self._lock:
            vac = self._ensure_vacuum_locked(duid)
            if name:
                vac["name"] = name
            if local_key:
                vac["local_key"] = local_key
            if source:
                vac["source"] = source
            if did:
                vac["did"] = did
            if id_kind:
                vac["id_kind"] = id_kind
            if last_nc_at:
                existing_nc_at = str(vac["onboarding_steps"].get("nc_prepare") or "")
                if not existing_nc_at or _is_newer_timestamp(last_nc_at, existing_nc_at):
                    vac["onboarding_steps"]["nc_prepare"] = last_nc_at
            if last_mqtt_at:
                if _is_newer_timestamp(last_mqtt_at, str(vac.get("last_mqtt_at") or "")):
                    vac["last_mqtt_at"] = last_mqtt_at
                if _is_newer_timestamp(last_mqtt_at, str(vac.get("last_message_at") or "")):
                    vac["last_message_at"] = last_mqtt_at
                    vac["last_message_source"] = "mqtt"
            if restored_activity and last_mqtt_at:
                vac["restored_activity"] = True

    def record_http_event(
        self,
        *,
        event_time: str,
        route_name: str,
        clean_path: str,
        raw_path: str,
        method: str,
        host: str,
        remote: str,
        did: str | None,
        pid: str | None = None,
    ) -> None:
        ip = _extract_ip(remote)
        normalized_pid = (pid or "").strip()
        step_name = route_name if route_name in _TRACKED_ONBOARDING_STEPS else None
        with self._lock:
            resolved_did = (did or "").strip()
            if not resolved_did and normalized_pid:
                maybe_did = self._resolve_did_from_pid_locked(normalized_pid)
                if maybe_did:
                    resolved_did = maybe_did
            event = {
                "time": event_time,
                "type": "http",
                "route": route_name,
                "path": clean_path,
                "raw_path": raw_path,
                "method": method,
                "host": host,
                "remote": remote,
                "did": resolved_did or did,
                "pid": normalized_pid,
            }
            self._recent_events.append(event)

            if step_name:
                if resolved_did:
                    vac = self._ensure_vacuum_locked(resolved_did)
                    vac["onboarding_steps"][step_name] = event_time
                    if ip:
                        pending = self._pending_steps_by_ip.pop(ip, {})
                        for pending_step, pending_time in pending.items():
                            vac["onboarding_steps"].setdefault(pending_step, pending_time)
                elif ip:
                    pending = self._pending_steps_by_ip.setdefault(ip, {})
                    pending[step_name] = event_time

            if resolved_did:
                vac = self._ensure_vacuum_locked(resolved_did)
                if ip:
                    vac["ips"].add(ip)
                    vac["last_ip"] = ip
                vac["last_http_at"] = event_time
                vac["last_http_route"] = route_name
                vac["last_http_path"] = clean_path
                vac["last_http_remote"] = remote
                vac["last_http_host"] = host
                vac["last_message_at"] = event_time
                vac["last_message_source"] = "http"

            self._record_pairing_http_event_locked(
                event_time=event_time,
                route_name=route_name,
                identifier=resolved_did or (did or "").strip(),
                remote_ip=ip,
            )

    def record_mqtt_connection(self, *, conn_id: str, client_ip: str, client_port: int) -> None:
        now = _utcnow_iso()
        with self._lock:
            self._mqtt_connections[conn_id] = {
                "conn_id": conn_id,
                "client_ip": client_ip,
                "client_port": client_port,
                "connected_at": now,
                "last_seen_at": now,
                "last_topic": "",
            }
            self._recent_events.append(
                {
                    "time": now,
                    "type": "mqtt_connect",
                    "conn_id": conn_id,
                    "client_ip": client_ip,
                    "client_port": client_port,
                }
            )

    def record_mqtt_disconnect(self, *, conn_id: str) -> None:
        now = _utcnow_iso()
        with self._lock:
            self._mqtt_connections.pop(conn_id, None)
            vacs = self._conn_to_vacuums.pop(conn_id, set())
            for duid in vacs:
                vac = self._vacuums.get(duid)
                if vac is None:
                    continue
                still_connected = any(duid in conn_vacuums for conn_vacuums in self._conn_to_vacuums.values())
                vac["connected"] = still_connected
                vac["last_disconnect_at"] = now
            self._recent_events.append({"time": now, "type": "mqtt_disconnect", "conn_id": conn_id})

    def record_mqtt_message(
        self,
        *,
        conn_id: str,
        direction: str,
        topic: str,
        payload_preview: str,
    ) -> None:
        now = _utcnow_iso()
        device_id, id_kind = self._extract_identity_from_topic(topic)
        did = device_id if id_kind == "did" else ""
        duid = device_id if id_kind == "duid" else ""
        with self._lock:
            conn = self._mqtt_connections.get(conn_id)
            if conn is not None:
                conn["last_seen_at"] = now
                conn["last_topic"] = topic

            self._recent_events.append(
                {
                    "time": now,
                    "type": "mqtt_message",
                    "conn_id": conn_id,
                    "direction": direction,
                    "topic": topic,
                    "did": did,
                    "duid": duid,
                    "id_kind": id_kind or "",
                }
            )

            if not device_id:
                return
            vac = self._ensure_vacuum_locked(device_id)
            vac["id_kind"] = id_kind or vac.get("id_kind", "")
            if did:
                vac["did"] = did
            vac["connected"] = True
            vac["last_mqtt_at"] = now
            vac["last_mqtt_topic"] = topic
            vac["last_mqtt_direction"] = direction
            vac["last_mqtt_payload_preview"] = payload_preview
            vac["last_message_at"] = now
            vac["last_message_source"] = "mqtt"
            vac["last_mqtt_conn_id"] = conn_id
            if conn is not None:
                client_ip = str(conn.get("client_ip") or "")
                if client_ip:
                    vac["ips"].add(client_ip)
                    vac["last_ip"] = client_ip
            self._conn_to_vacuums.setdefault(conn_id, set()).add(device_id)

            self._record_pairing_mqtt_event_locked(
                event_time=now,
                did=did,
                duid=duid,
                client_ip=str(conn.get("client_ip") or "") if conn is not None else "",
            )

    def record_cloud_request(self, result: dict[str, Any]) -> None:
        with self._lock:
            self._cloud_request = {
                **result,
                "time": _utcnow_iso(),
            }

    def vacuum_snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            key_dids, key_models, key_details = self._load_key_state_locked()
            out = []
            for vac in self._vacuums.values():
                out.append(self._to_snapshot_locked(vac, key_dids, key_models, key_details))
            out.sort(key=lambda item: (item.get("name") or "", item.get("duid") or ""))
            return out

    def health_snapshot(self) -> dict[str, Any]:
        with self._lock:
            services = [dict(value) for value in self._services.values()]
            services.sort(key=lambda item: item["name"])
            overall_ok = True
            for service in services:
                if service["required"] and service["enabled"] and not service["running"]:
                    overall_ok = False
                    break
            vacuums = self.vacuum_snapshot()
            connected = [vac for vac in vacuums if vac.get("connected")]
            return {
                "generated_at": _utcnow_iso(),
                "overall_ok": overall_ok,
                "services": services,
                "connected_vacuums": connected,
                "all_vacuums": vacuums,
                "active_mqtt_connections": len(self._mqtt_connections),
                "pending_onboarding_ips": sorted(self._pending_steps_by_ip.keys()),
                "last_cloud_request": self._cloud_request,
            }

    def start_pairing_session(self) -> dict[str, Any]:
        with self._lock:
            now = _utcnow_iso()
            self._pairing_session = {
                "active": True,
                "started_at": now,
                "updated_at": now,
                "region_at": "",
                "nc_at": "",
                "public_key_at": "",
                "connected_at": "",
                "target_did": "",
                "target_duid": "",
                "target_ip": "",
            }
            return self._pairing_snapshot_locked()

    def pairing_snapshot(self) -> dict[str, Any]:
        with self._lock:
            return self._pairing_snapshot_locked()

    def recent_events(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            if limit <= 0:
                return []
            return list(self._recent_events)[-limit:]

    def key_models_by_did(self) -> dict[str, str]:
        with self._lock:
            _, models, _ = self._load_key_state_locked()
            return dict(models)

    def _ensure_vacuum_locked(self, duid: str) -> dict[str, Any]:
        normalized = (duid or "").strip()
        if not normalized:
            normalized = "unknown"
        existing = self._vacuums.get(normalized)
        if existing is not None:
            return existing
        created = {
            "duid": normalized,
            "did": "",
            "id_kind": "",
            "name": "",
            "local_key": "",
            "source": "",
            "ips": set(),
            "connected": False,
            "last_ip": "",
            "last_http_at": "",
            "last_http_route": "",
            "last_http_path": "",
            "last_http_remote": "",
            "last_http_host": "",
            "last_mqtt_at": "",
            "last_mqtt_topic": "",
            "last_mqtt_direction": "",
            "last_mqtt_payload_preview": "",
            "last_mqtt_conn_id": "",
            "last_disconnect_at": "",
            "last_message_at": "",
            "last_message_source": "",
            "onboarding_steps": {},
            "restored_activity": False,
        }
        self._vacuums[normalized] = created
        return created

    def _pairing_snapshot_locked(self) -> dict[str, Any]:
        session = self._pairing_session
        if session is None or not session.get("active"):
            step_details = self._pairing_step_details_locked("")
            return {
                "active": False,
                "started_at": "",
                "updated_at": "",
                "status": "idle",
                "message": "No pairing session started.",
                "complete": False,
                "checks": {key: False for key in PAIRING_STEP_LABELS},
                "steps": [
                    {
                        "key": key,
                        "label": label,
                        "detail": step_details.get(key, ""),
                        "checked": False,
                        "checked_at": "",
                    }
                    for key, label in PAIRING_STEP_LABELS.items()
                ],
                "target": {
                    "did": "",
                    "duid": "",
                    "name": "",
                    "last_ip": "",
                    "connected": False,
                },
            }

        self._refresh_pairing_session_locked(session)
        target_vac = self._resolve_pairing_target_locked(session)
        target = self._pairing_target_snapshot_locked(session, target_vac)
        mqtt_connected = self._pairing_is_mqtt_connected_locked(target_vac)
        target_did = str(target.get("did") or session.get("target_did") or "").strip()
        step_details = self._pairing_step_details_locked(target_did)
        step_times = {
            "region": str(session.get("region_at") or ""),
            "nc": str(session.get("nc_at") or ""),
            "public_key": str(session.get("public_key_at") or ""),
            "connected": str(session.get("connected_at") or "") if mqtt_connected else "",
        }
        checks = {key: bool(value) for key, value in step_times.items()}
        complete = all(checks.values())
        if complete:
            status = "complete"
            message = "Device paired and connected."
        elif not any(checks.values()):
            status = "waiting"
            message = "Waiting for device to pair - please use the onboarding script"
        else:
            status = "in_progress"
            remaining = [PAIRING_STEP_LABELS[key] for key, checked in checks.items() if not checked]
            if remaining:
                message = f"Pairing in progress. Waiting for: {', '.join(remaining)}."
            else:
                message = "Pairing in progress."
        return {
            "active": True,
            "started_at": str(session.get("started_at") or ""),
            "updated_at": str(session.get("updated_at") or ""),
            "status": status,
            "message": message,
            "complete": complete,
            "checks": checks,
            "steps": [
                {
                    "key": key,
                    "label": label,
                    "detail": step_details.get(key, ""),
                    "checked": checks[key],
                    "checked_at": step_times[key],
                }
                for key, label in PAIRING_STEP_LABELS.items()
            ],
            "target": target,
        }

    def _pairing_step_details_locked(self, target_did: str) -> dict[str, str]:
        sample_count = self._pairing_public_key_sample_count_locked(target_did)
        sample_label = "sample" if sample_count == 1 else "samples"
        return {
            "region": "",
            "nc": "",
            "public_key": f"({sample_count} {sample_label})",
            "connected": "",
        }

    def _refresh_pairing_session_locked(self, session: dict[str, Any]) -> None:
        target_vac = self._resolve_pairing_target_locked(session)
        if target_vac is None:
            return

        changed = False
        target_did = str(target_vac.get("did") or session.get("target_did") or "").strip()
        target_duid = str(target_vac.get("duid") or session.get("target_duid") or "").strip()
        target_ip = str(target_vac.get("last_ip") or "").strip()
        if target_did and session.get("target_did") != target_did:
            session["target_did"] = target_did
            changed = True
        if target_duid and session.get("target_duid") != target_duid:
            session["target_duid"] = target_duid
            changed = True
        if target_ip and session.get("target_ip") != target_ip:
            session["target_ip"] = target_ip
            changed = True

        started_at = str(session.get("started_at") or "")
        last_mqtt_at = str(target_vac.get("last_mqtt_at") or "")
        if (
            last_mqtt_at
            and not session.get("connected_at")
            and _is_same_or_newer_timestamp(last_mqtt_at, started_at)
        ):
            session["connected_at"] = last_mqtt_at
            changed = True

        if target_did and not session.get("public_key_at"):
            _key_dids, _key_models, key_details = self._load_key_state_locked()
            key_state = dict(key_details.get(target_did) or {})
            if key_state.get("has_modulus"):
                recovered_at = str(
                    key_state.get("recovery_finished_at")
                    or key_state.get("recovery_started_at")
                    or ""
                ).strip()
                if recovered_at and _is_same_or_newer_timestamp(recovered_at, started_at):
                    session["public_key_at"] = recovered_at
                    changed = True

        if changed:
            session["updated_at"] = _utcnow_iso()

    def _pairing_target_snapshot_locked(
        self,
        session: dict[str, Any],
        target_vac: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if target_vac is None:
            return {
                "did": str(session.get("target_did") or ""),
                "duid": str(session.get("target_duid") or ""),
                "name": "",
                "last_ip": str(session.get("target_ip") or ""),
                "connected": False,
            }
        return {
            "did": str(target_vac.get("did") or session.get("target_did") or ""),
            "duid": str(target_vac.get("duid") or session.get("target_duid") or ""),
            "name": str(target_vac.get("name") or ""),
            "last_ip": str(target_vac.get("last_ip") or session.get("target_ip") or ""),
            "connected": self._pairing_is_mqtt_connected_locked(target_vac),
        }

    @staticmethod
    def _pairing_is_mqtt_connected_locked(target_vac: dict[str, Any] | None) -> bool:
        if target_vac is None:
            return False
        return bool(target_vac.get("connected"))

    def _pairing_public_key_sample_count_locked(self, target_did: str) -> int:
        normalized_did = target_did.strip()
        if not normalized_did:
            return 0
        _key_dids, _key_models, key_details = self._load_key_state_locked()
        key_state = dict(key_details.get(normalized_did) or {})
        return int(key_state.get("query_samples") or 0)

    def _resolve_pairing_target_locked(self, session: dict[str, Any]) -> dict[str, Any] | None:
        target_did = str(session.get("target_did") or "").strip()
        target_duid = str(session.get("target_duid") or "").strip()
        if target_did or target_duid:
            matched = self._find_vacuum_by_identity_locked(did=target_did, duid=target_duid)
            if matched is not None:
                return matched

        started_at = str(session.get("started_at") or "")
        target_ip = str(session.get("target_ip") or "").strip()
        candidates: list[dict[str, Any]] = []
        for vac in self._vacuums.values():
            if not self._vacuum_has_activity_since_locked(vac, started_at):
                continue
            if target_ip:
                ips = {str(item).strip() for item in vac.get("ips") or []}
                last_ip = str(vac.get("last_ip") or "").strip()
                if target_ip not in ips and target_ip != last_ip:
                    continue
            candidates.append(vac)
        if len(candidates) == 1:
            return candidates[0]
        return None

    def _find_vacuum_by_identity_locked(self, *, did: str = "", duid: str = "") -> dict[str, Any] | None:
        normalized_did = did.strip()
        normalized_duid = duid.strip()
        if normalized_did and normalized_did in self._vacuums:
            return self._vacuums[normalized_did]
        if normalized_duid and normalized_duid in self._vacuums:
            return self._vacuums[normalized_duid]
        for vac in self._vacuums.values():
            vac_duid = str(vac.get("duid") or "").strip()
            vac_did = str(vac.get("did") or "").strip()
            if normalized_did and (vac_did == normalized_did or (vac.get("id_kind") == "did" and vac_duid == normalized_did)):
                return vac
            if normalized_duid and vac_duid == normalized_duid:
                return vac
        return None

    def _vacuum_has_activity_since_locked(self, vac: dict[str, Any], started_at: str) -> bool:
        timestamps = [
            str(vac.get("last_http_at") or ""),
            str(vac.get("last_mqtt_at") or ""),
            str(vac.get("last_message_at") or ""),
        ]
        onboarding_steps = vac.get("onboarding_steps")
        if isinstance(onboarding_steps, dict):
            timestamps.extend(str(value or "") for value in onboarding_steps.values())
        return any(_is_same_or_newer_timestamp(candidate, started_at) for candidate in timestamps if candidate)

    def _record_pairing_http_event_locked(
        self,
        *,
        event_time: str,
        route_name: str,
        identifier: str,
        remote_ip: str,
    ) -> None:
        session = self._pairing_session
        if session is None or not _is_same_or_newer_timestamp(event_time, str(session.get("started_at") or "")):
            return
        if route_name not in {"region", "nc_prepare", "login_key_sign"}:
            return

        changed = False
        if route_name == "region" and session.get("region_at") != event_time:
            session["region_at"] = event_time
            changed = True
        if route_name == "nc_prepare" and session.get("nc_at") != event_time:
            session["nc_at"] = event_time
            changed = True

        normalized_ip = remote_ip.strip()
        if normalized_ip and not session.get("target_ip"):
            session["target_ip"] = normalized_ip
            changed = True

        normalized_identifier = identifier.strip()
        if normalized_identifier:
            kind = self._resolve_identity_kind_locked(normalized_identifier)
            if kind == "did" and session.get("target_did") != normalized_identifier:
                session["target_did"] = normalized_identifier
                changed = True
            elif kind == "duid" and session.get("target_duid") != normalized_identifier:
                session["target_duid"] = normalized_identifier
                changed = True

        if changed:
            session["updated_at"] = event_time

    def _record_pairing_mqtt_event_locked(
        self,
        *,
        event_time: str,
        did: str,
        duid: str,
        client_ip: str,
    ) -> None:
        session = self._pairing_session
        if session is None or not _is_same_or_newer_timestamp(event_time, str(session.get("started_at") or "")):
            return
        if not session.get("region_at") and not session.get("nc_at"):
            return

        normalized_ip = client_ip.strip()
        target_ip = str(session.get("target_ip") or "").strip()
        if target_ip and normalized_ip and target_ip != normalized_ip:
            return

        changed = False
        normalized_did = did.strip()
        normalized_duid = duid.strip()
        if normalized_did and not session.get("target_did"):
            session["target_did"] = normalized_did
            changed = True
        if normalized_duid and not session.get("target_duid"):
            session["target_duid"] = normalized_duid
            changed = True
        if normalized_ip and not session.get("target_ip"):
            session["target_ip"] = normalized_ip
            changed = True

        target_did = str(session.get("target_did") or "").strip()
        target_duid = str(session.get("target_duid") or "").strip()
        if (
            (normalized_did and normalized_did == target_did)
            or (normalized_duid and normalized_duid == target_duid)
            or (not target_did and not target_duid and (normalized_did or normalized_duid))
        ):
            if session.get("connected_at") != event_time:
                session["connected_at"] = event_time
                changed = True

        if changed:
            session["updated_at"] = event_time

    def _resolve_identity_kind_locked(self, identifier: str) -> str:
        normalized = identifier.strip()
        if not normalized:
            return ""
        matched = self._find_vacuum_by_identity_locked(did=normalized)
        if matched is not None and str(matched.get("did") or "").strip() == normalized:
            return "did"
        if normalized.isdigit():
            return "did"
        matched = self._find_vacuum_by_identity_locked(duid=normalized)
        if matched is not None:
            return "duid"
        return "duid"

    def _to_snapshot_locked(
        self,
        vac: dict[str, Any],
        key_dids: set[str],
        key_models: dict[str, str],
        key_details: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        onboarding_steps = dict(vac.get("onboarding_steps") or {})
        missing_steps = [step for step in REQUIRED_ONBOARDING_STEPS if step not in onboarding_steps]
        has_required_messages = not missing_steps
        last_message_at = str(vac.get("last_message_at") or "")
        duid = str(vac.get("duid") or "")
        did = str(vac.get("did") or "")
        id_kind = str(vac.get("id_kind") or "")
        if id_kind == "did" and not did:
            did = duid
        key_identity = did or duid
        has_public_key = key_identity in key_dids
        key_model = key_models.get(key_identity, "")
        key_state = dict(key_details.get(key_identity) or {})
        if not key_state and did and did in key_details:
            key_state = dict(key_details[did])
        if not key_state and duid and duid in key_details:
            key_state = dict(key_details[duid])
        public_key_ready = has_required_messages and has_public_key
        if public_key_ready:
            onboarding_status = "ready"
            guidance = "Required onboarding messages captured and public key is available."
        elif has_required_messages and not has_public_key:
            onboarding_status = "need_reconnect_for_public_key"
            query_samples = int(key_state.get("query_samples") or 0)
            max_signature_len = int(key_state.get("max_signature_len") or 0)
            recovery_state = str(key_state.get("recovery_state") or "").strip()
            recovery_note = str(key_state.get("recovery_note") or "").strip()
            if query_samples < 2:
                guidance = (
                    "Required onboarding messages captured, but public key recovery needs more signed requests. "
                    f"Captured query signatures: {query_samples}/2."
                )
            elif max_signature_len and max_signature_len < 128:
                guidance = (
                    "Required onboarding messages captured, but signatures appear too short for RSA recovery "
                    f"({max_signature_len} bytes)."
                )
            elif recovery_state == "recovering":
                guidance = "Required onboarding messages captured; RSA key recovery is running."
            elif recovery_note:
                guidance = (
                    "Required onboarding messages captured, but no public key is available yet. "
                    f"Recovery status: {recovery_note}"
                )
            else:
                guidance = (
                    "Required onboarding messages captured, but no public key is available yet. "
                    "Repeat onboarding traffic capture to collect additional signatures."
                )
        else:
            if bool(vac.get("restored_activity")) and last_message_at:
                onboarding_status = "waiting_for_reconnect"
                guidance = (
                    "This vacuum has already connected to the local stack. "
                    "Wait for it to reconnect after a server restart; onboarding does not need to be repeated."
                )
            else:
                labels = [ONBOARDING_STEP_LABELS.get(step, step) for step in missing_steps]
                onboarding_status = "collecting_messages"
                guidance = f"Still waiting for onboarding messages: {', '.join(labels)}."

        connected = bool(vac.get("connected"))
        if not connected and last_message_at:
            last_mqtt_at = str(vac.get("last_mqtt_at") or "")
            if last_mqtt_at:
                parsed = _parse_iso(last_mqtt_at)
                if parsed is not None:
                    delta = datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)
                    if delta.total_seconds() <= 180:
                        connected = True

        return {
            "duid": duid,
            "did": did,
            "id_kind": id_kind,
            "name": str(vac.get("name") or ""),
            "local_key": str(vac.get("local_key") or ""),
            "source": str(vac.get("source") or ""),
            "key_model": key_model,
            "ips": sorted(vac.get("ips") or []),
            "connected": connected,
            "last_ip": str(vac.get("last_ip") or ""),
            "last_http_at": str(vac.get("last_http_at") or ""),
            "last_http_route": str(vac.get("last_http_route") or ""),
            "last_http_path": str(vac.get("last_http_path") or ""),
            "last_http_remote": str(vac.get("last_http_remote") or ""),
            "last_http_host": str(vac.get("last_http_host") or ""),
            "last_mqtt_at": str(vac.get("last_mqtt_at") or ""),
            "last_mqtt_topic": str(vac.get("last_mqtt_topic") or ""),
            "last_mqtt_direction": str(vac.get("last_mqtt_direction") or ""),
            "last_mqtt_payload_preview": str(vac.get("last_mqtt_payload_preview") or ""),
            "last_disconnect_at": str(vac.get("last_disconnect_at") or ""),
            "last_message_at": last_message_at,
            "last_message_source": str(vac.get("last_message_source") or ""),
            "onboarding_steps": onboarding_steps,
            "onboarding": {
                "required_steps": list(REQUIRED_ONBOARDING_STEPS),
                "step_labels": dict(ONBOARDING_STEP_LABELS),
                "missing_steps": missing_steps,
                "has_required_messages": has_required_messages,
                "has_public_key": has_public_key,
                "public_key_ready": public_key_ready,
                "status": onboarding_status,
                "guidance": guidance,
                "key_state": key_state,
            },
        }

    def _load_public_key_dids_locked(self) -> set[str]:
        dids, _, _ = self._load_key_state_locked()
        return set(dids)

    def _load_key_state_locked(self) -> tuple[set[str], dict[str, str], dict[str, dict[str, Any]]]:
        path = self.key_state_file
        if path is None or not path.exists():
            self._key_cache_mtime_ns = None
            self._key_cache_dids = set()
            self._key_cache_models = {}
            self._key_cache_details = {}
            return set(), {}, {}
        try:
            mtime_ns = path.stat().st_mtime_ns
        except OSError:
            return set(self._key_cache_dids), dict(self._key_cache_models), dict(self._key_cache_details)
        if self._key_cache_mtime_ns == mtime_ns:
            return set(self._key_cache_dids), dict(self._key_cache_models), dict(self._key_cache_details)
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return set(self._key_cache_dids), dict(self._key_cache_models), dict(self._key_cache_details)
        devices = parsed.get("devices") if isinstance(parsed, dict) else None
        dids: set[str] = set()
        models: dict[str, str] = {}
        details: dict[str, dict[str, Any]] = {}
        if isinstance(devices, dict):
            for did, item in devices.items():
                if not isinstance(did, str) or not isinstance(item, dict):
                    continue
                modulus_hex = str(item.get("modulus_hex") or "").strip()
                if modulus_hex:
                    dids.add(did)
                pid = self._extract_pid_from_key_state_item(item)
                if pid:
                    models[did] = pid
                details[did] = self._extract_key_state_details(item)
        self._key_cache_mtime_ns = mtime_ns
        self._key_cache_dids = dids
        self._key_cache_models = models
        self._key_cache_details = details
        return set(dids), dict(models), dict(details)

    def _resolve_did_from_pid_locked(self, pid: str) -> str | None:
        model = pid.strip().lower()
        if not model:
            return None
        _, models, _ = self._load_key_state_locked()
        matches = [did for did, did_model in models.items() if did_model.lower() == model]
        if len(matches) == 1:
            return matches[0]
        return None

    @staticmethod
    def _extract_pid_from_key_state_item(item: dict[str, Any]) -> str:
        direct_pid = str(item.get("pid") or item.get("model") or "").strip()
        if direct_pid:
            return direct_pid

        def _extract_from_query(query: str) -> str:
            parsed = parse_qs(query, keep_blank_values=True)
            for key in ("pid", "m", "model"):
                values = parsed.get(key) or []
                for value in values:
                    candidate = str(value).strip()
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

    @staticmethod
    def _extract_key_state_details(item: dict[str, Any]) -> dict[str, Any]:
        query_samples = 0
        header_samples = 0
        max_signature_len = 0

        sample_list = item.get("samples")
        if isinstance(sample_list, list):
            for sample in sample_list:
                if not isinstance(sample, dict):
                    continue
                canonical = str(sample.get("canonical") or "").strip()
                signature_b64 = str(sample.get("signature_b64") or "").strip()
                if not canonical or not signature_b64:
                    continue
                query_samples += 1
                try:
                    sig_len = len(base64.b64decode(signature_b64, validate=True))
                    if sig_len > max_signature_len:
                        max_signature_len = sig_len
                except Exception:
                    pass

        header_list = item.get("header_samples")
        if isinstance(header_list, list):
            for sample in header_list:
                if not isinstance(sample, dict):
                    continue
                signature_b64 = str(sample.get("signature_b64") or "").strip()
                if not signature_b64:
                    continue
                header_samples += 1
                sig_len_raw = str(sample.get("signature_len") or "").strip()
                sig_len = 0
                if sig_len_raw.isdigit():
                    sig_len = int(sig_len_raw)
                else:
                    try:
                        sig_len = len(base64.b64decode(signature_b64, validate=True))
                    except Exception:
                        sig_len = 0
                if sig_len > max_signature_len:
                    max_signature_len = sig_len

        recovery = item.get("recovery")
        recovery_state = ""
        recovery_note = ""
        recovery_error = ""
        recovery_started_at = ""
        recovery_finished_at = ""
        if isinstance(recovery, dict):
            recovery_state = str(recovery.get("state") or "").strip()
            recovery_note = str(recovery.get("note") or "").strip()
            recovery_error = str(recovery.get("error") or "").strip()
            recovery_started_at = str(recovery.get("started_at") or "").strip()
            recovery_finished_at = str(recovery.get("finished_at") or "").strip()
        return {
            "query_samples": query_samples,
            "header_samples": header_samples,
            "max_signature_len": max_signature_len,
            "has_modulus": bool(str(item.get("modulus_hex") or "").strip()),
            "recovery_state": recovery_state,
            "recovery_note": recovery_note,
            "recovery_error": recovery_error,
            "recovery_started_at": recovery_started_at,
            "recovery_finished_at": recovery_finished_at,
        }

    @staticmethod
    def _extract_did_from_topic(topic: str) -> str | None:
        identifier, _ = RuntimeState._extract_identity_from_topic(topic)
        return identifier

    @staticmethod
    def _extract_identity_from_topic(topic: str) -> tuple[str | None, str | None]:
        d_match = _D_TOPIC_RE.match(topic)
        if d_match:
            return d_match.group(1), "did"
        m_match = _M_TOPIC_RE.match(topic)
        if m_match:
            return m_match.group(1), "duid"
        return None, None
