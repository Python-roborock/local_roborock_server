"""Config-driven release supervisor and admin/API server."""

from __future__ import annotations

import argparse
import asyncio
import base64
from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import secrets
import signal
import socket
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
import uvicorn

from .certs import CertificateManager
from .bundled_backend.shared.data_helpers import utcnow_iso
from .bundled_backend.shared.runtime_state import ONBOARDING_STEP_LABELS, REQUIRED_ONBOARDING_STEPS
from .cloud import CloudImportManager
from .config import AppConfig, AppPaths, load_config, resolve_paths
from .standalone_admin import register_standalone_admin_routes
from .backend import (
    MqttTlsProxy,
    MqttTopicBridge,
    RuntimeCredentialsStore,
    RuntimeState,
    ServerContext,
    _extract_inventory_vacuums,
    _load_inventory,
    _merge_vacuum_state,
    append_jsonl,
    classify_host,
    dispatch_plugin_zip_request,
    default_endpoint_rules,
    PluginZipDispatchError,
    resolve_route,
    setup_file_logger,
    start_broker,
    strip_roborock_prefix,
)
from shared.protocol_auth import ProtocolAuthStore
from https_server.routes.auth.service import (
    build_login_data_response,
    cloud_login_data_required_response,
    load_cloud_user_data,
)
from .bundled_backend.shared.zone_ranges_store import ZoneRangesStore
from .security import AdminSessionManager


ALL_HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
PROTOCOL_AUTH_SYNC_PATH = "/internal/protocol/user-data"
PROTOCOL_AUTH_SYNC_SECRET_HEADER = "x-local-sync-secret"
PROJECT_SUPPORT = {
    "title": "Support This Project",
    "text": (
        "If this project helps you keep your Roborock stack local, you can support ongoing research "
        "and maintenance here, or use the Roborock discount and affiliate links below:"
    ),
    "links": [
        {"label": "Buy Me a Coffee", "url": "https://buymeacoffee.com/lashl"},
        {"label": "PayPal", "url": "https://paypal.me/LLashley304"},
        {
            "label": "5% Off Roborock Store",
            "url": "https://us.roborock.com/discount/RRSAP202602071713342D18X?redirect=%2Fpages%2Froborock-store%3Fuuid%3DEQe6p1jdZczHEN4Q0nbsG9sZRm0RK1gW5eSM%252FCzcW4Q%253D",
        },
        {"label": "Roborock Affiliate", "url": "https://roborock.pxf.io/B0VYV9"},
        {"label": "Amazon Affiliate", "url": "https://amzn.to/4cx8zg3"},
    ],
}


def _request_query_params(request: Request) -> dict[str, list[str]]:
    return parse_qs(request.url.query, keep_blank_values=True)


def _request_body_params(raw_body: bytes, *, content_type: str = "") -> tuple[str, dict[str, list[str]]]:
    body_text = raw_body.decode("utf-8", errors="replace")
    if not body_text:
        return "", {}
    body_params = parse_qs(body_text, keep_blank_values=True)
    stripped = body_text.lstrip()
    if "json" in content_type.lower() or stripped.startswith(("{", "[")):
        body_params = dict(body_params)
        body_params.setdefault("__json", [body_text])
    return body_text, body_params


def _pick_first_header(headers: dict[str, str], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = str(headers.get(key, "")).strip()
        if value:
            return value
    return ""


def _request_json_object(body_params: dict[str, list[str]]) -> dict[str, Any]:
    for raw in body_params.get("__json") or []:
        try:
            parsed = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def _request_value(
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    *keys: str,
) -> str:
    json_body = _request_json_object(body_params)
    for key in keys:
        for value in query_params.get(key, []):
            candidate = str(value).strip()
            if candidate:
                return candidate
        for value in body_params.get(key, []):
            candidate = str(value).strip()
            if candidate:
                return candidate
        json_value = json_body.get(key)
        candidate = str(json_value).strip() if json_value is not None else ""
        if candidate:
            return candidate
    return ""


def _headers_for_log(headers: dict[str, str]) -> dict[str, str]:
    normalized = dict(headers)
    for key in list(normalized):
        if str(key).strip().lower() == PROTOCOL_AUTH_SYNC_SECRET_HEADER:
            normalized[key] = "<redacted>"
    return normalized


def _extract_explicit_pid(
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
) -> str:
    for key in ("pid", "m", "model"):
        for value in query_params.get(key, []) + body_params.get(key, []):
            candidate = str(value).strip()
            if candidate:
                return candidate
    return ""


def _connectivity_check(host: str, port: int) -> None:
    with socket.create_connection((host, port), timeout=3):
        return


class ManagedFastApiServer:
    """Owns FastAPI/uvicorn lifecycle."""

    def __init__(
        self,
        *,
        app: FastAPI,
        bind_host: str,
        port: int,
        cert_file: Path,
        key_file: Path,
    ) -> None:
        self._app = app
        self._bind_host = bind_host
        self._port = port
        self._cert_file = cert_file
        self._key_file = key_file
        self._server: uvicorn.Server | None = None
        self._serve_task: asyncio.Task[bool] | None = None

    async def start(self) -> None:
        config = uvicorn.Config(
            app=self._app,
            host=self._bind_host,
            port=self._port,
            log_level="warning",
            access_log=False,
            ssl_certfile=str(self._cert_file),
            ssl_keyfile=str(self._key_file),
            ssl_ciphers="DEFAULT:@SECLEVEL=0",
        )
        self._server = uvicorn.Server(config)
        self._serve_task = asyncio.create_task(self._server.serve(), name="release-https-server")
        await self._wait_started()

    async def _wait_started(self) -> None:
        if self._server is None:
            raise RuntimeError("HTTP server was not initialized")
        for _ in range(120):
            if self._server.started:
                return
            await asyncio.sleep(0.05)
        raise RuntimeError("Timed out waiting for HTTPS server startup")

    async def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._serve_task is not None:
            await self._serve_task


def _seed_runtime_vacuums_from_inventory(
    *,
    runtime_state: RuntimeState,
    runtime_credentials: RuntimeCredentialsStore,
    inventory_path: Path,
) -> int:
    try:
        parsed = json.loads(inventory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    if not isinstance(parsed, dict):
        return 0

    seen: set[str] = set()
    seeded = 0
    for source_key in ("devices", "received_devices", "receivedDevices"):
        items = parsed.get(source_key)
        if not isinstance(items, list):
            continue
        for raw in items:
            if not isinstance(raw, dict):
                continue
            duid = str(raw.get("duid") or raw.get("did") or raw.get("device_id") or "").strip()
            if not duid or duid in seen:
                continue
            seen.add(duid)
            model = str(raw.get("model") or "").strip()
            runtime_state.upsert_vacuum(
                duid,
                name=str(raw.get("name") or raw.get("device_name") or "").strip() or None,
                local_key=runtime_credentials.resolve_device_localkey(
                    duid=duid,
                    model=model,
                    name=str(raw.get("name") or raw.get("device_name") or "").strip(),
                    product_id=str(raw.get("product_id") or raw.get("productId") or "").strip(),
                    source="inventory_seed",
                    assign_if_missing=True,
                )
                or None,
                source=source_key,
            )
            seeded += 1
    return seeded


def _seed_runtime_vacuums_from_credentials(
    *,
    runtime_state: RuntimeState,
    runtime_credentials: RuntimeCredentialsStore,
) -> int:
    seeded = 0
    for raw in runtime_credentials.devices():
        if not isinstance(raw, dict):
            continue
        did = str(raw.get("did") or "").strip()
        duid = str(raw.get("duid") or "").strip()
        identifier = duid or did
        if not identifier:
            continue
        runtime_state.upsert_vacuum(
            identifier,
            did=did or None,
            id_kind="duid" if duid else "did",
            name=str(raw.get("name") or "").strip() or None,
            local_key=str(raw.get("localkey") or "").strip() or None,
            source="runtime_credentials",
            last_mqtt_at=str(raw.get("last_mqtt_seen_at") or "").strip() or None,
            last_nc_at=str(raw.get("last_nc_at") or "").strip() or None,
            restored_activity=bool(str(raw.get("last_mqtt_seen_at") or "").strip()),
        )
        seeded += 1
    return seeded


class ReleaseSupervisor:
    """Owns the release stack lifecycle."""

    def __init__(
        self,
        *,
        config: AppConfig,
        paths: AppPaths,
        enable_standalone_admin: bool = True,
    ) -> None:
        self.config = config
        self.paths = paths
        self.enable_standalone_admin = bool(enable_standalone_admin)

        self.root_logger = logging.getLogger("roborock_local_server")
        self.root_logger.setLevel(logging.INFO)
        if not self.root_logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
            self.root_logger.addHandler(handler)

        self._broker: Any | None = None
        self._topic_bridge: MqttTopicBridge | None = None
        self._mqtt_proxy: MqttTlsProxy | None = None
        self._http_server: ManagedFastApiServer | None = None
        self._renew_task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()

        self.certificate_manager = CertificateManager(config=config, paths=paths)
        self.session_manager = AdminSessionManager(
            secret=config.admin.session_secret,
            ttl_seconds=config.admin.session_ttl_seconds,
        )
        self.cloud_manager = CloudImportManager(
            inventory_path=self.paths.inventory_path,
            snapshot_path=self.paths.cloud_snapshot_path,
        )
        self.protocol_auth = ProtocolAuthStore(
            self.paths.cloud_snapshot_path,
            session_store_path=self.paths.protocol_auth_sessions_path,
        )

        self.loggers = self._setup_loggers()
        if not self.paths.device_key_state_path.exists():
            self.paths.device_key_state_path.parent.mkdir(parents=True, exist_ok=True)
            self.paths.device_key_state_path.write_text('{"devices":{}}\n', encoding="utf-8")
        self.runtime_credentials = RuntimeCredentialsStore(
            self.paths.runtime_credentials_path,
            inventory_path=self.paths.inventory_path,
            key_state_file=self.paths.device_key_state_path,
        )
        self.runtime_state = RuntimeState(
            log_dir=self.paths.runtime_dir,
            key_state_file=self.paths.device_key_state_path,
            runtime_credentials=self.runtime_credentials,
        )
        self.runtime_state.set_service(
            "https_server",
            running=False,
            required=True,
            enabled=True,
            detail=f"{self.config.network.bind_host}:{self.config.network.https_port}",
        )
        self.runtime_state.set_service(
            "mqtt_tls_proxy",
            running=False,
            required=True,
            enabled=True,
            detail=f"{self.config.network.bind_host}:{self.config.network.mqtt_tls_port}",
        )
        self.runtime_state.set_service(
            "mqtt_backend_broker",
            running=False,
            required=True,
            enabled=True,
            detail=f"{self.config.broker.mode}:{self.config.broker.host}:{self.config.broker.port}",
        )
        self.runtime_state.set_service(
            "mqtt_topic_bridge",
            running=False,
            required=False,
            enabled=self.config.broker.enable_topic_bridge,
            detail="rr/m <-> rr/d",
        )

        self._bootstrap_credentials = self._derive_bootstrap_credentials()
        self.runtime_credentials.update_base(
            api_host=self.config.network.stack_fqdn,
            mqtt_host=self.config.network.stack_fqdn,
            wood_host=self.config.network.stack_fqdn,
            region=self.config.network.region,
            localkey=self._bootstrap_credentials["localkey"],
            duid=self._bootstrap_credentials["duid"],
            mqtt_usr=self._bootstrap_credentials["mqtt_usr"],
            mqtt_passwd=self._bootstrap_credentials["mqtt_passwd"],
            mqtt_clientid=self._bootstrap_credentials["mqtt_clientid"],
            https_port=self.config.network.https_port,
            mqtt_tls_port=self.config.network.mqtt_tls_port,
            mqtt_backend_port=self.config.broker.port,
        )
        self.runtime_credentials.sync_inventory()

        self.context = ServerContext(
            api_host=self.config.network.stack_fqdn,
            mqtt_host=self.config.network.stack_fqdn,
            wood_host=self.config.network.stack_fqdn,
            region=self.config.network.region,
            localkey=self._bootstrap_credentials["localkey"],
            duid=self._bootstrap_credentials["duid"],
            mqtt_usr=self._bootstrap_credentials["mqtt_usr"],
            mqtt_passwd=self._bootstrap_credentials["mqtt_passwd"],
            mqtt_clientid=self._bootstrap_credentials["mqtt_clientid"],
            mqtt_tls_port=self.config.network.mqtt_tls_port,
            http_jsonl=self.paths.http_jsonl_path,
            mqtt_jsonl=self.paths.mqtt_jsonl_path,
            loggers=self.loggers,
            key_state_file=self.paths.device_key_state_path,
            bootstrap_encryption_enabled=True,
            runtime_state=self.runtime_state,
            runtime_credentials=self.runtime_credentials,
            zone_ranges_store=self._init_zone_ranges_store(),
        )
        self.endpoint_rules = default_endpoint_rules()
        self.app = self._create_app()

    def _init_zone_ranges_store(self) -> ZoneRangesStore:
        store = ZoneRangesStore(self.paths.http_jsonl_path.parent)
        if not store._data:
            added = store.seed_from_mqtt_jsonl(self.paths.mqtt_jsonl_path)
            if added:
                self.root_logger.info("Seeded zone ranges store with %d entries from MQTT log", added)
        return store

    def _setup_loggers(self) -> dict[str, logging.Logger]:
        self.paths.runtime_dir.mkdir(parents=True, exist_ok=True)
        return {
            "api": setup_file_logger("api", self.paths.runtime_dir / "api_server.log"),
            "iot": setup_file_logger("iot", self.paths.runtime_dir / "iot_server.log"),
            "wood": setup_file_logger("wood", self.paths.runtime_dir / "wood_server.log"),
            "https": setup_file_logger("https", self.paths.runtime_dir / "https_server.log"),
            "mqtt": setup_file_logger("mqtt", self.paths.runtime_dir / "mqtt_server.log"),
            "unknown": setup_file_logger("unknown", self.paths.runtime_dir / "unknown_server.log"),
        }

    def _derive_bootstrap_credentials(self) -> dict[str, str]:
        persisted_duid = str(self.runtime_credentials.bootstrap_value("duid", "") or "").strip()
        localkey = (
            self.config.network.localkey
            or str(self.runtime_credentials.bootstrap_value("localkey", "") or "").strip()
            or secrets.token_hex(8)
        )
        duid = self.config.network.duid or persisted_duid or f"rr_{secrets.token_hex(8)}"
        mqtt_usr = (
            self.config.network.mqtt_username
            or str(self.runtime_credentials.bootstrap_value("mqtt_usr", "") or "").strip()
            or hashlib.md5(duid.encode("utf-8")).hexdigest()[:16]
        )
        mqtt_passwd = (
            self.config.network.mqtt_password
            or str(self.runtime_credentials.bootstrap_value("mqtt_passwd", "") or "").strip()
            or secrets.token_hex(6)
        )
        mqtt_clientid = (
            self.config.network.mqtt_client_id
            or str(self.runtime_credentials.bootstrap_value("mqtt_clientid", "") or "").strip()
            or duid
        )
        return {
            "localkey": localkey,
            "duid": duid,
            "mqtt_usr": mqtt_usr,
            "mqtt_passwd": mqtt_passwd,
            "mqtt_clientid": mqtt_clientid,
        }

    def _authenticated(self, request: Request) -> bool:
        return self.session_manager.verify(request.cookies.get(self.session_manager.cookie_name)) is not None

    def _require_admin(self, request: Request) -> None:
        if not self._authenticated(request):
            raise HTTPException(status_code=401, detail="Authentication required")

    @staticmethod
    def _normalized_path(path: str) -> str:
        normalized = str(path or "").rstrip("/")
        return normalized or "/"

    @classmethod
    def _is_public_protocol_path(cls, clean_path: str) -> bool:
        normalized = cls._normalized_path(clean_path)
        return normalized in {
            "/",
            "/region",
            "/time",
            "/location",
            "/nc/prepare",
            "/api/v1/getUrlByEmail",
            "/api/v1/ml/c",
            "/api/v1/sendEmailCode",
            "/api/v1/sendSmsCode",
            "/api/v1/validateEmailCode",
            "/api/v1/validateSmsCode",
            "/api/v1/loginWithCode",
            "/api/v3/key/sign",
            "/api/v3/sms/sendCode",
            "/api/v4/key/captcha",
            "/api/v4/email/code/send",
            "/api/v4/sms/code/send",
            "/api/v4/email/code/validate",
            "/api/v4/sms/code/validate",
            "/api/v4/auth/email/login/code",
            "/api/v4/auth/phone/login/code",
            "/api/v4/auth/mobile/login/code",
            "/api/v5/email/code/send",
            "/api/v5/sms/code/send",
            "/api/v5/email/code/validate",
            "/api/v5/sms/code/validate",
            "/api/v5/auth/email/login/code",
            "/api/v5/auth/phone/login/code",
            "/api/v5/auth/mobile/login/code",
            "/api/v1/country/version",
            "/api/v1/country/list",
            "/api/v1/appconfig",
            "/api/v2/appconfig",
            "/api/v1/appfeatureplugin",
            "/api/v1/appplugin",
            "/api/v1/plugins",
            "/api/v4/agreement/latest",
        }

    @classmethod
    def _is_code_send_path(cls, clean_path: str) -> bool:
        normalized = cls._normalized_path(clean_path)
        return normalized in {
            "/api/v1/sendEmailCode",
            "/api/v1/sendSmsCode",
            "/api/v3/sms/sendCode",
            "/api/v4/email/code/send",
            "/api/v4/sms/code/send",
            "/api/v5/email/code/send",
            "/api/v5/sms/code/send",
        }

    @classmethod
    def _is_code_validate_path(cls, clean_path: str) -> bool:
        normalized = cls._normalized_path(clean_path)
        return normalized in {
            "/api/v1/validateEmailCode",
            "/api/v1/validateSmsCode",
            "/api/v4/email/code/validate",
            "/api/v4/sms/code/validate",
            "/api/v5/email/code/validate",
            "/api/v5/sms/code/validate",
        }

    @classmethod
    def _is_code_submit_path(cls, clean_path: str) -> bool:
        normalized = cls._normalized_path(clean_path)
        return normalized in {
            "/api/v1/loginWithCode",
            "/api/v4/auth/email/login/code",
            "/api/v4/auth/phone/login/code",
            "/api/v4/auth/mobile/login/code",
            "/api/v5/auth/email/login/code",
            "/api/v5/auth/phone/login/code",
            "/api/v5/auth/mobile/login/code",
        }

    @classmethod
    def _is_password_login_path(cls, clean_path: str) -> bool:
        normalized = cls._normalized_path(clean_path)
        return normalized in {
            "/api/v1/login",
            "/api/v3/auth/email/login",
            "/api/v3/auth/phone/login",
            "/api/v3/auth/mobile/login",
            "/api/v5/auth/email/login/pwd",
            "/api/v5/auth/phone/login/pwd",
            "/api/v5/auth/mobile/login/pwd",
        }

    @classmethod
    def _is_password_reset_path(cls, clean_path: str) -> bool:
        normalized = cls._normalized_path(clean_path)
        return normalized in {
            "/api/v5/user/password/mobile/reset",
            "/api/v5/user/password/email/reset",
        }

    @classmethod
    def _required_protocol_auth(cls, clean_path: str) -> str | None:
        normalized = cls._normalized_path(clean_path)
        if cls._is_public_protocol_path(normalized):
            return None
        if normalized.startswith(("/user/", "/v2/user/", "/v3/user/")):
            return "hawk"
        if normalized.startswith("/api/"):
            return "token"
        return None

    def _login_send_success_payload(self) -> dict[str, Any]:
        return {"code": 200, "msg": "success", "data": {"sent": True, "validForSec": 300}}

    def _login_validate_success_payload(self) -> dict[str, Any]:
        return {"code": 200, "msg": "success", "data": {"valid": True}}

    @staticmethod
    def _unsupported_password_login_payload() -> dict[str, Any]:
        return {
            "code": 40031,
            "msg": "password_login_not_supported",
            "data": {"reason": "code_login_only"},
        }

    @staticmethod
    def _protocol_auth_failure_payload(reason: str, auth_kind: str) -> dict[str, Any]:
        return {
            "code": 40101,
            "msg": "authentication_required",
            "data": {"reason": reason, "auth": auth_kind},
        }

    def _protocol_auth_not_ready_payload(self) -> tuple[int, dict[str, Any]]:
        availability = self.protocol_auth.availability()
        payload = cloud_login_data_required_response(
            self.context,
            reason=availability.reason,
            missing_fields=list(availability.missing_fields) or None,
        )
        return 412, payload

    @classmethod
    def _is_protocol_sync_path(cls, clean_path: str) -> bool:
        return cls._normalized_path(clean_path) == PROTOCOL_AUTH_SYNC_PATH

    @staticmethod
    def _protocol_sync_success_payload(*, source: str) -> dict[str, Any]:
        return {
            "code": 200,
            "msg": "success",
            "data": {"stored": True, "source": source},
        }

    @staticmethod
    def _protocol_sync_failure_payload(*, reason: str, detail: str = "") -> dict[str, Any]:
        payload: dict[str, Any] = {"reason": reason}
        if detail:
            payload["detail"] = detail
        return {"code": 40041, "msg": "protocol_sync_failed", "data": payload}

    def _sync_secret_matches(self, headers: dict[str, str]) -> bool:
        provided = _pick_first_header(headers, ("x-local-sync-secret", "X-Local-Sync-Secret"))
        expected = str(self.config.admin.session_secret or "").strip()
        return bool(expected) and secrets.compare_digest(provided, expected)

    async def _handle_protocol_sync_route(
        self,
        *,
        method: str,
        clean_path: str,
        headers: dict[str, str],
        body_params: dict[str, list[str]],
    ) -> tuple[str, int, dict[str, Any]] | None:
        if not self._is_protocol_sync_path(clean_path):
            return None
        if method.upper() != "POST":
            return "protocol_auth_sync_method_not_allowed", 405, self._protocol_sync_failure_payload(
                reason="method_not_allowed"
            )
        if not self._sync_secret_matches(headers):
            return "protocol_auth_sync_unauthorized", 401, self._protocol_sync_failure_payload(
                reason="invalid_sync_secret"
            )

        payload = _request_json_object(body_params)
        user_data = payload.get("user_data")
        if not isinstance(user_data, dict):
            return "protocol_auth_sync_invalid_payload", 400, self._protocol_sync_failure_payload(
                reason="missing_user_data"
            )

        source = str(payload.get("source") or "mitm_cloud_login").strip() or "mitm_cloud_login"
        try:
            self.protocol_auth.upsert_user_data(user_data, source=source)
        except ValueError as exc:
            return "protocol_auth_sync_invalid_payload", 400, self._protocol_sync_failure_payload(
                reason="invalid_user_data",
                detail=str(exc),
            )

        return "protocol_auth_sync", 200, self._protocol_sync_success_payload(source=source)

    async def _handle_protocol_login_route(
        self,
        *,
        clean_path: str,
        query_params: dict[str, list[str]],
        body_params: dict[str, list[str]],
    ) -> tuple[str, int, dict[str, Any]] | None:
        normalized = self._normalized_path(clean_path)
        if self._is_code_send_path(normalized):
            account = _request_value(
                query_params,
                body_params,
                "email",
                "username",
                "account",
                "mobile",
                "phone",
            )
            base_url = _request_value(query_params, body_params, "base_url", "baseUrl")
            try:
                result = await self.cloud_manager.request_code(email=account, base_url=base_url)
            except Exception as exc:  # noqa: BLE001
                result = {"success": False, "step": "code_request_failed", "error": str(exc)}
                self.runtime_state.record_cloud_request(result)
                return "protocol_login_request_code", 400, {
                    "code": 40021,
                    "msg": "code_request_failed",
                    "data": {"error": str(exc)},
                }
            self.runtime_state.record_cloud_request(result)
            return "protocol_login_request_code", 200, self._login_send_success_payload()

        if self._is_code_validate_path(normalized):
            return "protocol_login_validate_code", 200, self._login_validate_success_payload()

        if self._is_code_submit_path(normalized):
            account = _request_value(
                query_params,
                body_params,
                "email",
                "username",
                "account",
                "mobile",
                "phone",
            )
            base_url = _request_value(query_params, body_params, "base_url", "baseUrl")
            session_id = _request_value(query_params, body_params, "session_id", "sessionId")
            if not session_id:
                session_id = self.cloud_manager.find_pending_session_id(email=account, base_url=base_url)
            code = _request_value(
                query_params,
                body_params,
                "code",
                "verifyCode",
                "emailCode",
                "smsCode",
            )
            try:
                result = await self.cloud_manager.submit_code(session_id=session_id, code=code)
                self.refresh_inventory_state()
            except Exception as exc:  # noqa: BLE001
                result = {"success": False, "step": "code_submit_failed", "error": str(exc)}
                self.runtime_state.record_cloud_request(result)
                return "protocol_login_submit_code", 400, {
                    "code": 40022,
                    "msg": "code_submit_failed",
                    "data": {"error": str(exc)},
                }
            cloud_user_data = load_cloud_user_data(self.context)
            if cloud_user_data is None:
                self.runtime_state.record_cloud_request(result)
                status_code, response_payload = self._protocol_auth_not_ready_payload()
                return "protocol_login_submit_code_not_ready", status_code, response_payload
            try:
                issued_user_data = self.protocol_auth.issue_local_session(
                    cloud_user_data,
                    source="protocol_code_login",
                )
            except ValueError as exc:
                self.runtime_state.record_cloud_request(result)
                return "protocol_login_submit_code", 400, {
                    "code": 40023,
                    "msg": "local_session_issue_failed",
                    "data": {"error": str(exc)},
                }
            self.runtime_state.record_cloud_request(result)
            return "protocol_login_submit_code", 200, build_login_data_response(self.context, issued_user_data)

        if self._is_password_login_path(normalized) or self._is_password_reset_path(normalized):
            return "protocol_login_password_unsupported", 400, self._unsupported_password_login_payload()

        return None

    async def _handle_roborock_request(self, request: Request) -> Response:
        host = (request.headers.get("host") or "").strip()
        group = classify_host(host)
        logger = self.context.loggers.get(group, self.context.loggers["unknown"])
        raw_body = await request.body()
        clean_path = strip_roborock_prefix(request.url.path)
        query_params = _request_query_params(request)
        body_text, body_params = _request_body_params(
            raw_body,
            content_type=str(request.headers.get("content-type") or ""),
        )
        body_sha256 = hashlib.sha256(raw_body).hexdigest()
        is_protocol_sync_request = self._is_protocol_sync_path(clean_path)

        if host:
            host_no_port = host.split(":", 1)[0].strip()
            if host_no_port:
                query_params = {key: list(values) for key, values in query_params.items()}
                query_params.setdefault("__host", [host_no_port])

        explicit_did = self.context.extract_explicit_did(query_params, body_params)
        explicit_pid = _extract_explicit_pid(query_params, body_params)
        key_cache = self.context.device_key_cache()

        query_sample_added = False
        header_sample_added = False
        if key_cache is not None and explicit_did:
            if request.url.query:
                try:
                    query_sample_added = key_cache.add_signed_query(explicit_did, request.url.query)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("key_cache add_signed_query failed did=%s: %s", explicit_did, exc)
            sign = _pick_first_header(
                dict(request.headers),
                ("sign", "x-sign", "x_roborock_sign", "x-roborock-sign"),
            )
            if sign:
                nonce = _pick_first_header(
                    dict(request.headers),
                    ("nonce", "x-nonce", "x_roborock_nonce", "x-roborock-nonce"),
                )
                ts = _pick_first_header(
                    dict(request.headers),
                    ("ts", "timestamp", "x-timestamp", "x_roborock_ts", "x-roborock-ts"),
                )
                try:
                    header_sample_added = key_cache.add_header_signature(
                        explicit_did,
                        method=request.method,
                        path=request.url.path,
                        query=request.url.query,
                        nonce=nonce,
                        ts=ts,
                        signature_b64=sign,
                        body_sha256=body_sha256,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("key_cache add_header_signature failed did=%s: %s", explicit_did, exc)

        raw_path = request.url.path
        if request.url.query:
            raw_path += f"?{request.url.query}"
        client_host = request.client.host if request.client else "-"
        client_port = request.client.port if request.client else 0
        entry: dict[str, object] = {
            "time": utcnow_iso(),
            "server": group,
            "host": host,
            "method": request.method,
            "raw_path": raw_path,
            "clean_path": clean_path,
            "query": {key: value for key, value in query_params.items()},
            "headers": _headers_for_log(dict(request.headers)),
            "body_len": len(raw_body),
            "body_sha256": body_sha256,
            "remote": f"{client_host}:{client_port}",
        }
        if explicit_did:
            entry["did"] = explicit_did
        if explicit_pid:
            entry["pid"] = explicit_pid
        if is_protocol_sync_request:
            entry["body_redacted"] = True
        else:
            entry["body_b64"] = base64.b64encode(raw_body).decode("ascii")
        if body_text and not is_protocol_sync_request:
            entry["body_text"] = body_text
            try:
                entry["body_json"] = json.loads(body_text)
            except json.JSONDecodeError:
                pass
            if body_params:
                entry["body_form"] = {key: value for key, value in body_params.items()}
        if query_sample_added or header_sample_added:
            entry["key_state_capture"] = {
                "did": explicit_did,
                "query_sample_added": query_sample_added,
                "header_sample_added": header_sample_added,
            }

        custom_sync = await self._handle_protocol_sync_route(
            method=request.method,
            clean_path=clean_path,
            headers=dict(request.headers),
            body_params=body_params,
        )
        if custom_sync is not None:
            route_name, status_code, response_payload = custom_sync
            entry["route"] = route_name
            entry["response_json"] = response_payload
            try:
                self.runtime_state.record_http_event(
                    event_time=str(entry["time"]),
                    route_name=route_name,
                    clean_path=clean_path,
                    raw_path=raw_path,
                    method=request.method,
                    host=host,
                    remote=str(entry["remote"]),
                    did=explicit_did or None,
                    pid=explicit_pid or None,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("runtime_state record_http_event failed: %s", exc)
            append_jsonl(self.context.http_jsonl, entry)
            logger.info(
                "%s %s host=%s route=%s status=%d body_sha256=%s",
                request.method,
                clean_path,
                host or "-",
                route_name,
                status_code,
                body_sha256[:16],
            )
            return JSONResponse(response_payload, status_code=status_code)

        custom_login = await self._handle_protocol_login_route(
            clean_path=clean_path,
            query_params=query_params,
            body_params=body_params,
        )
        if custom_login is not None:
            route_name, status_code, response_payload = custom_login
            entry["route"] = route_name
            entry["response_json"] = response_payload
            try:
                self.runtime_state.record_http_event(
                    event_time=str(entry["time"]),
                    route_name=route_name,
                    clean_path=clean_path,
                    raw_path=raw_path,
                    method=request.method,
                    host=host,
                    remote=str(entry["remote"]),
                    did=explicit_did or None,
                    pid=explicit_pid or None,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("runtime_state record_http_event failed: %s", exc)
            append_jsonl(self.context.http_jsonl, entry)
            logger.info(
                "%s %s host=%s route=%s status=%d body_sha256=%s",
                request.method,
                clean_path,
                host or "-",
                route_name,
                status_code,
                body_sha256[:16],
            )
            return JSONResponse(response_payload, status_code=status_code)

        required_auth = self._required_protocol_auth(clean_path)
        if required_auth is not None:
            availability = self.protocol_auth.availability()
            if availability.user is None:
                status_code, response_payload = self._protocol_auth_not_ready_payload()
                route_name = f"{required_auth}_auth_not_ready"
                entry["route"] = route_name
                entry["response_json"] = response_payload
                try:
                    self.runtime_state.record_http_event(
                        event_time=str(entry["time"]),
                        route_name=route_name,
                        clean_path=clean_path,
                        raw_path=raw_path,
                        method=request.method,
                        host=host,
                        remote=str(entry["remote"]),
                        did=explicit_did or None,
                        pid=explicit_pid or None,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("runtime_state record_http_event failed: %s", exc)
                append_jsonl(self.context.http_jsonl, entry)
                logger.info(
                    "%s %s host=%s route=%s status=%d body_sha256=%s",
                    request.method,
                    clean_path,
                    host or "-",
                    route_name,
                    status_code,
                    body_sha256[:16],
                )
                return JSONResponse(response_payload, status_code=status_code)

            if required_auth == "token":
                authenticated, auth_reason = self.protocol_auth.verify_token(request.headers)
            else:
                authenticated, auth_reason = self.protocol_auth.verify_hawk(
                    path=self._normalized_path(clean_path),
                    query_params=query_params,
                    body_params=body_params,
                    headers=request.headers,
                )
            if not authenticated:
                route_name = f"{required_auth}_auth_failed"
                response_payload = self._protocol_auth_failure_payload(auth_reason, required_auth)
                entry["route"] = route_name
                entry["response_json"] = response_payload
                try:
                    self.runtime_state.record_http_event(
                        event_time=str(entry["time"]),
                        route_name=route_name,
                        clean_path=clean_path,
                        raw_path=raw_path,
                        method=request.method,
                        host=host,
                        remote=str(entry["remote"]),
                        did=explicit_did or None,
                        pid=explicit_pid or None,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("runtime_state record_http_event failed: %s", exc)
                append_jsonl(self.context.http_jsonl, entry)
                logger.info(
                    "%s %s host=%s route=%s status=401 body_sha256=%s",
                    request.method,
                    clean_path,
                    host or "-",
                    route_name,
                    body_sha256[:16],
                )
                return JSONResponse(response_payload, status_code=401)

        try:
            plugin_dispatch = await dispatch_plugin_zip_request(
                clean_path=clean_path,
                query_params=query_params,
                runtime_dir=self.paths.runtime_dir,
            )
        except PluginZipDispatchError as exc:
            route_name = exc.route_name
            plugin_source = exc.source_url
            error_payload = {
                "success": False,
                "code": 502,
                "msg": "plugin_proxy_failed",
                "data": {"source": plugin_source, "error": str(exc)},
            }
            entry["route"] = route_name
            entry["plugin_source"] = plugin_source
            entry["response_json"] = error_payload
            try:
                self.runtime_state.record_http_event(
                    event_time=str(entry["time"]),
                    route_name=route_name,
                    clean_path=clean_path,
                    raw_path=raw_path,
                    method=request.method,
                    host=host,
                    remote=str(entry["remote"]),
                    did=explicit_did or None,
                    pid=explicit_pid or None,
                )
            except Exception as record_exc:  # noqa: BLE001
                logger.warning("runtime_state record_http_event failed: %s", record_exc)
            append_jsonl(self.context.http_jsonl, entry)
            logger.warning(
                "%s %s host=%s route=%s plugin_source=%s error=%s",
                request.method,
                clean_path,
                host or "-",
                route_name,
                plugin_source,
                exc,
            )
            return JSONResponse(error_payload, status_code=502)

        if plugin_dispatch is not None:
            route_name, plugin_source, response = plugin_dispatch
            entry["route"] = route_name
            entry["plugin_source"] = plugin_source
            entry["response_meta"] = {
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type", ""),
                "cache": response.headers.get("X-RR-Plugin-Cache", ""),
            }
            try:
                self.runtime_state.record_http_event(
                    event_time=str(entry["time"]),
                    route_name=route_name,
                    clean_path=clean_path,
                    raw_path=raw_path,
                    method=request.method,
                    host=host,
                    remote=str(entry["remote"]),
                    did=explicit_did or None,
                    pid=explicit_pid or None,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("runtime_state record_http_event failed: %s", exc)
            append_jsonl(self.context.http_jsonl, entry)
            logger.info(
                "%s %s host=%s route=%s plugin_source=%s cache=%s",
                request.method,
                clean_path,
                host or "-",
                route_name,
                plugin_source,
                response.headers.get("X-RR-Plugin-Cache", ""),
            )
            return response

        route_name, response_payload = resolve_route(
            rules=self.endpoint_rules,
            context=self.context,
            clean_path=clean_path,
            query_params=query_params,
            body_params=body_params,
            method=request.method,
        )
        entry["route"] = route_name
        entry["response_json"] = response_payload
        try:
            self.runtime_state.record_http_event(
                event_time=str(entry["time"]),
                route_name=route_name,
                clean_path=clean_path,
                raw_path=raw_path,
                method=request.method,
                host=host,
                remote=str(entry["remote"]),
                did=explicit_did or None,
                pid=explicit_pid or None,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("runtime_state record_http_event failed: %s", exc)
        append_jsonl(self.context.http_jsonl, entry)
        if key_cache is not None and explicit_did:
            try:
                key_cache.maybe_recover_async(explicit_did)
            except Exception as exc:  # noqa: BLE001
                logger.warning("key_cache maybe_recover_async failed did=%s: %s", explicit_did, exc)

        logger.info(
            "%s %s host=%s route=%s body_sha256=%s",
            request.method,
            clean_path,
            host or "-",
            route_name,
            body_sha256[:16],
        )
        return JSONResponse(response_payload)

    def _status_payload(self) -> dict[str, Any]:
        health = self.runtime_state.health_snapshot()
        merged_vacuums = self._vacuums_payload()["vacuums"]
        health["all_vacuums"] = merged_vacuums
        health["connected_vacuums"] = [vac for vac in merged_vacuums if vac.get("connected")]
        return {
            "health": health,
            "pairing": self.runtime_state.pairing_snapshot(),
            "support": PROJECT_SUPPORT,
            "inventory_path": str(self.paths.inventory_path),
            "cloud_snapshot_path": str(self.paths.cloud_snapshot_path),
        }

    def _vacuums_payload(self) -> dict[str, Any]:
        inventory = _load_inventory(self.paths.inventory_path)
        inventory_vacuums = _extract_inventory_vacuums(self.context, inventory)
        vacuums = _merge_vacuum_state(context=self.context, inventory_vacuums=inventory_vacuums)
        return {
            "inventory_path": str(self.paths.inventory_path),
            "vacuums": vacuums,
        }

    def _onboarding_devices_payload(self) -> dict[str, Any]:
        devices: list[dict[str, Any]] = []
        for vac in self._vacuums_payload()["vacuums"]:
            inventory_source = str(vac.get("inventory_source") or "").strip()
            if not inventory_source:
                continue
            onboarding = dict(vac.get("onboarding") or {})
            key_state = dict(onboarding.get("key_state") or {})
            devices.append(
                {
                    "duid": str(vac.get("duid") or "").strip(),
                    "did": str(vac.get("did") or "").strip(),
                    "name": str(vac.get("name") or vac.get("duid") or "").strip(),
                    "connected": bool(vac.get("connected")),
                    "onboarding": {
                        "has_public_key": bool(onboarding.get("has_public_key")),
                        "status": str(onboarding.get("status") or "").strip(),
                        "guidance": str(onboarding.get("guidance") or "").strip(),
                        "key_state": {
                            "query_samples": int(key_state.get("query_samples") or 0),
                        },
                    },
                }
            )
        return {
            "devices": devices,
            "generated_at": utcnow_iso(),
        }

    def start_onboarding_session(self, *, duid: str) -> dict[str, Any]:
        normalized_duid = str(duid or "").strip()
        if not normalized_duid:
            raise ValueError("duid is required")
        devices = self._onboarding_devices_payload()["devices"]
        matched = next((item for item in devices if item["duid"] == normalized_duid), None)
        if matched is None:
            raise KeyError(normalized_duid)
        return self.runtime_state.start_onboarding_session(
            target_duid=normalized_duid,
            target_name=str(matched.get("name") or ""),
            target_did=str(matched.get("did") or ""),
        )

    def onboarding_session_snapshot(self, *, session_id: str) -> dict[str, Any]:
        snapshot = self.runtime_state.onboarding_session_snapshot()
        normalized_session_id = str(session_id or "").strip()
        if not snapshot.get("active"):
            raise KeyError(normalized_session_id)
        if normalized_session_id and snapshot.get("session_id") != normalized_session_id:
            raise KeyError(normalized_session_id)
        return snapshot

    def clear_onboarding_session(self, *, session_id: str) -> dict[str, Any]:
        snapshot = self.runtime_state.onboarding_session_snapshot()
        normalized_session_id = str(session_id or "").strip()
        if not snapshot.get("active"):
            raise KeyError(normalized_session_id)
        if normalized_session_id and snapshot.get("session_id") != normalized_session_id:
            raise KeyError(normalized_session_id)
        cleared = self.runtime_state.clear_onboarding_session()
        return {"ok": True, "session": cleared}

    def _ui_health_payload(self) -> dict[str, Any]:
        runtime_state = self.runtime_state
        if runtime_state is None:
            return {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "overall_ok": False,
                "services": [],
                "connected_vacuums": [],
                "all_vacuums": [],
                "active_mqtt_connections": 0,
                "pending_onboarding_ips": [],
                "last_cloud_request": None,
                "note": "Runtime state tracking is disabled.",
            }
        return runtime_state.health_snapshot()

    def _ui_vacuums_payload(self) -> dict[str, Any]:
        payload = self._vacuums_payload()
        payload["required_onboarding_steps"] = list(REQUIRED_ONBOARDING_STEPS)
        payload["step_labels"] = dict(ONBOARDING_STEP_LABELS)
        return payload

    def refresh_inventory_state(self) -> None:
        self.runtime_credentials.sync_inventory()
        _seed_runtime_vacuums_from_inventory(
            runtime_state=self.runtime_state,
            runtime_credentials=self.runtime_credentials,
            inventory_path=self.paths.inventory_path,
        )
        _seed_runtime_vacuums_from_credentials(
            runtime_state=self.runtime_state,
            runtime_credentials=self.runtime_credentials,
        )

    @staticmethod
    def _is_standalone_route_path(path: str) -> bool:
        normalized = str(path or "").rstrip("/")
        return normalized == "/admin" or normalized.startswith("/admin/")

    def _register_protocol_routes(self, app: FastAPI) -> None:
        @app.get("/ui/api/health")
        async def ui_health(request: Request) -> JSONResponse:
            if not self.enable_standalone_admin:
                return JSONResponse({"error": "Not Found"}, status_code=404)
            self._require_admin(request)
            return JSONResponse(self._ui_health_payload())

        @app.get("/ui/api/vacuums")
        async def ui_vacuums(request: Request) -> JSONResponse:
            if not self.enable_standalone_admin:
                return JSONResponse({"error": "Not Found"}, status_code=404)
            self._require_admin(request)
            return JSONResponse(self._ui_vacuums_payload())

        @app.api_route("/", methods=list(ALL_HTTP_METHODS))
        async def root_handler(request: Request) -> Response:
            if self._is_standalone_route_path(request.url.path):
                return JSONResponse({"error": "Not Found"}, status_code=404)
            return await self._handle_roborock_request(request)

        @app.api_route("/{full_path:path}", methods=list(ALL_HTTP_METHODS))
        async def catchall_handler(request: Request, full_path: str) -> Response:
            _ = full_path
            if self._is_standalone_route_path(request.url.path):
                return JSONResponse({"error": "Not Found"}, status_code=404)
            return await self._handle_roborock_request(request)

    def _create_app(self) -> FastAPI:
        app = FastAPI(title="Roborock Local Server", docs_url=None, redoc_url=None, openapi_url=None)
        if self.enable_standalone_admin:
            register_standalone_admin_routes(
                app=app,
                supervisor=self,
                project_support=PROJECT_SUPPORT,
            )
        self._register_protocol_routes(app)
        return app

    async def _start_http_server(self) -> None:
        cert_paths = self.certificate_manager.certificate_paths
        self._http_server = ManagedFastApiServer(
            app=self.app,
            bind_host=self.config.network.bind_host,
            port=self.config.network.https_port,
            cert_file=cert_paths.cert_file,
            key_file=cert_paths.key_file,
        )
        await self._http_server.start()
        self.runtime_state.set_service("https_server", running=True, required=True, enabled=True)

    def _start_mqtt_proxy(self) -> None:
        cert_paths = self.certificate_manager.certificate_paths
        self._mqtt_proxy = MqttTlsProxy(
            cert_file=cert_paths.cert_file,
            key_file=cert_paths.key_file,
            listen_host=self.config.network.bind_host,
            listen_port=self.config.network.mqtt_tls_port,
            backend_host=self.config.broker.host,
            backend_port=self.config.broker.port,
            localkey=self.context.localkey,
            logger=self.loggers["mqtt"],
            decoded_jsonl=self.context.mqtt_jsonl,
            cloud_snapshot_path=self.paths.cloud_snapshot_path,
            protocol_auth_sessions_path=self.paths.protocol_auth_sessions_path,
            runtime_state=self.runtime_state,
            runtime_credentials=self.runtime_credentials,
            zone_ranges_store=self.context.zone_ranges_store,
        )
        self._mqtt_proxy.start()
        self.runtime_state.set_service("mqtt_tls_proxy", running=True, required=True, enabled=True)

    async def reload_tls_services(self) -> None:
        self.root_logger.info("Reloading TLS listeners after certificate update")
        if self._http_server is not None:
            self.runtime_state.set_service("https_server", running=False, required=True, enabled=True)
            await self._http_server.stop()
            self._http_server = None
        if self._mqtt_proxy is not None:
            self.runtime_state.set_service("mqtt_tls_proxy", running=False, required=True, enabled=True)
            self._mqtt_proxy.stop()
            self._mqtt_proxy = None
        await self._start_http_server()
        self._start_mqtt_proxy()

    async def _renew_loop(self) -> None:
        interval = max(3600, self.config.tls.renew_check_seconds)
        while not self._stop_event.is_set():
            await asyncio.sleep(interval)
            try:
                if self.certificate_manager.ensure_certificate():
                    await self.reload_tls_services()
            except Exception as exc:  # noqa: BLE001
                self.root_logger.warning("TLS renewal check failed: %s", exc)

    async def start(self) -> None:
        for path in (self.paths.data_dir, self.paths.runtime_dir, self.paths.state_dir, self.paths.certs_dir, self.paths.acme_dir):
            path.mkdir(parents=True, exist_ok=True)

        self.certificate_manager.ensure_certificate()
        self.refresh_inventory_state()

        if self.config.broker.mode == "embedded":
            self._broker = await start_broker(
                self.config.broker.port,
                state_dir=self.paths.state_dir / "mqtt_broker",
                mosquitto_binary=self.config.broker.mosquitto_binary,
                logger=self.loggers["mqtt"],
            )
            self.runtime_state.set_service("mqtt_backend_broker", running=True, required=True, enabled=True)
        else:
            _connectivity_check(self.config.broker.host, self.config.broker.port)
            self.runtime_state.set_service("mqtt_backend_broker", running=True, required=True, enabled=True)

        if self.config.broker.enable_topic_bridge:
            self._topic_bridge = MqttTopicBridge(
                host=self.config.broker.host,
                port=self.config.broker.port,
                logger=self.loggers["mqtt"],
                runtime_state=self.runtime_state,
                inventory_path=self.paths.inventory_path,
            )
            await self._topic_bridge.start()
            self.runtime_state.set_service("mqtt_topic_bridge", running=True, required=False, enabled=True)
        else:
            self.runtime_state.set_service("mqtt_topic_bridge", running=False, required=False, enabled=False)

        await self._start_http_server()
        self._start_mqtt_proxy()

        self.root_logger.info(
            "HTTPS server listening on %s:%d",
            self.config.network.bind_host,
            self.config.network.https_port,
        )
        self.root_logger.info(
            "MQTT TLS proxy listening on %s:%d",
            self.config.network.bind_host,
            self.config.network.mqtt_tls_port,
        )
        self.root_logger.info(
            "MQTT backend %s on %s:%d",
            self.config.broker.mode,
            self.config.broker.host,
            self.config.broker.port,
        )

        if self.config.tls.mode == "cloudflare_acme":
            self._renew_task = asyncio.create_task(self._renew_loop(), name="tls-renew-loop")

    async def stop(self) -> None:
        self._stop_event.set()
        if self._renew_task is not None:
            self._renew_task.cancel()
            try:
                await self._renew_task
            except asyncio.CancelledError:
                pass
        if self._mqtt_proxy is not None:
            self.runtime_state.set_service("mqtt_tls_proxy", running=False, required=True, enabled=True)
            self._mqtt_proxy.stop()
            self._mqtt_proxy = None
        if self._topic_bridge is not None:
            self.runtime_state.set_service(
                "mqtt_topic_bridge",
                running=False,
                required=False,
                enabled=self.config.broker.enable_topic_bridge,
            )
            await self._topic_bridge.stop()
            self._topic_bridge = None
        if self._http_server is not None:
            self.runtime_state.set_service("https_server", running=False, required=True, enabled=True)
            await self._http_server.stop()
            self._http_server = None
        self.runtime_state.set_service("mqtt_backend_broker", running=False, required=True, enabled=True)
        if self._broker is not None:
            await self._broker.shutdown()
            self._broker = None

    async def serve_forever(self) -> int:
        await self.start()

        def request_shutdown() -> None:
            if not self._stop_event.is_set():
                self._stop_event.set()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, request_shutdown)
            except NotImplementedError:
                pass

        try:
            await self._stop_event.wait()
        finally:
            await self.stop()
        return 0


async def run_server(*, config_file: Path, enable_standalone_admin: bool = True) -> int:
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    supervisor = ReleaseSupervisor(
        config=config,
        paths=paths,
        enable_standalone_admin=enable_standalone_admin,
    )
    return await supervisor.serve_forever()


def repair_runtime_identities(*, config_file: Path, links: list[str]) -> int:
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    runtime_credentials = RuntimeCredentialsStore(
        paths.runtime_credentials_path,
        inventory_path=paths.inventory_path,
        key_state_file=paths.device_key_state_path,
    )
    runtime_credentials.sync_inventory()

    inventory = _load_inventory(paths.inventory_path)
    inventory_vacuums = _extract_inventory_vacuums(
        ServerContext(
            api_host=config.network.stack_fqdn,
            mqtt_host=config.network.stack_fqdn,
            wood_host=config.network.stack_fqdn,
            region=config.network.region,
            localkey=str(runtime_credentials.bootstrap_value("localkey", "") or ""),
            duid=str(runtime_credentials.bootstrap_value("duid", "") or ""),
            mqtt_usr=str(runtime_credentials.bootstrap_value("mqtt_usr", "") or ""),
            mqtt_passwd=str(runtime_credentials.bootstrap_value("mqtt_passwd", "") or ""),
            mqtt_clientid=str(runtime_credentials.bootstrap_value("mqtt_clientid", "") or ""),
            mqtt_tls_port=config.network.mqtt_tls_port,
            http_jsonl=paths.http_jsonl_path,
            mqtt_jsonl=paths.mqtt_jsonl_path,
            loggers={},
            key_state_file=paths.device_key_state_path,
            bootstrap_encryption_enabled=False,
            runtime_state=None,
            runtime_credentials=runtime_credentials,
        ),
        inventory,
    )
    inventory_by_duid = {str(item.get("duid") or "").strip(): item for item in inventory_vacuums}

    if not links:
        orphan_dids = [
            device
            for device in runtime_credentials.devices()
            if str(device.get("did") or "").strip() and not str(device.get("duid") or "").strip()
        ]
        unmapped_cloud = [
            item
            for item in inventory_vacuums
            if not str(item.get("did") or "").strip()
        ]
        print("Orphan runtime DIDs:")
        for device in orphan_dids:
            print(
                f"  did={device.get('did','')} mqtt_usr={device.get('device_mqtt_usr','')} "
                f"last_mqtt_seen_at={device.get('last_mqtt_seen_at','')}"
            )
        print("Cloud DUIDs without a DID:")
        for item in unmapped_cloud:
            print(f"  duid={item.get('duid','')} name={item.get('name','')} model={item.get('model','')}")
        return 0

    repaired: list[tuple[str, str, str]] = []
    for link in links:
        normalized = str(link or "").strip()
        if "=" not in normalized:
            raise SystemExit(f"Invalid --link '{normalized}'. Expected DID=DUID.")
        did, duid = (part.strip() for part in normalized.split("=", 1))
        if not did or not duid:
            raise SystemExit(f"Invalid --link '{normalized}'. Expected DID=DUID.")
        inventory_match = inventory_by_duid.get(duid)
        if inventory_match is None:
            raise SystemExit(f"DUID '{duid}' was not found in {paths.inventory_path}")
        merged = runtime_credentials.ensure_device(
            did=did,
            duid=duid,
            name=str(inventory_match.get("name") or ""),
            model=str(inventory_match.get("model") or ""),
            product_id=str(inventory_match.get("product_id") or ""),
            localkey=str(inventory_match.get("local_key") or ""),
            assign_localkey=False,
        )
        repaired.append((did, duid, str(merged.get("name") or duid)))

    print(f"Repaired {len(repaired)} device identity link(s) in {paths.runtime_credentials_path}")
    for did, duid, name in repaired:
        print(f"  did={did} -> duid={duid} ({name})")
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Roborock local server release runtime")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Run the release stack")
    serve.add_argument("--config", default="config.toml")
    serve.add_argument(
        "--core-only",
        action="store_true",
        help="Run protocol runtime without standalone admin/dashboard routes.",
    )

    hash_password = subparsers.add_parser("hash-password", help="Generate an admin password hash")
    hash_password.add_argument("--password", default="")

    generate_secret = subparsers.add_parser("generate-secret", help="Generate a random admin session secret")
    generate_secret.add_argument("--bytes", type=int, default=32)

    configure = subparsers.add_parser("configure", help="Interactively write a small config.toml")
    configure.add_argument("--config", default="config.toml")
    configure.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing config.toml and Cloudflare token file.",
    )

    repair_identities = subparsers.add_parser(
        "repair-identities",
        help="Manually adopt existing runtime DIDs into known cloud DUIDs",
    )
    repair_identities.add_argument("--config", default="config.toml")
    repair_identities.add_argument(
        "--link",
        action="append",
        default=[],
        help="Explicit DID=DUID mapping to repair existing state; can be supplied multiple times",
    )
    return parser
