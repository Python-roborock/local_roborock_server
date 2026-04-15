#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pycryptodome>=3.20,<4",
#     "fastapi>=0.110,<1",
#     "uvicorn>=0.27,<1",
# ]
# ///
"""Guided remote onboarding for pairing vacuums through the main server.

Starts a local web UI at http://127.0.0.1:<port>/ and opens your browser
automatically
"""

from __future__ import annotations

from dataclasses import dataclass, field
import io
import json
import logging
from pathlib import Path
import secrets
import socket
import ssl
import sys
import threading
import time
import webbrowser
from typing import Any, TextIO
from urllib import error, parse, request
import zlib

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import uvicorn


CFGWIFI_HOST = "192.168.8.1"
CFGWIFI_PORT = 55559
CFGWIFI_TIMEOUT_SECONDS = 2.0
CFGWIFI_PRE_KEY = "6433df70f5a3a42e"
CFGWIFI_UID = "1234567890"
DEFAULT_COUNTRY_DOMAIN = "us"
DEFAULT_TIMEZONE = "America/New_York"
POLL_INTERVAL_SECONDS = 5.0
POLL_TIMEOUT_SECONDS = 300.0

# Mapping from IANA timezone to POSIX TZ string for the vacuum firmware.
_IANA_TO_POSIX: dict[str, str] = {
    "America/New_York": "EST5EDT,M3.2.0,M11.1.0",
    "America/Chicago": "CST6CDT,M3.2.0,M11.1.0",
    "America/Denver": "MST7MDT,M3.2.0,M11.1.0",
    "America/Los_Angeles": "PST8PDT,M3.2.0,M11.1.0",
    "America/Phoenix": "MST7",
    "America/Anchorage": "AKST9AKDT,M3.2.0,M11.1.0",
    "Pacific/Honolulu": "HST10",
    "America/Toronto": "EST5EDT,M3.2.0,M11.1.0",
    "America/Vancouver": "PST8PDT,M3.2.0,M11.1.0",
    "America/Winnipeg": "CST6CDT,M3.2.0,M11.1.0",
    "America/Edmonton": "MST7MDT,M3.2.0,M11.1.0",
    "Europe/London": "GMT0BST,M3.5.0/1,M10.5.0",
    "Europe/Berlin": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Paris": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Europe/Amsterdam": "CET-1CEST,M3.5.0,M10.5.0/3",
    "Asia/Shanghai": "CST-8",
    "Asia/Tokyo": "JST-9",
    "Asia/Kolkata": "IST-5:30",
    "Australia/Sydney": "AEST-10AEDT,M10.1.0,M4.1.0/3",
    "Australia/Melbourne": "AEST-10AEDT,M10.1.0,M4.1.0/3",
    "Australia/Perth": "AWST-8",
}
DEFAULT_CST = _IANA_TO_POSIX[DEFAULT_TIMEZONE]


def posix_tz_from_iana(iana: str) -> str:
    """Return a POSIX TZ string for the given IANA timezone, or empty string if unknown."""
    return _IANA_TO_POSIX.get(iana.strip(), "")


# Mapping from IANA timezone to country domain for the vacuum firmware.
_IANA_TO_COUNTRY: dict[str, str] = {
    "America/New_York": "us",
    "America/Chicago": "us",
    "America/Denver": "us",
    "America/Los_Angeles": "us",
    "America/Phoenix": "us",
    "America/Anchorage": "us",
    "Pacific/Honolulu": "us",
    "America/Toronto": "us",
    "America/Vancouver": "us",
    "America/Winnipeg": "us",
    "America/Edmonton": "us",
    "Europe/London": "gb",
    "Europe/Berlin": "de",
    "Europe/Paris": "fr",
    "Europe/Amsterdam": "nl",
    "Asia/Shanghai": "cn",
    "Asia/Tokyo": "jp",
    "Asia/Kolkata": "in",
    "Australia/Sydney": "au",
    "Australia/Melbourne": "au",
    "Australia/Perth": "au",
}


def country_from_iana(iana: str) -> str:
    """Return a country domain for the given IANA timezone, or empty string if unknown."""
    return _IANA_TO_COUNTRY.get(iana.strip(), "")


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def build_frame(payload: bytes, cmd_id: int) -> bytes:
    buf = io.BytesIO()
    buf.write(b"1.0")
    buf.write(b"\x00\x00\x00\x01")
    buf.write(bytes([0, cmd_id]))
    buf.write(bytes([(len(payload) >> 8) & 0xFF, len(payload) & 0xFF]))
    buf.write(payload)
    csum = crc32(buf.getvalue())
    buf.write(bytes([(csum >> 24) & 0xFF, (csum >> 16) & 0xFF, (csum >> 8) & 0xFF, csum & 0xFF]))
    return buf.getvalue()


def parse_cmd(pkt: bytes) -> int:
    return (pkt[7] << 8) | pkt[8]


def parse_payload(pkt: bytes) -> bytes:
    ln = (pkt[9] << 8) | pkt[10]
    return pkt[11 : 11 + ln]


def rsa_decrypt_blocks(payload: bytes, private_key: bytes) -> bytes:
    key = RSA.import_key(private_key)
    cipher = PKCS1_v1_5.new(key)
    block_size = key.size_in_bytes()
    out = bytearray()
    for index in range(0, len(payload), block_size):
        out.extend(cipher.decrypt(payload[index : index + block_size], sentinel=None))
    return bytes(out)


def aes_encrypt_json(data: dict[str, Any], key16: str) -> bytes:
    cipher = AES.new(key16.encode(), AES.MODE_ECB)
    plaintext = json.dumps(data, separators=(",", ":")).encode()
    return cipher.encrypt(pad(plaintext, AES.block_size))


def build_hello_packet(pre_key: str, pubkey_pem: bytes) -> bytes:
    body = {"id": 1, "method": "hello", "params": {"app_ver": 1, "key": pubkey_pem.decode()}}
    return build_frame(aes_encrypt_json(body, pre_key), 16)


def build_wifi_packet(session_key: str, body: dict[str, Any]) -> bytes:
    return build_frame(aes_encrypt_json(body, session_key), 1)


def recv_with_timeout(sock: socket.socket, timeout: float) -> bytes | None:
    sock.settimeout(timeout)
    try:
        data, _addr = sock.recvfrom(4096)
        return data
    except TimeoutError:
        return None
    except socket.timeout:
        return None


def sanitize_stack_server(url: str) -> str:
    value = str(url or "").strip()
    for prefix in ("https://", "http://"):
        if value.lower().startswith(prefix):
            value = value[len(prefix) :]
    value = value.strip().strip("/")
    if value.lower().startswith("api-"):
        value = value[4:]
    if not value:
        raise ValueError("A server host is required.")
    return f"{value}/"


def normalize_api_base_url(url: str) -> str:
    value = str(url or "").strip()
    if not value:
        raise ValueError("A server host is required.")
    for prefix in ("https://", "http://"):
        if value.lower().startswith(prefix):
            value = value[len(prefix) :]
            break
    value = value.strip().strip("/")
    if not value:
        raise ValueError("A server host is required.")
    if not value.lower().startswith("api-"):
        value = f"api-{value}"
    return f"https://{value}"


def _format_bool_label(value: bool, true_label: str, false_label: str) -> str:
    return true_label if value else false_label


def format_device_label(device: dict[str, Any], *, disambiguator: str = "") -> str:
    onboarding = dict(device.get("onboarding") or {})
    key_state = dict(onboarding.get("key_state") or {})
    name = str(device.get("name") or device.get("duid") or "Unknown vacuum")
    if disambiguator:
        name = f"{name} [{disambiguator}]"
    samples = int(key_state.get("query_samples") or 0)
    labels = [
        _format_bool_label(bool(onboarding.get("has_public_key")), "Public Key Determined", "No Public Key"),
        _format_bool_label(bool(device.get("connected")), "Connected", "Disconnected"),
        f"{samples} Query Samples",
    ]
    return f"{name} [{' ] ['.join(labels)}]"


def _print_status_summary(status: dict[str, Any], output: TextIO) -> None:
    target = dict(status.get("target") or {})
    name = str(target.get("name") or target.get("duid") or target.get("did") or "Unknown vacuum")
    output.write(
        f"Status for {name}: samples={int(status.get('query_samples') or 0)}, "
        f"public_key={bool(status.get('has_public_key'))}, "
        f"connected={bool(status.get('connected'))}, "
        f"state={status.get('public_key_state') or 'missing'}\n"
    )
    guidance = str(status.get("guidance") or "").strip()
    if guidance:
        output.write(f"{guidance}\n")


@dataclass(slots=True)
class GuidedOnboardingConfig:
    api_base_url: str
    stack_server: str
    admin_password: str
    ssid: str
    password: str
    timezone: str
    cst: str
    country_domain: str


class RemoteOnboardingApi:
    def __init__(
            self,
            *,
            base_url: str,
            admin_password: str,
            timeout_seconds: float = 15.0,
            opener: request.OpenerDirector | None = None,
            ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.admin_password = admin_password
        self.timeout_seconds = timeout_seconds
        self._ssl_context = ssl_context
        if opener is not None:
            self._opener = opener
        else:
            handlers = [request.HTTPCookieProcessor()]
            if ssl_context is not None:
                handlers.append(request.HTTPSHandler(context=ssl_context))
            self._opener = request.build_opener(*handlers)
        self._logged_in = False

    def login(self) -> None:
        if self._logged_in:
            return
        self._request_json(
            "POST",
            "/admin/api/login",
            payload={"password": self.admin_password},
            allow_401=True,
        )
        self._logged_in = True

    def list_devices(self) -> list[dict[str, Any]]:
        payload = self._request_json("GET", "/admin/api/onboarding/devices")
        devices = payload.get("devices")
        return list(devices) if isinstance(devices, list) else []

    def start_session(self, *, duid: str) -> dict[str, Any]:
        return self._request_json("POST", "/admin/api/onboarding/sessions", payload={"duid": duid})

    def get_session(self, *, session_id: str) -> dict[str, Any]:
        return self._request_json("GET", f"/admin/api/onboarding/sessions/{parse.quote(session_id, safe='')}")

    def delete_session(self, *, session_id: str) -> dict[str, Any]:
        return self._request_json("DELETE", f"/admin/api/onboarding/sessions/{parse.quote(session_id, safe='')}")

    def _request_json(
            self,
            method: str,
            path: str,
            *,
            payload: dict[str, Any] | None = None,
            allow_401: bool = False,
    ) -> dict[str, Any]:
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = request.Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except error.HTTPError as exc:
            if exc.code == 401 and allow_401:
                raise RuntimeError("Invalid admin password.") from exc
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(_format_http_error(exc.code, detail)) from exc
        except error.URLError as exc:
            raise RuntimeError(f"Unable to reach {self.base_url}: {exc.reason}") from exc
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid JSON response from {path}: {raw[:200]}") from exc
        if not isinstance(parsed, dict):
            raise RuntimeError(f"Unexpected response from {path}: {parsed!r}")
        return parsed


def _format_http_error(status_code: int, raw_body: str) -> str:
    try:
        parsed = json.loads(raw_body)
    except json.JSONDecodeError:
        parsed = {}
    if isinstance(parsed, dict):
        message = str(parsed.get("error") or parsed.get("detail") or "").strip()
        if message:
            return f"HTTP {status_code}: {message}"
    body = raw_body.strip()
    if body:
        return f"HTTP {status_code}: {body[:200]}"
    return f"HTTP {status_code}"


def onboard_once(config: GuidedOnboardingConfig, output: TextIO = sys.stdout) -> bool:
    token_s = f"S_TOKEN_{secrets.token_hex(16)}"
    token_t = f"T_TOKEN_{secrets.token_hex(16)}"

    key = RSA.generate(1024)
    priv = key.export_key()
    pub = key.publickey().export_key()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target = (CFGWIFI_HOST, CFGWIFI_PORT)
    try:
        hello = build_hello_packet(CFGWIFI_PRE_KEY, pub)
        sock.sendto(hello, target)
        hello_resp = recv_with_timeout(sock, CFGWIFI_TIMEOUT_SECONDS)
        if not hello_resp:
            output.write("HELLO: no response\n")
            return False

        cmd = parse_cmd(hello_resp)
        dec = rsa_decrypt_blocks(parse_payload(hello_resp), priv).decode(errors="replace")
        output.write(f"HELLO_RESP_CMD={cmd}\n")
        output.write(f"HELLO_RESP_JSON={dec}\n")
        parsed = json.loads(dec)
        session_key = parsed["params"]["key"]
        if not isinstance(session_key, str) or len(session_key) != 16:
            output.write("HELLO: session key invalid\n")
            return False

        body = {
            "u": CFGWIFI_UID,
            "ssid": config.ssid,
            "token": {
                "r": config.stack_server,
                "tz": config.timezone,
                "s": token_s,
                "cst": config.cst,
                "t": token_t,
            },
            "passwd": config.password,
            "country_domain": config.country_domain,
        }
        wifi_pkt = build_wifi_packet(session_key, body)
        sock.sendto(wifi_pkt, target)
        output.write(f"TOKEN_S={token_s}\n")
        output.write(f"TOKEN_T={token_t}\n")
        output.write(f"WIFI_BODY_SENT={json.dumps(body, separators=(',', ':'))}\n")

        wifi_resp = recv_with_timeout(sock, CFGWIFI_TIMEOUT_SECONDS)
        if wifi_resp is None:
            output.write("WIFI_RESP: none\n")
        else:
            output.write(f"WIFI_RESP_CMD={parse_cmd(wifi_resp)}\n")
            output.write(f"WIFI_RESP_HEX={wifi_resp.hex()[:800]}\n")
        return True
    finally:
        sock.close()


_state_lock = threading.Lock()
_state_cond = threading.Condition(_state_lock)
_SHUTDOWN_EVENT = threading.Event()
_ACCESS_TOKEN = secrets.token_urlsafe(24)


@dataclass
class LogEntry:
    ts: float
    level: str
    msg: str


class _UILogBuffer(io.TextIOBase):

    def __init__(self, max_entries: int = 500) -> None:
        super().__init__()
        self._entries: list[LogEntry] = []
        self._max = max_entries
        self._pending = ""

    def write(self, s: str) -> int:  # type: ignore[override]
        self._pending += s
        while "\n" in self._pending:
            line, self._pending = self._pending.split("\n", 1)
            if line.strip():
                self._append(line)
        return len(s)

    def info(self, msg: str) -> None:
        self._append(msg, level="")

    def ok(self, msg: str) -> None:
        self._append(msg, level="ok")

    def warn(self, msg: str) -> None:
        self._append(msg, level="warn")

    def err(self, msg: str) -> None:
        self._append(msg, level="err")

    def _append(self, msg: str, level: str = "") -> None:
        lvl = level
        if not lvl:
            low = msg.lower()
            if "fail" in low or "error" in low or "invalid" in low or "unable" in low:
                lvl = "err"
            elif "ok" in low.split() or "success" in low or "reachable" in low or "connected" in low:
                lvl = "ok"
        entry = LogEntry(ts=time.time(), level=lvl, msg=msg)
        self._entries.append(entry)
        if len(self._entries) > self._max:
            self._entries = self._entries[-self._max :]

    def snapshot(self) -> list[dict[str, Any]]:
        return [{"ts": e.ts, "level": e.level, "msg": e.msg} for e in self._entries]


@dataclass
class _SharedState:
    phase: str = "needs_config"
    config: GuidedOnboardingConfig | None = None
    config_error: str | None = None
    devices: list[dict[str, Any]] = field(default_factory=list)
    target: dict[str, Any] | None = None
    session_id: str | None = None
    baseline_samples: int = 0
    status: dict[str, Any] = field(default_factory=dict)
    result_message: str | None = None
    result_detail: str | None = None
    can_continue: bool = False
    error_message: str | None = None
    pending_command: str | None = None
    pending_payload: dict[str, Any] = field(default_factory=dict)


_state = _SharedState()
_log = _UILogBuffer()


def _set_phase(new_phase: str, **fields: Any) -> None:
    with _state_cond:
        _state.phase = new_phase
        for k, v in fields.items():
            setattr(_state, k, v)
        _state_cond.notify_all()


def _set_command(cmd: str, **payload: Any) -> None:
    with _state_cond:
        _state.pending_command = cmd
        _state.pending_payload = payload
        _state_cond.notify_all()


def _wait_for_command(expected: set[str], timeout: float | None = None) -> tuple[str, dict[str, Any]] | None:
    with _state_cond:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if _SHUTDOWN_EVENT.is_set():
                return None
            if _state.pending_command in expected:
                cmd = _state.pending_command
                payload = dict(_state.pending_payload)
                _state.pending_command = None
                _state.pending_payload = {}
                return cmd, payload
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                _state_cond.wait(timeout=remaining)
            else:
                _state_cond.wait(timeout=1.0)


class _QuitSignal(Exception):
    pass


def _build_config_from_payload(payload: dict[str, Any]) -> GuidedOnboardingConfig:
    server = str(payload.get("server") or "").strip()
    if not server:
        raise ValueError("Server is required.")
    api_base_url = normalize_api_base_url(server)
    stack_server = sanitize_stack_server(server)
    admin_password = str(payload.get("admin_password") or "")
    if not admin_password:
        raise ValueError("Admin password is required.")
    ssid = str(payload.get("ssid") or "").strip()
    if not ssid:
        raise ValueError("Home Wi-Fi SSID is required.")
    wifi_password = str(payload.get("wifi_password") or "")
    if not wifi_password:
        raise ValueError("Home Wi-Fi password is required.")
    timezone = str(payload.get("timezone") or "").strip() or DEFAULT_TIMEZONE
    cst = str(payload.get("cst") or "").strip() or posix_tz_from_iana(timezone) or DEFAULT_CST
    country_domain = str(payload.get("country_domain") or "").strip() or country_from_iana(timezone) or DEFAULT_COUNTRY_DOMAIN
    return GuidedOnboardingConfig(
        api_base_url=api_base_url,
        stack_server=stack_server,
        admin_password=admin_password,
        ssid=ssid,
        password=wifi_password,
        timezone=timezone,
        cst=cst,
        country_domain=country_domain,
    )


def _serialize_devices(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for d in devices:
        onboarding = dict(d.get("onboarding") or {})
        key_state = dict(onboarding.get("key_state") or {})
        out.append({
            "duid": str(d.get("duid") or ""),
            "name": str(d.get("name") or d.get("duid") or "Unknown"),
            "has_public_key": bool(onboarding.get("has_public_key")),
            "connected": bool(d.get("connected")),
            "query_samples": int(key_state.get("query_samples") or 0),
        })
    return out


def _serialize_status(status: dict[str, Any]) -> dict[str, Any]:
    return {
        "query_samples": int(status.get("query_samples") or 0),
        "has_public_key": bool(status.get("has_public_key")),
        "connected": bool(status.get("connected")),
        "public_key_state": str(status.get("public_key_state") or "missing"),
    }


def _wait_for_reachability(api: RemoteOnboardingApi, session_id: str, *, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _SHUTDOWN_EVENT.is_set():
            return False
        with _state_cond:
            if _state.pending_command == "ready":
                _state.pending_command = None
                _state.pending_payload = {}
        try:
            api.get_session(session_id=session_id)
            return True
        except Exception:
            pass
        with _state_cond:
            _state_cond.wait(timeout=2.0)
    return False


def _poll_until_progress(
        api: RemoteOnboardingApi,
        session_id: str,
        baseline_samples: int,
) -> tuple[str, dict[str, Any]]:
    deadline = time.monotonic() + POLL_TIMEOUT_SECONDS
    latest: dict[str, Any] = {}
    while True:
        if _SHUTDOWN_EVENT.is_set():
            return "timeout", latest
        try:
            latest = api.get_session(session_id=session_id)
        except Exception as exc:  # noqa: BLE001
            _log.warn(f"poll: get_session error: {exc}")
            latest = latest or {}
        if str(latest.get("identity_conflict") or "").strip():
            return "conflict", latest
        if bool(latest.get("connected")):
            return "connected", latest
        if bool(latest.get("has_public_key")):
            return "public_key_ready", latest
        if int(latest.get("query_samples") or 0) > baseline_samples:
            return "sample_increased", latest
        if time.monotonic() >= deadline:
            return "timeout", latest
        _log.info("Waiting for the server to observe new onboarding traffic...")
        with _state_cond:
            _state_cond.wait(timeout=POLL_INTERVAL_SECONDS)


def _run_onboarding_for_device(
        api: RemoteOnboardingApi,
        config: GuidedOnboardingConfig,
        device: dict[str, Any],
) -> None:
    duid = str(device.get("duid") or "")
    name = str(device.get("name") or duid or "vacuum")
    _log.info(f"Starting session for {name} ({duid})")

    try:
        session = api.start_session(duid=duid)
    except Exception as exc:  # noqa: BLE001
        _log.err(f"Failed to start session: {exc}")
        _set_phase("error", error_message=str(exc), target={"name": name, "duid": duid})
        _wait_for_command({"retry", "reselect", "quit"})
        return

    session_id = str(session.get("session_id") or "").strip()
    if not session_id:
        _log.err("Server did not return a session id.")
        _set_phase("error", error_message="Server did not return a session id.",
                   target={"name": name, "duid": duid})
        _wait_for_command({"retry", "reselect", "quit"})
        return

    target_info = {"name": name, "duid": duid}

    try:
        while True:
            try:
                status = api.get_session(session_id=session_id)
            except Exception as exc:  # noqa: BLE001
                _log.err(f"get_session failed: {exc}")
                _set_phase("error", error_message=str(exc), target=target_info)
                result = _wait_for_command({"retry", "reselect", "quit"})
                if result is None or result[0] == "quit":
                    raise _QuitSignal
                if result[0] == "reselect":
                    return
                continue

            baseline = int(status.get("query_samples") or 0)
            _print_status_summary(status, _log)
            _set_phase(
                "awaiting_vacuum_wifi",
                target=target_info,
                session_id=session_id,
                baseline_samples=baseline,
                status=_serialize_status(status),
                result_message=None,
                result_detail=None,
                error_message=None,
                can_continue=False,
            )

            result = _wait_for_command({"send_onboarding", "reselect", "quit"})
            if result is None or result[0] == "quit":
                raise _QuitSignal
            if result[0] == "reselect":
                return

            _set_phase("sending_onboarding")
            _log.info("Sending cfgwifi onboarding packet to 192.168.8.1...")
            try:
                sent_ok = onboard_once(config, _log)
            except Exception as exc:  # noqa: BLE001
                _log.err(f"onboard_once raised: {exc}")
                sent_ok = False

            if not sent_ok:
                _log.err("Onboarding send failed. Are you joined to the vacuum's Wi-Fi?")
                _set_phase(
                    "error",
                    error_message="Onboarding send failed. Ensure your machine is joined to the vacuum's Wi-Fi hotspot, then retry.",
                    target=target_info,
                )
                result = _wait_for_command({"retry", "reselect", "quit"})
                if result is None or result[0] == "quit":
                    raise _QuitSignal
                if result[0] == "reselect":
                    return
                continue

            _log.ok("Onboarding packet sent.")

            # Wait for normal Wi-Fi to come back
            _set_phase("awaiting_normal_wifi")
            _log.info("Waiting for normal Wi-Fi / server reachability...")
            reachable = _wait_for_reachability(api, session_id, timeout_seconds=120.0)
            if not reachable:
                _log.err("Could not reach the server after leaving the vacuum hotspot.")
                _set_phase(
                    "error",
                    error_message="Could not reach the server after leaving the vacuum hotspot. Check your Wi-Fi and try again.",
                    target=target_info,
                )
                result = _wait_for_command({"retry", "reselect", "quit"})
                if result is None or result[0] == "quit":
                    raise _QuitSignal
                if result[0] == "reselect":
                    return
                continue
            _log.ok("Server reachable. Polling for progress...")

            _set_phase("polling")
            outcome, latest = _poll_until_progress(api, session_id, baseline)
            _print_status_summary(latest, _log)

            status_serialized = _serialize_status(latest)
            if outcome == "connected":
                _set_phase("done", status=status_serialized,
                           result_message="The vacuum is connected to the local server.",
                           result_detail="Onboarding complete.",
                           can_continue=False)
                _log.ok("Vacuum connected.")
            elif outcome == "public_key_ready":
                _set_phase("done", status=status_serialized,
                           result_message="Public key is ready.",
                           result_detail="Run one more pairing cycle to finish the connection.",
                           can_continue=True)
            elif outcome == "sample_increased":
                _set_phase("done", status=status_serialized,
                           result_message="Sample count increased.",
                           result_detail="Repeat the pairing cycle to collect more onboarding data.",
                           can_continue=True)
            elif outcome == "conflict":
                _set_phase("done", status=status_serialized,
                           result_message="Identity conflict detected.",
                           result_detail=str(latest.get("identity_conflict") or ""),
                           can_continue=False)
            else:
                _set_phase("done", status=status_serialized,
                           result_message="Timed out waiting for progress.",
                           result_detail="The server did not observe new onboarding traffic within the timeout.",
                           can_continue=True)

            result = _wait_for_command({"retry", "reselect", "quit"})
            if result is None or result[0] == "quit":
                raise _QuitSignal
            if result[0] == "reselect":
                return
    finally:
        try:
            api.delete_session(session_id=session_id)
        except Exception:
            pass


def _run_device_loop(api: RemoteOnboardingApi, config: GuidedOnboardingConfig) -> None:
    while True:
        try:
            devices = api.list_devices()
        except Exception as exc:  # noqa: BLE001
            _log.err(f"Could not list devices: {exc}")
            _set_phase("error", error_message=str(exc))
            result = _wait_for_command({"retry", "reselect", "quit"})
            if result is None or result[0] == "quit":
                raise _QuitSignal
            continue

        _set_phase("choosing_device", devices=_serialize_devices(devices), target=None,
                   session_id=None, status={}, result_message=None, result_detail=None,
                   error_message=None, can_continue=False)
        _log.info(f"{len(devices)} device(s) available.")

        result = _wait_for_command({"select_device", "refresh_devices", "quit"})
        if result is None or result[0] == "quit":
            raise _QuitSignal
        cmd, payload = result
        if cmd == "refresh_devices":
            continue

        duid = str(payload.get("duid") or "")
        selected = next((d for d in devices if str(d.get("duid") or "") == duid), None)
        if selected is None:
            _log.err(f"Unknown duid {duid}")
            continue

        _run_onboarding_for_device(api, config, selected)


def _worker_loop() -> None:
    _log.info("Worker started. Waiting for configuration...")
    while not _SHUTDOWN_EVENT.is_set():
        result = _wait_for_command({"submit_config", "quit"})
        if result is None:
            return
        cmd, payload = result
        if cmd == "quit":
            return

        try:
            config = _build_config_from_payload(payload)
        except Exception as exc:  # noqa: BLE001
            _set_phase("needs_config", config_error=str(exc))
            _log.err(f"Config error: {exc}")
            continue

        _set_phase("logging_in", config=config, config_error=None)
        _log.info(f"Logging in to {config.api_base_url}...")
        api = RemoteOnboardingApi(
            base_url=config.api_base_url,
            admin_password=config.admin_password,
            ssl_context=ssl._create_unverified_context(),
        )

        try:
            api.login()
        except Exception as exc:  # noqa: BLE001
            _set_phase("needs_config", config_error=str(exc), config=None)
            _log.err(f"Login failed: {exc}")
            continue

        _log.ok("Logged in.")

        try:
            _run_device_loop(api, config)
        except _QuitSignal:
            _log.info("Quit requested.")
            return
        except Exception as exc:  # noqa: BLE001
            _log.err(f"Fatal error: {exc}")
            _set_phase("error", error_message=str(exc))
            result = _wait_for_command({"quit", "reselect"})
            if result is None or result[0] == "quit":
                return
            continue


_INDEX_HTML = (Path(__file__).parent / "ui.html").read_text(encoding="utf-8")

app = FastAPI(title="Vacuum Onboarding", docs_url=None, redoc_url=None, openapi_url=None)


def _check_token(request: Request) -> None:
    provided = request.headers.get("x-token") or request.query_params.get("token") or ""
    if not secrets.compare_digest(provided, _ACCESS_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid or missing token.")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return HTMLResponse(_INDEX_HTML)


@app.get("/api/state")
async def get_state(request: Request) -> JSONResponse:
    _check_token(request)
    with _state_lock:
        return JSONResponse({
            "phase": _state.phase,
            "config_error": _state.config_error,
            "devices": list(_state.devices),
            "target_name": (_state.target or {}).get("name"),
            "target_duid": (_state.target or {}).get("duid"),
            "status": dict(_state.status),
            "baseline_samples": _state.baseline_samples,
            "result_message": _state.result_message,
            "result_detail": _state.result_detail,
            "can_continue": _state.can_continue,
            "error_message": _state.error_message,
            "timezones": sorted(_IANA_TO_POSIX.keys()),
            "default_timezone": DEFAULT_TIMEZONE,
            "log": _log.snapshot(),
        })


class ConfigPayload(BaseModel):
    server: str
    admin_password: str
    ssid: str
    wifi_password: str
    timezone: str = ""
    country_domain: str = ""
    cst: str = ""


@app.post("/api/config")
async def post_config(payload: ConfigPayload, request: Request) -> JSONResponse:
    _check_token(request)
    _set_command("submit_config", **payload.model_dump())
    return JSONResponse({"ok": True})


class SelectPayload(BaseModel):
    duid: str


@app.post("/api/select-device")
async def select_device(payload: SelectPayload, request: Request) -> JSONResponse:
    _check_token(request)
    _set_command("select_device", duid=payload.duid)
    return JSONResponse({"ok": True})


@app.post("/api/refresh-devices")
async def refresh_devices(request: Request) -> JSONResponse:
    _check_token(request)
    _set_command("refresh_devices")
    return JSONResponse({"ok": True})


@app.post("/api/send-onboarding")
async def send_onboarding_ep(request: Request) -> JSONResponse:
    _check_token(request)
    _set_command("send_onboarding")
    return JSONResponse({"ok": True})


@app.post("/api/ready")
async def post_ready(request: Request) -> JSONResponse:
    _check_token(request)
    _set_command("ready")
    return JSONResponse({"ok": True})


@app.post("/api/retry")
async def post_retry(request: Request) -> JSONResponse:
    _check_token(request)
    _set_command("retry")
    return JSONResponse({"ok": True})


@app.post("/api/reselect")
async def post_reselect(request: Request) -> JSONResponse:
    _check_token(request)
    _set_command("reselect")
    return JSONResponse({"ok": True})


@app.post("/api/quit")
async def post_quit(request: Request) -> JSONResponse:
    _check_token(request)
    _set_command("quit")
    _SHUTDOWN_EVENT.set()
    threading.Thread(target=_deferred_shutdown, daemon=True).start()
    return JSONResponse({"ok": True})


def _deferred_shutdown() -> None:
    time.sleep(0.3)
    _server_ref[0].should_exit = True  # type: ignore[union-attr]


_server_ref: list[uvicorn.Server | None] = [None]


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    port = _pick_free_port()
    url = f"http://127.0.0.1:{port}/?token={_ACCESS_TOKEN}"

    worker = threading.Thread(target=_worker_loop, name="onboarding-worker", daemon=True)
    worker.start()

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    _server_ref[0] = server

    print(f"Vacuum Onboarding UI: {url}")
    print("Opening browser...")
    try:
        webbrowser.open(url)
    except Exception:  # noqa: BLE001
        print("Could not open browser automatically. Copy the URL above.")

    try:
        server.run()
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        _SHUTDOWN_EVENT.set()
        with _state_cond:
            _state_cond.notify_all()
        worker.join(timeout=2.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())