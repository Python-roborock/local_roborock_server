#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["pycryptodome>=3.20,<4"]
# ///
"""Guided remote onboarding CLI for pairing vacuums through the main server.

This is a standalone script. Copy it to any machine and run:

    uv run start_onboarding.py --server api-roborock.example.com
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from getpass import getpass
import io
import json
import secrets
import socket
import ssl
import sys
import time
from typing import Any, Callable, TextIO
from urllib import error, parse, request
import zlib

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad


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
    """Thin authenticated JSON client for the admin onboarding endpoints."""

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
        self._opener = opener or request.build_opener(request.HTTPCookieProcessor())
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
            with self._opener.open(req, timeout=self.timeout_seconds, context=self._ssl_context) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except TypeError:
            try:
                with self._opener.open(req, timeout=self.timeout_seconds) as response:
                    raw = response.read().decode("utf-8", errors="replace")
            except error.HTTPError as exc:
                if exc.code == 401 and allow_401:
                    raise RuntimeError("Invalid admin password.") from exc
                detail = exc.read().decode("utf-8", errors="replace")
                raise RuntimeError(_format_http_error(exc.code, detail)) from exc
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Guided Roborock remote onboarding")
    parser.add_argument("--server", required=True, help="Main server hostname, usually starting with api-")
    parser.add_argument("--admin-password", default="")
    parser.add_argument("--ssid", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--timezone", default="")
    parser.add_argument("--cst", default="")
    parser.add_argument("--country-domain", default="")
    return parser


def _prompt_text(value: str, prompt: str, *, default: str = "", secret: bool = False) -> str:
    if str(value or "").strip():
        return str(value).strip()
    display_prompt = prompt if not default else f"{prompt} [{default}]"
    while True:
        entered = getpass(f"{display_prompt}: ") if secret else input(f"{display_prompt}: ")
        candidate = str(entered or "").strip() or default
        if candidate:
            return candidate
        print("A value is required.")


def prompt_for_config(args: argparse.Namespace) -> GuidedOnboardingConfig:
    api_base_url = normalize_api_base_url(args.server)
    stack_server = sanitize_stack_server(args.server)
    admin_password = _prompt_text(args.admin_password, "Admin password", secret=True)
    ssid = _prompt_text(args.ssid, "Home Wi-Fi SSID")
    password = _prompt_text(args.password, "Home Wi-Fi password", secret=True)
    timezone = _prompt_text(args.timezone, "Timezone", default=DEFAULT_TIMEZONE)
    cst = str(args.cst or "").strip()
    if not cst:
        cst = posix_tz_from_iana(timezone)
    if not cst:
        cst = _prompt_text("", "POSIX TZ string (could not auto-detect from timezone)", default=DEFAULT_CST)
    country_domain = str(args.country_domain or "").strip()
    if not country_domain:
        country_domain = country_from_iana(timezone)
    if not country_domain:
        country_domain = _prompt_text("", "Country domain (could not auto-detect from timezone)", default=DEFAULT_COUNTRY_DOMAIN)
    return GuidedOnboardingConfig(
        api_base_url=api_base_url,
        stack_server=stack_server,
        admin_password=admin_password,
        ssid=ssid,
        password=password,
        timezone=timezone,
        cst=cst,
        country_domain=country_domain,
    )


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


def choose_device(devices: list[dict[str, Any]], *, output: TextIO) -> dict[str, Any] | None:
    if not devices:
        output.write("No known vacuums are available for onboarding.\n")
        return None

    name_counts: dict[str, int] = {}
    for device in devices:
        key = str(device.get("name") or device.get("duid") or "").strip().lower()
        name_counts[key] = name_counts.get(key, 0) + 1

    while True:
        output.write("Available vacuums:\n")
        for index, device in enumerate(devices, start=1):
            key = str(device.get("name") or device.get("duid") or "").strip().lower()
            disambiguator = str(device.get("duid") or "") if name_counts.get(key, 0) > 1 else ""
            output.write(f"  {index}. {format_device_label(device, disambiguator=disambiguator)}\n")
        raw = input("Select a vacuum by number, or type 'quit': ").strip().lower()
        if raw == "quit":
            return None
        if raw.isdigit():
            index = int(raw)
            if 1 <= index <= len(devices):
                return devices[index - 1]
        output.write("Please enter a valid number.\n")


def poll_session_until_progress(
    api: Any,
    *,
    session_id: str,
    baseline_samples: int,
    output: TextIO,
    poll_interval_seconds: float = POLL_INTERVAL_SECONDS,
    timeout_seconds: float = POLL_TIMEOUT_SECONDS,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> tuple[str, dict[str, Any]]:
    deadline = time.monotonic() + timeout_seconds
    latest = api.get_session(session_id=session_id)
    while True:
        latest = api.get_session(session_id=session_id)
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
        output.write("Waiting for the server to observe new onboarding traffic...\n")
        sleep_fn(poll_interval_seconds)


def prompt_post_attempt_action(status: dict[str, Any], *, output: TextIO) -> str:
    while True:
        _print_status_summary(status, output)
        raw = input("Choose: [retry] [refresh] [reselect] [quit]: ").strip().lower()
        if raw in {"retry", "refresh", "reselect", "quit"}:
            return raw
        output.write("Please type retry, refresh, reselect, or quit.\n")


def run_guided_onboarding(
    *,
    config: GuidedOnboardingConfig,
    api: Any,
    send_onboarding: Callable[[GuidedOnboardingConfig, TextIO], bool] = onboard_once,
    output: TextIO = sys.stdout,
    poll_interval_seconds: float = POLL_INTERVAL_SECONDS,
    timeout_seconds: float = POLL_TIMEOUT_SECONDS,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> int:
    api.login()

    while True:
        devices = api.list_devices()
        selected = choose_device(devices, output=output)
        if selected is None:
            return 0

        session = api.start_session(duid=str(selected.get("duid") or ""))
        session_id = str(session.get("session_id") or "").strip()
        if not session_id:
            raise RuntimeError("Server did not return an onboarding session id.")

        try:
            while True:
                status = api.get_session(session_id=session_id)
                baseline_samples = int(status.get("query_samples") or 0)
                output.write(
                    "\nReset the vacuum Wi-Fi, connect this machine to the vacuum Wi-Fi, "
                    "then press Enter to send onboarding.\n"
                )
                output.write("Type 'reselect' to choose another vacuum or 'quit' to exit.\n")
                raw = input("> ").strip().lower()
                if raw == "quit":
                    return 0
                if raw == "reselect":
                    break

                output.write("Sending cfgwifi onboarding packet...\n")
                if not send_onboarding(config, output):
                    output.write("Onboarding send failed.\n")
                    action = prompt_post_attempt_action(status, output=output)
                    if action == "reselect":
                        break
                    if action == "quit":
                        return 0
                    if action == "refresh":
                        refreshed = api.get_session(session_id=session_id)
                        _print_status_summary(refreshed, output)
                    continue

                output.write(
                    "Reconnect this machine to your normal Wi-Fi. "
                    "The script will poll the main server every 5 seconds for up to 5 minutes.\n"
                )
                result, status = poll_session_until_progress(
                    api,
                    session_id=session_id,
                    baseline_samples=baseline_samples,
                    output=output,
                    poll_interval_seconds=poll_interval_seconds,
                    timeout_seconds=timeout_seconds,
                    sleep_fn=sleep_fn,
                )
                _print_status_summary(status, output)
                if result == "connected":
                    output.write("The vacuum is connected to the local server.\n")
                    return 0
                if result == "public_key_ready":
                    output.write("The public key is ready. Do one final pairing cycle to finish the connection.\n")
                    continue
                if result == "sample_increased":
                    output.write("The sample count increased. Repeat the pairing cycle to collect more onboarding data.\n")
                    continue

                action = prompt_post_attempt_action(status, output=output)
                if action == "retry":
                    continue
                if action == "refresh":
                    _print_status_summary(api.get_session(session_id=session_id), output)
                    continue
                if action == "quit":
                    return 0
                break
        finally:
            try:
                api.delete_session(session_id=session_id)
            except Exception:
                pass


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = prompt_for_config(args)
    api = RemoteOnboardingApi(
        base_url=config.api_base_url,
        admin_password=config.admin_password,
    )
    try:
        return run_guided_onboarding(config=config, api=api)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
