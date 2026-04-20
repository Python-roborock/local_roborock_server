"""
mitmproxy addon: intercept Roborock app traffic and rewrite responses.

Requests needed for cloud authentication stay on Roborock cloud.
After auth bootstrap, app API traffic is routed to LOCAL_API so app home/device
state comes from your local stack.

Usage:
  uv run mitm_redirect.py --local-api YOUR_SERVER_HOST [--local-mqtt HOST] [--local-wood HOST] [--sync-secret SECRET] [--mode wireguard]
"""

from __future__ import annotations

from datetime import datetime
import json
import os
import re
import ssl
import tomllib
from urllib.parse import urlsplit
from urllib.error import HTTPError
from urllib.request import Request, urlopen

# mitmproxy is only available when loaded as an addon by mitmweb,
# not when running this script directly as a CLI launcher.
if __name__ != "__main__":
    from mitmproxy import ctx, http


# Populated by load() from env vars set by the CLI launcher.
LOCAL_API: str = ""
LOCAL_API_HOST: str = ""
LOCAL_API_PORT: int | None = None
LOCAL_MQTT: str = ""
LOCAL_MQTT_HOST: str = ""
LOCAL_MQTT_PORT: int | None = None
LOCAL_WOOD: str = ""
LOCAL_WOOD_HOST: str = ""
LOCAL_WOOD_PORT: int | None = None
LOCAL_SYNC_SECRET: str = ""
DEFAULT_LOCAL_API_PORT = 555
DEFAULT_LOCAL_MQTT_PORT = 8881


# Domains whose responses are candidates for host rewrite.
REWRITE_HOSTS = {
    "api.roborock.com",
    "api-us.roborock.com",
    "api-eu.roborock.com",
    "api-cn.roborock.com",
    "cnaccount.roborock.com",
    "usaccount.roborock.com",
    "euaccount.roborock.com",
    "account.roborock.com",
    "usiot.roborock.com",
    "euiot.roborock.com",
    "cniot.roborock.com",
    "mqtt.roborock.com",
    "mqtt-us.roborock.com",
    "mqtt-eu.roborock.com",
    "mqtt-cn.roborock.com",
    "wood.roborock.com",
    "wood-us.roborock.com",
    "wood-eu.roborock.com",
    "wood-cn.roborock.com",
}


# API hosts that should be routed to local stack after bootstrap.
API_ROUTE_HOSTS = {
    "api.roborock.com",
    "api-us.roborock.com",
    "api-eu.roborock.com",
    "api-cn.roborock.com",
    "cnaccount.roborock.com",
    "usaccount.roborock.com",
    "euaccount.roborock.com",
    "account.roborock.com",
    "usiot.roborock.com",
    "euiot.roborock.com",
    "cniot.roborock.com",
}


def _compile_host_patterns(hosts: set[str]) -> tuple[re.Pattern[str], ...]:
    return tuple(
        re.compile(rf"(?<![A-Za-z0-9.-]){re.escape(host)}(?::(?P<port>\d+))?", re.IGNORECASE)
        for host in hosts
    )


_API_REWRITE_PATTERNS = _compile_host_patterns(API_ROUTE_HOSTS)
_MQTT_REWRITE_PATTERNS = _compile_host_patterns(
    {
        "mqtt.roborock.com",
        "mqtt-us.roborock.com",
        "mqtt-eu.roborock.com",
        "mqtt-cn.roborock.com",
    }
)
_MQTT_NUMBERED_REWRITE_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9.-])mqtt-\w+-\d+\.roborock\.com(?::(?P<port>\d+))?", re.IGNORECASE),
)
_WOOD_REWRITE_PATTERNS = _compile_host_patterns(
    {
        "wood.roborock.com",
        "wood-us.roborock.com",
        "wood-eu.roborock.com",
        "wood-cn.roborock.com",
    }
)


# Keep these on cloud so login/auth keeps working.
CLOUD_ONLY_PATH_PREFIXES = (
    "/api/v5/auth/",
    "/api/v4/auth/",
    "/api/v3/auth/",
    "/api/v5/email/code/send",
    "/api/v4/email/code/send",
    "/api/v5/sms/code/send",
    "/api/v4/sms/code/send",
    "/api/v3/key/sign",
    "/api/v4/key/captcha",
)

# Only route endpoints that local server meaningfully implements.
LOCAL_ROUTE_EXACT_PATHS = {
    "/api/v1/gethomedetail",
    "/api/v1/geturlbyemail",
    "/api/v1/userinfo",
    "/api/v1/appconfig",
    "/api/v2/appconfig",
    "/api/v1/appfeatureplugin",
    "/api/v1/user/roles",
    "/api/v1/logout",
    "/api/v1/appplugin",
    "/api/v1/plugins",
    "/api/v4/product",
    "/api/v5/product",
}

LOCAL_ROUTE_REGEXES = (
    re.compile(r"^/api/v1/home/[^/]+/devices/order$"),
)

LOCAL_ROUTE_PREFIXES = (
    "/user/",
    "/v2/user/",
    "/v3/user/",
)

PROTOCOL_AUTH_SYNC_PATH = "/internal/protocol/user-data"
PROTOCOL_AUTH_SYNC_SOURCE = "mitm_cloud_login"
PROTOCOL_AUTH_PREFLIGHT_SOURCE = "mitm_preflight"
LOGIN_SYNC_EXACT_PATHS = {
    "/api/v1/loginwithcode",
    "/api/v4/auth/email/login/code",
    "/api/v4/auth/phone/login/code",
    "/api/v4/auth/mobile/login/code",
    "/api/v5/auth/email/login/code",
    "/api/v5/auth/phone/login/code",
    "/api/v5/auth/mobile/login/code",
    "/api/v3/auth/email/login",
    "/api/v3/auth/phone/login",
    "/api/v3/auth/mobile/login",
    "/api/v5/auth/email/login/pwd",
    "/api/v5/auth/phone/login/pwd",
    "/api/v5/auth/mobile/login/pwd",
}


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = ""
LOG_DIR_REWRITE = ""
LOG_DIR_PASSTHROUGH = ""
_seq_rewrite = 0
_seq_passthrough = 0
_sync_warning_emitted = False
_FILENAME_SAFE_RE = re.compile(r'[^A-Za-z0-9._-]+')


class SyncEndpointError(RuntimeError):
    def __init__(self, sync_url: str, detail: str, *, status: int | None = None) -> None:
        self.sync_url = str(sync_url or "").strip()
        self.status = status
        self.detail = str(detail or "").strip() or "unknown sync error"
        super().__init__(self.detail)

    def __str__(self) -> str:
        prefix = f"{self.sync_url}: " if self.sync_url else ""
        return f"{prefix}{self.detail}"


def _next_seq_rewrite() -> int:
    global _seq_rewrite
    _seq_rewrite += 1
    return _seq_rewrite


def _next_seq_passthrough() -> int:
    global _seq_passthrough
    _seq_passthrough += 1
    return _seq_passthrough


def _init_log_dir() -> None:
    global LOG_DIR, LOG_DIR_REWRITE, LOG_DIR_PASSTHROUGH
    session = datetime.now().strftime("%Y%m%d_%H%M%S")
    LOG_DIR = os.path.join(SCRIPT_DIR, "mitm_logs", session)
    LOG_DIR_REWRITE = os.path.join(LOG_DIR, "rewritten")
    LOG_DIR_PASSTHROUGH = os.path.join(LOG_DIR, "passthrough")
    os.makedirs(LOG_DIR_REWRITE, exist_ok=True)
    os.makedirs(LOG_DIR_PASSTHROUGH, exist_ok=True)
    ctx.log.info(f"[LOG] Rewritten    -> {LOG_DIR_REWRITE}")
    ctx.log.info(f"[LOG] Passthrough  -> {LOG_DIR_PASSTHROUGH}")


def _parse_endpoint(value: str, *, fallback_host: str = "", fallback_port: int | None = None) -> tuple[str, int | None]:
    raw = str(value or "").strip()
    if not raw:
        return fallback_host, fallback_port
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = (parsed.hostname or parsed.path.split("/", 1)[0]).strip().strip("/")
    if not host:
        return fallback_host, fallback_port
    return host, parsed.port if parsed.port is not None else fallback_port


def _format_authority(host: str, port: int | None, *, default_port: int | None = None) -> str:
    normalized_host = str(host or "").strip().strip("/")
    if not normalized_host:
        return ""
    if port is None:
        return normalized_host
    if default_port is not None and port == default_port:
        return normalized_host
    return f"{normalized_host}:{port}"


def _sync_callback_url(local_api: str) -> str:
    authority = str(local_api or "").strip().strip("/")
    return f"https://{authority}{PROTOCOL_AUTH_SYNC_PATH}"


def _parse_json_object(content: bytes) -> dict[str, object]:
    try:
        decoded = content.decode("utf-8")
        parsed = json.loads(decoded)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _describe_sync_http_result(status: int, body: bytes) -> str:
    parsed = _parse_json_object(body)
    msg = str(parsed.get("msg") or "").strip()
    data = parsed.get("data")
    reason = ""
    detail = ""
    if isinstance(data, dict):
        reason = str(data.get("reason") or "").strip()
        detail = str(data.get("detail") or "").strip()
    parts = [f"HTTP {status}"]
    if msg:
        parts.append(msg)
    if reason:
        parts.append(reason)
    if detail:
        parts.append(detail)
    return " - ".join(parts)


def _post_sync_payload(
    *,
    local_api: str,
    sync_secret: str,
    payload: dict[str, object],
    timeout: float = 5.0,
) -> tuple[str, int, bytes]:
    sync_url = _sync_callback_url(local_api)
    request = Request(
        sync_url,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Local-Sync-Secret": sync_secret,
        },
        method="POST",
    )
    context = ssl.create_default_context()
    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            status = getattr(response, "status", 200)
            return sync_url, status, response.read()
    except HTTPError as exc:
        return sync_url, exc.code, exc.read()
    except Exception as exc:
        raise SyncEndpointError(sync_url, f"request failed: {exc}") from exc


def _preflight_sync_endpoint(local_api: str, sync_secret: str) -> None:
    sync_url, status, body = _post_sync_payload(
        local_api=local_api,
        sync_secret=sync_secret,
        payload={"source": PROTOCOL_AUTH_PREFLIGHT_SOURCE},
    )
    parsed = _parse_json_object(body)
    data = parsed.get("data")
    reason = str(data.get("reason") or "").strip() if isinstance(data, dict) else ""
    if status == 400 and reason == "missing_user_data":
        return
    raise SyncEndpointError(sync_url, f"preflight failed: {_describe_sync_http_result(status, body)}", status=status)


def _write_sync_failure_response(flow: http.HTTPFlow, exc: SyncEndpointError) -> None:
    payload = {
        "code": 50241,
        "msg": "local_sync_failed",
        "data": {
            "reason": "sync_unreachable",
            "syncUrl": exc.sync_url,
            "detail": exc.detail,
        },
    }
    flow.response.status_code = 502
    flow.response.headers["content-type"] = "application/json"
    flow.response.content = json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _load_local_sync_secret() -> str:
    config_path = os.path.join(SCRIPT_DIR, "config.toml")
    if not os.path.exists(config_path):
        return ""
    try:
        with open(config_path, "rb") as handle:
            parsed = tomllib.load(handle)
    except Exception:
        return ""
    admin = parsed.get("admin")
    if not isinstance(admin, dict):
        return ""
    return str(admin.get("session_secret") or "").strip()


def load(loader) -> None:
    global LOCAL_API, LOCAL_API_HOST, LOCAL_API_PORT
    global LOCAL_MQTT, LOCAL_MQTT_HOST, LOCAL_MQTT_PORT
    global LOCAL_WOOD, LOCAL_WOOD_HOST, LOCAL_WOOD_PORT
    global LOCAL_SYNC_SECRET
    LOCAL_API_HOST, LOCAL_API_PORT = _parse_endpoint(
        os.environ["MITM_LOCAL_API"],
        fallback_port=DEFAULT_LOCAL_API_PORT,
    )
    LOCAL_API = _format_authority(LOCAL_API_HOST, LOCAL_API_PORT, default_port=443)
    LOCAL_MQTT_HOST, LOCAL_MQTT_PORT = _parse_endpoint(
        os.environ.get("MITM_LOCAL_MQTT", ""),
        fallback_host=LOCAL_API_HOST,
        fallback_port=DEFAULT_LOCAL_MQTT_PORT,
    )
    LOCAL_MQTT = _format_authority(LOCAL_MQTT_HOST, LOCAL_MQTT_PORT)
    LOCAL_WOOD_HOST, LOCAL_WOOD_PORT = _parse_endpoint(
        os.environ.get("MITM_LOCAL_WOOD", ""),
        fallback_host=LOCAL_API_HOST,
        fallback_port=LOCAL_API_PORT,
    )
    LOCAL_WOOD = _format_authority(LOCAL_WOOD_HOST, LOCAL_WOOD_PORT, default_port=443)
    LOCAL_SYNC_SECRET = str(os.environ.get("MITM_LOCAL_SYNC_SECRET") or "").strip()
    _init_log_dir()
    ctx.log.info(f"[CONFIG] LOCAL_API={LOCAL_API} LOCAL_MQTT={LOCAL_MQTT} LOCAL_WOOD={LOCAL_WOOD}")
    if LOCAL_SYNC_SECRET:
        ctx.log.info(f"[SYNC] protocol auth session sync enabled via {_sync_callback_url(LOCAL_API)}")
    else:
        ctx.log.warn("[SYNC] protocol auth session sync disabled: no sync secret configured")


def _safe_body(content: bytes, content_type: str) -> str:
    if not content:
        return "<empty>"
    try:
        if "json" in content_type or _looks_like_json(content):
            return json.dumps(json.loads(content), indent=2, ensure_ascii=False)
        return content.decode("utf-8", errors="replace")
    except Exception:
        return f"<binary {len(content)} bytes>"


def _safe_filename_component(value: str, *, default: str = "x") -> str:
    candidate = _FILENAME_SAFE_RE.sub("_", value or "").strip("._")
    if not candidate:
        return default
    return candidate[:80]


def _log_flow(flow: http.HTTPFlow, rewritten: bool, rewrites: list[str] | None = None) -> None:
    if rewritten:
        seq = _next_seq_rewrite()
        log_dir = LOG_DIR_REWRITE
    else:
        seq = _next_seq_passthrough()
        log_dir = LOG_DIR_PASSTHROUGH

    host = flow.request.pretty_host
    method = flow.request.method
    path = flow.request.path
    safe_host = _safe_filename_component(host, default="host")
    safe_method = _safe_filename_component(method, default="M")
    safe_path = _safe_filename_component(path.split("?")[0].replace("/", "_"), default="root")
    filename = f"{seq:04d}_{safe_method}_{safe_host}_{safe_path}.log"
    filepath = os.path.join(log_dir, filename)

    req_ct = flow.request.headers.get("content-type", "")
    lines: list[str] = []
    lines.append(f"{'=' * 80}")
    lines.append(f"#{seq}  {datetime.now().isoformat()}")
    lines.append(f"Host: {host}")
    if rewritten:
        lines.append("Action: response rewritten")
        if rewrites:
            lines.append("Rewrites:")
            for rewrite in rewrites:
                lines.append(f"  {rewrite}")
    else:
        lines.append("Action: passthrough")
    lines.append(f"{'=' * 80}")

    lines.append("")
    lines.append(f">>> REQUEST: {method} {flow.request.pretty_url}")
    lines.append(f"    Path:    {path}")
    lines.append("")
    lines.append("--- Request Headers ---")
    for key, value in flow.request.headers.items():
        lines.append(f"  {key}: {value}")
    lines.append("")
    lines.append("--- Request Body ---")
    lines.append(_safe_body(flow.request.content, req_ct))

    if flow.response:
        resp_ct = flow.response.headers.get("content-type", "")
        lines.append("")
        lines.append(f"<<< RESPONSE: {flow.response.status_code} {flow.response.reason}")
        lines.append("")
        lines.append("--- Response Headers ---")
        for key, value in flow.response.headers.items():
            lines.append(f"  {key}: {value}")
        lines.append("")
        lines.append("--- Response Body (ORIGINAL, before rewrite) ---")
        lines.append(_safe_body(flow.response.content, resp_ct))
    else:
        lines.append("")
        lines.append("<<< NO RESPONSE")

    lines.append("")
    try:
        with open(filepath, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
    except OSError as exc:
        ctx.log.warn(f"[LOG] Failed writing flow log {filepath}: {exc}")


def request(flow: http.HTTPFlow) -> None:
    """Route only supported API calls to local stack after auth bootstrap."""
    host = flow.request.pretty_host.lower()
    path = flow.request.path or "/"
    clean_path = (path.split("?", 1)[0] or "/").rstrip("/").lower()
    if not clean_path:
        clean_path = "/"

    if host not in API_ROUTE_HOSTS:
        return
    if any(path.startswith(prefix) for prefix in CLOUD_ONLY_PATH_PREFIXES):
        return
    if not (
        clean_path in LOCAL_ROUTE_EXACT_PATHS
        or any(route_regex.match(clean_path) for route_regex in LOCAL_ROUTE_REGEXES)
        or any(clean_path.startswith(prefix) for prefix in LOCAL_ROUTE_PREFIXES)
    ):
        return

    source = flow.request.pretty_host
    flow.request.scheme = "https"
    flow.request.host = LOCAL_API_HOST
    flow.request.port = LOCAL_API_PORT or DEFAULT_LOCAL_API_PORT
    flow.request.headers["Host"] = LOCAL_API
    ctx.log.info(f"[ROUTE] {source}{path} -> {LOCAL_API}{path}")


def _clean_path(path: str) -> str:
    clean_path = (str(path or "").split("?", 1)[0] or "/").rstrip("/").lower()
    return clean_path or "/"


def _is_login_sync_candidate(path: str) -> bool:
    return _clean_path(path) in LOGIN_SYNC_EXACT_PATHS


def _extract_protocol_user_data(payload: object) -> dict[str, object] | None:
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    rriot = data.get("rriot")
    if not isinstance(rriot, dict):
        return None
    required_values = (
        str(data.get("token") or "").strip(),
        str(data.get("rruid") or "").strip(),
        str(rriot.get("u") or "").strip(),
        str(rriot.get("s") or "").strip(),
        str(rriot.get("h") or "").strip(),
        str(rriot.get("k") or "").strip(),
    )
    if not all(required_values):
        return None
    return dict(data)


def _sync_protocol_user_data(user_data: dict[str, object]) -> None:
    global _sync_warning_emitted
    if not LOCAL_SYNC_SECRET:
        if not _sync_warning_emitted:
            ctx.log.warn("[SYNC] skipped protocol auth sync: no sync secret configured")
            _sync_warning_emitted = True
        return

    sync_url, status, body = _post_sync_payload(
        local_api=LOCAL_API,
        sync_secret=LOCAL_SYNC_SECRET,
        payload={"source": PROTOCOL_AUTH_SYNC_SOURCE, "user_data": user_data},
    )
    if not 200 <= status < 300:
        raise SyncEndpointError(sync_url, _describe_sync_http_result(status, body), status=status)

    hawk_id = str(((user_data.get("rriot") or {}) if isinstance(user_data.get("rriot"), dict) else {}).get("u") or "")
    ctx.log.info(
        f"[SYNC] stored protocol auth session rruid={str(user_data.get('rruid') or '')} "
        f"hawk_id={hawk_id} status={status}"
    )


def response(flow: http.HTTPFlow) -> None:
    """Rewrite cloud endpoint references in JSON payloads."""
    host = flow.request.pretty_host
    is_target = host in REWRITE_HOSTS

    if not is_target:
        _log_flow(flow, rewritten=False)
        return

    if not flow.response or not flow.response.content:
        _log_flow(flow, rewritten=False)
        return

    content_type = flow.response.headers.get("content-type", "")
    rewrites: list[str] = []
    if "json" in content_type or _looks_like_json(flow.response.content):
        try:
            body = json.loads(flow.response.content)
            if _is_login_sync_candidate(flow.request.path):
                user_data = _extract_protocol_user_data(body)
                if user_data is not None:
                    try:
                        _sync_protocol_user_data(user_data)
                    except SyncEndpointError as exc:
                        ctx.log.error(f"[SYNC] blocking login response: {exc}")
                        _write_sync_failure_response(flow, exc)
                        _log_flow(flow, rewritten=False)
                        return
            if _rewrite_json(body, rewrites):
                _log_flow(flow, rewritten=True, rewrites=rewrites)
                flow.response.content = json.dumps(body).encode("utf-8")
                ctx.log.info(f"[REWRITE] {host}{flow.request.path} - {len(rewrites)} substitutions")
                return
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    _log_flow(flow, rewritten=False)


def _looks_like_json(content: bytes) -> bool:
    try:
        return content[:1].decode("utf-8").strip() in ("{", "[")
    except Exception:
        return False


def _rewrite_json(obj, rewrites: list[str]) -> bool:
    changed = False
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, str):
                new_value = _rewrite_value(value)
                if new_value != value:
                    rewrites.append(f"{key}: {value!r} -> {new_value!r}")
                    obj[key] = new_value
                    changed = True
            elif isinstance(value, (dict, list)):
                if _rewrite_json(value, rewrites):
                    changed = True
    elif isinstance(obj, list):
        for index, item in enumerate(obj):
            if isinstance(item, str):
                new_value = _rewrite_value(item)
                if new_value != item:
                    rewrites.append(f"[{index}]: {item!r} -> {new_value!r}")
                    obj[index] = new_value
                    changed = True
            elif isinstance(item, (dict, list)):
                if _rewrite_json(item, rewrites):
                    changed = True
    return changed


def _rewrite_authorities(
    text: str,
    *,
    patterns: tuple[re.Pattern[str], ...],
    replacement_host: str,
    replacement_port: int | None,
    default_port: int | None = None,
) -> str:
    if not replacement_host:
        return text

    def _replace(match: re.Match[str]) -> str:
        original_port = match.group("port")
        port = int(original_port) if replacement_port is None and original_port else replacement_port
        return _format_authority(replacement_host, port, default_port=default_port)

    rewritten = text
    for pattern in patterns:
        rewritten = pattern.sub(_replace, rewritten)
    return rewritten


def _rewrite_value(text: str) -> str:
    rewritten = _rewrite_authorities(
        text,
        patterns=_MQTT_REWRITE_PATTERNS + _MQTT_NUMBERED_REWRITE_PATTERNS,
        replacement_host=LOCAL_MQTT_HOST,
        replacement_port=LOCAL_MQTT_PORT,
    )
    rewritten = _rewrite_authorities(
        rewritten,
        patterns=_API_REWRITE_PATTERNS,
        replacement_host=LOCAL_API_HOST,
        replacement_port=LOCAL_API_PORT,
        default_port=443,
    )
    rewritten = _rewrite_authorities(
        rewritten,
        patterns=_WOOD_REWRITE_PATTERNS,
        replacement_host=LOCAL_WOOD_HOST,
        replacement_port=LOCAL_WOOD_PORT,
        default_port=443,
    )
    return rewritten


if __name__ == "__main__":
    import argparse
    import subprocess
    import sys

    parser = argparse.ArgumentParser(
        description="Launch mitmweb with Roborock traffic interception.",
    )
    parser.add_argument(
        "--local-api",
        required=True,
        help="Hostname or HTTPS URL of your local API server. Defaults to HTTPS :555 when omitted.",
    )
    parser.add_argument(
        "--local-mqtt",
        default=None,
        help="Hostname or URL of your local MQTT server. Omit to reuse the API hostname and default to MQTT TLS :8881.",
    )
    parser.add_argument(
        "--local-wood",
        default=None,
        help="Hostname or HTTPS URL of your local Wood server. Explicit ports are supported.",
    )
    parser.add_argument(
        "--sync-secret",
        default=None,
        help="Optional admin.session_secret for protocol auth sync. Defaults to config.toml when available.",
    )
    parser.add_argument("--mode", default="wireguard", help="mitmweb proxy mode (default: wireguard)")
    parser.add_argument("--listen-port", default=None, help="mitmweb listen port")

    args, extra = parser.parse_known_args()
    local_api_host, local_api_port = _parse_endpoint(
        args.local_api,
        fallback_port=DEFAULT_LOCAL_API_PORT,
    )
    local_api = _format_authority(local_api_host, local_api_port, default_port=443)
    local_mqtt_host, local_mqtt_port = _parse_endpoint(
        args.local_mqtt or "",
        fallback_host=local_api_host,
        fallback_port=DEFAULT_LOCAL_MQTT_PORT,
    )
    local_mqtt = _format_authority(local_mqtt_host, local_mqtt_port)
    local_wood_host, local_wood_port = _parse_endpoint(
        args.local_wood or "",
        fallback_host=local_api_host,
        fallback_port=local_api_port,
    )
    local_wood = _format_authority(local_wood_host, local_wood_port, default_port=443)
    local_sync_secret = str(args.sync_secret or os.environ.get("MITM_LOCAL_SYNC_SECRET") or _load_local_sync_secret()).strip()

    for label, original, normalized in (
        ("local-api", args.local_api, local_api),
        ("local-mqtt", args.local_mqtt or "", local_mqtt),
        ("local-wood", args.local_wood or "", local_wood),
    ):
        if original and normalized and str(original).strip() != normalized:
            print(f"[CONFIG] normalized --{label} from {original!r} to {normalized!r}")

    env = os.environ.copy()
    env["MITM_LOCAL_API"] = local_api
    env["MITM_LOCAL_MQTT"] = local_mqtt
    env["MITM_LOCAL_WOOD"] = local_wood
    env["MITM_LOCAL_SYNC_SECRET"] = local_sync_secret

    if local_sync_secret:
        try:
            _preflight_sync_endpoint(local_api, local_sync_secret)
        except SyncEndpointError as exc:
            print(f"[SYNC] refusing to start mitmweb: {exc}", file=sys.stderr)
            sys.exit(2)
        print(f"[SYNC] verified protocol auth sync endpoint via {_sync_callback_url(local_api)}")
    else:
        print("[SYNC] protocol auth session sync disabled: no sync secret configured")

    cmd = [
        "uvx",
        "--from",
        "mitmproxy",
        "mitmweb",
        "--mode",
        args.mode,
        "--set",
        "connection_strategy=lazy",
        "--set",
        "http3=false",
        "-s",
        os.path.abspath(__file__),
    ]
    if args.listen_port:
        cmd += ["--listen-port", args.listen_port]
    cmd += extra

    sys.exit(subprocess.run(cmd, env=env).returncode)
