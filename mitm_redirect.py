"""
mitmproxy addon: intercept Roborock app traffic and rewrite responses.

Requests needed for cloud authentication stay on Roborock cloud.
After auth bootstrap, app API traffic is routed to LOCAL_API so app home/device
state comes from your local stack.

Usage:
  uv run mitm_redirect.py --local-api YOUR_SERVER_HOST [--local-mqtt HOST] [--local-wood HOST] [--mode wireguard]
"""

from __future__ import annotations

from datetime import datetime
import json
import os
import re

# mitmproxy is only available when loaded as an addon by mitmweb,
# not when running this script directly as a CLI launcher.
if __name__ != "__main__":
    from mitmproxy import ctx, http


# Populated by load() from env vars set by the CLI launcher.
LOCAL_API: str = ""
LOCAL_MQTT: str = ""
LOCAL_WOOD: str = ""


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


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = ""
LOG_DIR_REWRITE = ""
LOG_DIR_PASSTHROUGH = ""
_seq_rewrite = 0
_seq_passthrough = 0
_FILENAME_SAFE_RE = re.compile(r'[^A-Za-z0-9._-]+')


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


def load(loader) -> None:
    global LOCAL_API, LOCAL_MQTT, LOCAL_WOOD
    LOCAL_API = os.environ["MITM_LOCAL_API"]
    LOCAL_MQTT = os.environ.get("MITM_LOCAL_MQTT", LOCAL_API) or LOCAL_API
    LOCAL_WOOD = os.environ.get("MITM_LOCAL_WOOD", LOCAL_API) or LOCAL_API
    _init_log_dir()
    ctx.log.info(f"[CONFIG] LOCAL_API={LOCAL_API} LOCAL_MQTT={LOCAL_MQTT} LOCAL_WOOD={LOCAL_WOOD}")


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
    flow.request.host = LOCAL_API
    flow.request.port = 443
    flow.request.headers["Host"] = LOCAL_API
    ctx.log.info(f"[ROUTE] {source}{path} -> {LOCAL_API}{path}")


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


def _rewrite_value(text: str) -> str:
    for host in ("mqtt.roborock.com", "mqtt-us.roborock.com", "mqtt-eu.roborock.com", "mqtt-cn.roborock.com"):
        if host in text:
            text = text.replace(host, LOCAL_MQTT)
    text = re.sub(r"mqtt-\w+-\d+\.roborock\.com", LOCAL_MQTT, text)

    for host in (
        "api.roborock.com",
        "api-us.roborock.com",
        "api-eu.roborock.com",
        "api-cn.roborock.com",
        "usiot.roborock.com",
        "euiot.roborock.com",
        "cniot.roborock.com",
        "cnaccount.roborock.com",
        "usaccount.roborock.com",
        "euaccount.roborock.com",
        "account.roborock.com",
    ):
        if host in text:
            text = text.replace(host, LOCAL_API)

    for host in ("wood.roborock.com", "wood-us.roborock.com", "wood-eu.roborock.com", "wood-cn.roborock.com"):
        if host in text:
            text = text.replace(host, LOCAL_WOOD)

    return text


if __name__ == "__main__":
    import argparse
    import subprocess
    import sys

    parser = argparse.ArgumentParser(
        description="Launch mitmweb with Roborock traffic interception.",
    )
    parser.add_argument("--local-api", required=True, help="Hostname of your local API server")
    parser.add_argument("--local-mqtt", default=None, help="Hostname of your local MQTT server (defaults to --local-api)")
    parser.add_argument("--local-wood", default=None, help="Hostname of your local Wood server (defaults to --local-api)")
    parser.add_argument("--mode", default="wireguard", help="mitmweb proxy mode (default: wireguard)")
    parser.add_argument("--listen-port", default=None, help="mitmweb listen port")

    args, extra = parser.parse_known_args()

    env = os.environ.copy()
    env["MITM_LOCAL_API"] = args.local_api
    env["MITM_LOCAL_MQTT"] = args.local_mqtt or args.local_api
    env["MITM_LOCAL_WOOD"] = args.local_wood or args.local_api

    cmd = ["uvx", "--from", "mitmproxy", "mitmweb", "--mode", args.mode, "-s", os.path.abspath(__file__)]
    if args.listen_port:
        cmd += ["--listen-port", args.listen_port]
    cmd += extra

    sys.exit(subprocess.run(cmd, env=env).returncode)
