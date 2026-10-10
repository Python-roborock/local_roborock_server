from __future__ import annotations

import re
import socket
import ssl
import json
from typing import Any, TextIO
from urllib import parse
from urllib import request


DEFAULT_MQTT_TLS_PORT = 8881
TLS_CONNECT_TIMEOUT_SECONDS = 8.0
_REQUIRED_SERVICE_NAMES = ("https_server", "mqtt_tls_proxy", "mqtt_backend_broker")
_SERVICE_PORT_RE = re.compile(r":(?P<port>\d+)\s*$")


def build_ssl_context(*, allow_insecure_tls: bool) -> ssl.SSLContext | None:
    if not allow_insecure_tls:
        return None
    return ssl._create_unverified_context()


def perform_onboarding_preflight(
    *,
    api: Any,
    api_base_url: str,
    allow_insecure_tls: bool,
    output: TextIO,
) -> dict[str, Any]:
    api_host, api_port = _parse_https_endpoint(api_base_url)
    output.write(f"Checking admin API reachability at {api_base_url}/admin/api/status...\n")
    api.login()
    status = api.get_status()
    output.write("Admin API login succeeded.\n")

    output.write("Checking required stack services...\n")
    services = _service_map_from_status(status)
    problems: list[str] = []
    for name in _REQUIRED_SERVICE_NAMES:
        service = services.get(name)
        if service is None:
            problems.append(f"{name} is missing from /admin/api/status")
            continue
        if not bool(service.get("enabled", True)):
            problems.append(f"{name} is disabled")
            continue
        if not bool(service.get("running")):
            detail = str(service.get("detail") or "").strip()
            suffix = f" ({detail})" if detail else ""
            problems.append(f"{name} is not running{suffix}")
    if problems:
        raise RuntimeError("Stack preflight failed: " + "; ".join(problems))
    output.write("Required services are running: https_server, mqtt_tls_proxy, mqtt_backend_broker.\n")

    mqtt_service = services["mqtt_tls_proxy"]
    mqtt_port = _service_port(mqtt_service, default_port=DEFAULT_MQTT_TLS_PORT)

    output.write(f"Checking API TLS listener at https://{api_host}:{api_port}...\n")
    _probe_tls_endpoint(
        host=api_host,
        port=api_port,
        allow_insecure_tls=allow_insecure_tls,
        label=f"https://{api_host}:{api_port}",
    )
    output.write(_tls_success_message(f"https://{api_host}:{api_port}", allow_insecure_tls))

    # Prefer advertised port (external_tls mode) over internal listener port
    advertised_mqtt_port = status.get("advertised_mqtt_tls_port")
    mqtt_preflight_port = advertised_mqtt_port if advertised_mqtt_port else mqtt_port

    output.write(f"Checking MQTT TLS listener at ssl://{api_host}:{mqtt_preflight_port}...\n")
    _probe_tls_endpoint(
        host=api_host,
        port=mqtt_preflight_port,
        allow_insecure_tls=allow_insecure_tls,
        label=f"ssl://{api_host}:{mqtt_preflight_port}",
    )
    output.write(_tls_success_message(f"ssl://{api_host}:{mqtt_preflight_port}", allow_insecure_tls))
    return status


def perform_camera_preflight(*, api: Any, stack_server: str, country_domain: str,
                             model: str, output: TextIO) -> None:
    # Defer firmware-specific checks until a device is selected. Ordinary pairing
    # may coexist with TURN configured for another robot.
    if "/" not in country_domain:
        return
    status = api.get_status()
    services = _service_map_from_status(status)
    if not isinstance(status.get("turn"), dict) or status["turn"].get("mode") not in {"disabled", "provided", "external"}:
        raise RuntimeError("Server does not support camera TURN status; update it before camera onboarding.")
    turn = status["turn"]
    if turn.get("mode") == "disabled":
        raise RuntimeError("Camera preflight failed: TURN is disabled. Configure provided or external mode first.")
    # Firmware varies: Saros uses country_domain, Qrevo a87 uses token.r.
    endpoints = camera_bootstrap_endpoints(stack_server=stack_server, country_domain=country_domain, model=model)
    for host, port in endpoints:
        label = f"https://{host}:{port}/iot.roborock.com/fwapi/createca"
        output.write(f"Checking camera bootstrap DNS and trusted TLS at {label}...\n")
        try:
            _probe_tls_endpoint(host=host, port=port, allow_insecure_tls=False, label=label)
            _probe_camera_response(label=label, expected_host=str(turn.get("host") or ""), expected_port=int(turn.get("port") or 3478))
        except RuntimeError as exc:
            raise RuntimeError(
                f"Camera bootstrap preflight failed: {exc}. Configure DNS and a trusted certificate "
                "for this hostname, with the HTTPS listener or proxy on this port. "
                "A certificate for the api- hostname alone does not cover token.r; "
                "use ZeroSSL wildcard provisioning, a provided wildcard/SAN certificate, "
                "or a proxy with a separately renewed certificate. Actalis automatic provisioning "
                "covers only the API hostname."
            ) from exc
    relay = services.get("turn_relay")
    if turn.get("mode") == "provided" and (not relay or not relay.get("running")):
        raise RuntimeError("Camera preflight failed: provided TURN relay is not running.")
    if turn.get("mode") == "provided":
        output.write("Provided TURN is running. Also enable its UDP listener and relay port mappings; TLS checks do not verify UDP media connectivity.\n")


def camera_bootstrap_endpoints(*, stack_server: str, country_domain: str, model: str = "") -> list[tuple[str, int]]:
    """Check the observed firmware input; unknown models conservatively need both."""
    endpoints: list[tuple[str, int]] = []
    inputs = [("token.r", stack_server), ("country_domain", country_domain)]
    if model == "roborock.vacuum.a87":
        inputs = inputs[:1]
    elif model == "roborock.vacuum.a144":
        inputs = inputs[1:]
    for name, value in inputs:
        host, port = _camera_input(name, value)
        if (host, port) not in endpoints:
            endpoints.append((host, port))
    return endpoints


def _probe_camera_response(*, label: str, expected_host: str, expected_port: int) -> None:
    try:
        req = request.Request(label, data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
        with request.urlopen(req, context=ssl.create_default_context(), timeout=TLS_CONNECT_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read(65536))
        expected = f"turn:{expected_host}:{expected_port}"
        parts = [payload.get(key) for key in ("data", "result")] if isinstance(payload, dict) else []
        matches = any(isinstance(part, dict) and (
            part.get("url") == expected or expected in (part.get("urls") or [])
        ) for part in parts)
        if not isinstance(payload, dict) or payload.get("code") != 200 or not matches:
            raise ValueError("createca response does not match the server's configured TURN endpoint")
    except Exception as exc:
        raise RuntimeError(f"Camera bootstrap route check failed at {label}: verify proxy routing and TURN configuration.") from exc


def _camera_input(name: str, value: str) -> tuple[str, int]:
    if not value.endswith("/") or len(value) > 15:
        raise ValueError(
            f"Camera {name} must include a trailing slash and fit in 15 characters "
            "including any port. Use a shorter hostname or port 443."
        )
    host, port = _parse_https_endpoint(f"https://{value}")
    parsed = parse.urlsplit(f"https://{value}")
    if parsed.path != "/" or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError(f"Camera {name} must contain only a hostname, optional port, and trailing slash.")
    return host, port


def _parse_https_endpoint(url: str) -> tuple[str, int]:
    parsed = parse.urlsplit(str(url or "").strip())
    host = str(parsed.hostname or "").strip()
    if not host:
        raise ValueError("A valid HTTPS server URL is required.")
    port = parsed.port or 443
    return host, port


def _service_map_from_status(status: dict[str, Any]) -> dict[str, dict[str, Any]]:
    health = status.get("health")
    if not isinstance(health, dict):
        raise RuntimeError("Stack preflight failed: /admin/api/status did not return a health payload.")
    services = health.get("services")
    if not isinstance(services, list):
        raise RuntimeError("Stack preflight failed: /admin/api/status did not return health.services.")
    out: dict[str, dict[str, Any]] = {}
    for item in services:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if name:
            out[name] = item
    return out


def _service_port(service: dict[str, Any], *, default_port: int) -> int:
    detail = str(service.get("detail") or "").strip()
    match = _SERVICE_PORT_RE.search(detail)
    if match is None:
        return default_port
    try:
        return int(match.group("port"))
    except ValueError:
        return default_port


def _probe_tls_endpoint(*, host: str, port: int, allow_insecure_tls: bool, label: str) -> None:
    context = build_ssl_context(allow_insecure_tls=allow_insecure_tls) or ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TLS_CONNECT_TIMEOUT_SECONDS) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                tls_sock.do_handshake()
    except ssl.SSLCertVerificationError as exc:
        raise RuntimeError(f"TLS certificate verification failed for {label}: {exc}") from exc
    except ssl.SSLError as exc:
        raise RuntimeError(f"TLS handshake failed for {label}: {exc}") from exc
    except OSError as exc:
        raise RuntimeError(f"Could not connect to {label}: {exc}") from exc


def _tls_success_message(label: str, allow_insecure_tls: bool) -> str:
    if allow_insecure_tls:
        return f"TLS listener reachable at {label} (certificate verification skipped).\n"
    return f"TLS certificate is valid and listener is reachable at {label}.\n"


_HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


def normalize_camera_domain(raw_value: str) -> str:
    candidate = str(raw_value or "").strip()
    if not candidate:
        return ""
    if "://" in candidate:
        raise ValueError("Camera domain must be a hostname without a scheme (e.g. 'myvac.cc').")
    if ":" in candidate:
        raise ValueError("Camera domain must be a hostname without a port.")
    candidate = candidate.rstrip("/")
    if "/" in candidate:
        raise ValueError("Camera domain must be a hostname without a path.")
    if " " in candidate or not _HOSTNAME_RE.fullmatch(candidate):
        raise ValueError(f"Camera domain '{candidate}' must be a valid hostname.")
    if len(candidate) > 14:
        raise ValueError(f"Camera domain '{candidate}' exceeds the 14-character limit ({len(candidate)} chars).")
    result = f"{candidate}/"
    _camera_input("country_domain", result)
    return result
