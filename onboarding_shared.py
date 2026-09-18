from __future__ import annotations

import re
import socket
import ssl
from typing import Any, TextIO
from urllib import parse


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
