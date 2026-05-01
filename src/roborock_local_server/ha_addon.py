"""Home Assistant app option adapter for config.toml generation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
from typing import Any
from urllib.parse import urlsplit

from .configure import hash_password


DEFAULT_OPTIONS: dict[str, Any] = {
    "stack_fqdn": "",
    "listener_mode": "local_tls",
    "https_port": 555,
    "mqtt_tls_port": 8881,
    "listen_https_port": 555,
    "listen_mqtt_port": 8881,
    "region": "us",
    "use_external_broker": False,
    "broker_host": "127.0.0.1",
    "broker_port": 18830,
    "enable_topic_bridge": True,
    "tls_mode": "provided",
    "tls_base_domain": "",
    "tls_email": "",
    "cloudflare_token": "",
    "cert_file": "/ssl/fullchain.pem",
    "key_file": "/ssl/privkey.pem",
    "admin_password": "",
    "admin_session_secret": "",
    "protocol_auth_enabled": True,
    "protocol_login_email": "",
    "protocol_login_pin": "",
}

_HOST_RE = re.compile(r"^[a-z0-9.-]+$")
DEFAULT_OPTIONS_PATH = Path("/data/options.json")
DEFAULT_CONFIG_PATH = Path("/data/config.toml")
DEFAULT_CLOUDFLARE_TOKEN_PATH = Path("/run/secrets/cloudflare_token")


def _toml_string(value: str) -> str:
    return json.dumps(value)


def _toml_bool(value: bool) -> str:
    return "true" if value else "false"


def _normalize_hostname(raw_value: str, *, field_name: str, require_api_prefix: bool = False) -> str:
    text = str(raw_value or "").strip()
    if not text:
        raise ValueError(f"{field_name} is required")
    if "://" in text:
        parsed = urlsplit(text)
        candidate = parsed.hostname or ""
    else:
        candidate = text.split("/", 1)[0].strip()
        if ":" in candidate:
            candidate = candidate.split(":", 1)[0].strip()
    normalized = candidate.strip().strip(".").lower()
    if normalized.startswith("*."):
        normalized = normalized[2:].strip()
    if not normalized:
        raise ValueError(f"{field_name} is required")
    if " " in normalized or not _HOST_RE.fullmatch(normalized):
        raise ValueError(f"{field_name} must be a hostname without a scheme or path")
    if "." not in normalized:
        raise ValueError(f"{field_name} must be a fully qualified domain name")
    if require_api_prefix and not normalized.startswith("api-"):
        raise ValueError(f"{field_name} must start with api-")
    return normalized


def _as_bool(value: object, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return bool(value)


def _as_int(value: object, *, field_name: str, default: int) -> int:
    if value in (None, ""):
        return default
    try:
        candidate = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if not (1 <= candidate <= 65535):
        raise ValueError(f"{field_name} must be between 1 and 65535")
    return candidate


def _require_non_empty(value: object, *, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field_name} is required")
    return text


def _require_email(value: object, *, field_name: str) -> str:
    text = _require_non_empty(value, field_name=field_name)
    if "@" not in text:
        raise ValueError(f"{field_name} must be an email address")
    return text


def _require_pin(value: object, *, field_name: str) -> str:
    text = _require_non_empty(value, field_name=field_name)
    if len(text) != 6 or not text.isdigit():
        raise ValueError(f"{field_name} must be exactly 6 digits")
    return text


def _load_options(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return parsed


def _render_config_toml(*, options: dict[str, Any], cloudflare_token_path: Path) -> str:
    merged = dict(DEFAULT_OPTIONS)
    merged.update(options)

    stack_fqdn = _normalize_hostname(
        merged.get("stack_fqdn", ""),
        field_name="stack_fqdn",
        require_api_prefix=True,
    )
    region = str(merged.get("region", "us") or "us").strip().lower() or "us"
    listener_mode = str(merged.get("listener_mode", "local_tls") or "local_tls").strip().lower() or "local_tls"
    if listener_mode not in {"local_tls", "external_tls"}:
        raise ValueError("listener_mode must be 'local_tls' or 'external_tls'")
    https_port = _as_int(merged.get("https_port"), field_name="https_port", default=555)
    mqtt_tls_port = _as_int(merged.get("mqtt_tls_port"), field_name="mqtt_tls_port", default=8881)
    listen_https_port = _as_int(merged.get("listen_https_port"), field_name="listen_https_port", default=https_port)
    listen_mqtt_port = _as_int(merged.get("listen_mqtt_port"), field_name="listen_mqtt_port", default=mqtt_tls_port)

    use_external_broker = _as_bool(merged.get("use_external_broker"), default=False)
    broker_mode = "external" if use_external_broker else "embedded"
    broker_host = str(merged.get("broker_host", "127.0.0.1") or "").strip()
    if not broker_host:
        broker_host = "127.0.0.1" if not use_external_broker else ""
    if use_external_broker and not broker_host:
        raise ValueError("broker_host is required when use_external_broker is true")
    broker_port_default = 1883 if use_external_broker else 18830
    broker_port = _as_int(merged.get("broker_port"), field_name="broker_port", default=broker_port_default)
    enable_topic_bridge = _as_bool(merged.get("enable_topic_bridge"), default=True)

    tls_mode = str(merged.get("tls_mode", "provided") or "provided").strip().lower()
    if tls_mode not in {"provided", "cloudflare_acme"}:
        raise ValueError("tls_mode must be 'provided' or 'cloudflare_acme'")
    tls_base_domain = str(merged.get("tls_base_domain", "") or "").strip()
    tls_email = str(merged.get("tls_email", "") or "").strip()
    cloudflare_token = str(merged.get("cloudflare_token", "") or "").strip()
    cert_file = str(merged.get("cert_file", "/ssl/fullchain.pem") or "").strip()
    key_file = str(merged.get("key_file", "/ssl/privkey.pem") or "").strip()

    if listener_mode == "local_tls" and tls_mode == "cloudflare_acme":
        _normalize_hostname(tls_base_domain, field_name="tls_base_domain")
        _require_email(tls_email, field_name="tls_email")
        _require_non_empty(cloudflare_token, field_name="cloudflare_token")
    elif listener_mode == "local_tls":
        _require_non_empty(cert_file, field_name="cert_file")
        _require_non_empty(key_file, field_name="key_file")

    admin_password = _require_non_empty(merged.get("admin_password"), field_name="admin_password")
    admin_session_secret = str(merged.get("admin_session_secret", "") or "").strip() or secrets.token_urlsafe(32)
    if len(admin_session_secret) < 24:
        raise ValueError("admin_session_secret must be at least 24 characters when set")
    protocol_auth_enabled = _as_bool(merged.get("protocol_auth_enabled"), default=True)
    protocol_login_email = _require_email(merged.get("protocol_login_email"), field_name="protocol_login_email")
    protocol_login_pin = _require_pin(merged.get("protocol_login_pin"), field_name="protocol_login_pin")

    password_hash = hash_password(admin_password)
    protocol_login_pin_hash = hash_password(protocol_login_pin)
    cloudflare_token_file = str(cloudflare_token_path)

    lines = [
        "[network]",
        f"stack_fqdn = {_toml_string(stack_fqdn)}",
        f"listener_mode = {_toml_string(listener_mode)}",
        'bind_host = "0.0.0.0"',
        f"https_port = {https_port}",
        f"mqtt_tls_port = {mqtt_tls_port}",
        f"listen_https_port = {listen_https_port}",
        f"listen_mqtt_port = {listen_mqtt_port}",
        f"region = {_toml_string(region)}",
        "",
        "[broker]",
        f"mode = {_toml_string(broker_mode)}",
        f"host = {_toml_string(broker_host)}",
        f"port = {broker_port}",
        'mosquitto_binary = "mosquitto"',
        f"enable_topic_bridge = {_toml_bool(enable_topic_bridge)}",
        "",
        "[storage]",
        'data_dir = "/data"',
        "",
        "[tls]",
        f"mode = {_toml_string(tls_mode)}",
    ]
    if listener_mode == "local_tls" and tls_mode == "cloudflare_acme":
        lines.extend(
            [
                f"base_domain = {_toml_string(tls_base_domain)}",
                f"email = {_toml_string(tls_email)}",
                f"cloudflare_token_file = {_toml_string(cloudflare_token_file)}",
                "renew_days_before = 30",
                "renew_check_seconds = 43200",
                'acme_server = "zerossl"',
            ]
        )
    else:
        lines.extend(
            [
                'base_domain = ""',
                'email = ""',
                'cloudflare_token_file = ""',
                "renew_days_before = 30",
                "renew_check_seconds = 43200",
                'acme_server = "zerossl"',
                f"cert_file = {_toml_string(cert_file)}",
                f"key_file = {_toml_string(key_file)}",
            ]
        )
    lines.extend(
        [
            "",
            "[admin]",
            f"password_hash = {_toml_string(password_hash)}",
            f"session_secret = {_toml_string(admin_session_secret)}",
            "session_ttl_seconds = 86400",
            f"protocol_auth_enabled = {_toml_bool(protocol_auth_enabled)}",
            f"protocol_login_email = {_toml_string(protocol_login_email)}",
            f"protocol_login_pin_hash = {_toml_string(protocol_login_pin_hash)}",
            "",
        ]
    )
    return "\n".join(lines), cloudflare_token if listener_mode == "local_tls" and tls_mode == "cloudflare_acme" else ""


def write_config_from_home_assistant_options(
    *,
    options_path: Path = DEFAULT_OPTIONS_PATH,
    config_path: Path = DEFAULT_CONFIG_PATH,
    cloudflare_token_path: Path = DEFAULT_CLOUDFLARE_TOKEN_PATH,
) -> Path:
    options = _load_options(options_path)
    config_text, cloudflare_token = _render_config_toml(options=options, cloudflare_token_path=cloudflare_token_path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(config_text, encoding="utf-8")
    if cloudflare_token:
        cloudflare_token_path.parent.mkdir(parents=True, exist_ok=True)
        cloudflare_token_path.write_text(cloudflare_token, encoding="utf-8")
        if os.name != "nt":
            cloudflare_token_path.chmod(0o600)
    return config_path


def main() -> int:
    write_config_from_home_assistant_options()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
