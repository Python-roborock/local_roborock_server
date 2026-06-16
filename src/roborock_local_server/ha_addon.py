"""Home Assistant app option adapter for config.toml generation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import tomllib
from typing import Any
from urllib.parse import urlsplit

from .configure import hash_password

DEFAULT_OPTIONS: dict[str, Any] = {
    "stack_fqdn": "",
    "https_port": 555,
    "mqtt_tls_port": 8881,
    "advertised_https_port": 0,
    "advertised_mqtt_tls_port": 0,
    "region": "us",
    "tls_mode": "provided",
    "tls_base_domain": "",
    "tls_email": "",
    "acme_server": "zerossl",
    "acme_eab_kid": "",
    "acme_eab_hmac_key": "",
    "cloudflare_token": "",
    "cert_file": "",
    "key_file": "",
    "admin_password": "",
    "protocol_login_email": "",
    "protocol_login_pin": "",
}

_HOST_RE = re.compile(r"^[a-z0-9.-]+$")
DEFAULT_OPTIONS_PATH = Path("/data/options.json")
DEFAULT_CONFIG_PATH = Path("/data/config.toml")
DEFAULT_CLOUDFLARE_TOKEN_PATH = Path("/run/secrets/cloudflare_token")
DEFAULT_ACME_EAB_KID_PATH = Path("/run/secrets/acme_eab_kid")
DEFAULT_ACME_EAB_HMAC_KEY_PATH = Path("/run/secrets/acme_eab_hmac_key")


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


def _as_optional_port(value: object, *, field_name: str) -> int:
    if value in (None, "", 0, "0"):
        return 0
    return _as_int(value, field_name=field_name, default=0)


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


def _normalize_acme_server(value: object, *, field_name: str) -> str:
    normalized = str(value or "").strip().lower() or "zerossl"
    if normalized not in {"zerossl", "actalis"}:
        raise ValueError(f"{field_name} must be 'zerossl' or 'actalis'")
    return normalized


def _load_options(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return parsed


def _load_existing_admin_session_secret(config_path: Path) -> str:
    if not config_path.exists():
        return ""
    try:
        parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return ""
    admin = parsed.get("admin")
    if not isinstance(admin, dict):
        return ""
    secret = str(admin.get("session_secret", "") or "").strip()
    return secret if len(secret) >= 24 else ""


def _render_config_toml(
    *,
    options: dict[str, Any],
    config_path: Path,
    cloudflare_token_path: Path,
    acme_eab_kid_path: Path,
    acme_eab_hmac_key_path: Path,
) -> tuple[str, dict[Path, str]]:
    merged = dict(DEFAULT_OPTIONS)
    merged.update(options)

    stack_fqdn = _normalize_hostname(
        merged.get("stack_fqdn", ""),
        field_name="stack_fqdn",
        require_api_prefix=True,
    )
    region = str(merged.get("region", "us") or "us").strip().lower() or "us"
    listener_mode = str(merged.get("listener_mode", "local_tls") or "local_tls").strip().lower() or "local_tls"
    if listener_mode != "local_tls":
        # The add-on always terminates its own TLS; external_tls is Docker-only.
        raise ValueError("listener_mode='external_tls' is not supported by the Home Assistant add-on")
    https_port = _as_int(merged.get("https_port"), field_name="https_port", default=555)
    mqtt_tls_port = _as_int(merged.get("mqtt_tls_port"), field_name="mqtt_tls_port", default=8881)
    advertised_https_port = _as_optional_port(
        merged.get("advertised_https_port"),
        field_name="advertised_https_port",
    )
    advertised_mqtt_tls_port = _as_optional_port(
        merged.get("advertised_mqtt_tls_port"),
        field_name="advertised_mqtt_tls_port",
    )
    advertised_https_port = advertised_https_port or https_port
    advertised_mqtt_tls_port = advertised_mqtt_tls_port or mqtt_tls_port

    # Legacy HA options for broker selection are ignored now that the add-on
    # always runs the embedded broker with the topic bridge enabled.
    broker_mode = "embedded"
    broker_host = "127.0.0.1"
    broker_port = 18830

    tls_mode = str(merged.get("tls_mode", "provided") or "provided").strip().lower()
    if tls_mode not in {"provided", "cloudflare_acme"}:
        raise ValueError("tls_mode must be 'provided' or 'cloudflare_acme'")
    tls_base_domain = str(merged.get("tls_base_domain", "") or "").strip()
    tls_email = str(merged.get("tls_email", "") or "").strip()
    acme_server = _normalize_acme_server(merged.get("acme_server", "zerossl"), field_name="acme_server")
    acme_eab_kid = str(merged.get("acme_eab_kid", "") or "").strip()
    acme_eab_hmac_key = str(merged.get("acme_eab_hmac_key", "") or "").strip()
    cloudflare_token = str(merged.get("cloudflare_token", "") or "").strip()
    cert_file = str(merged.get("cert_file", "") or "").strip()
    key_file = str(merged.get("key_file", "") or "").strip()
    effective_tls_mode = "cloudflare_acme" if cloudflare_token else tls_mode

    if effective_tls_mode == "cloudflare_acme":
        _normalize_hostname(tls_base_domain, field_name="tls_base_domain")
        _require_email(tls_email, field_name="tls_email")
        _require_non_empty(cloudflare_token, field_name="cloudflare_token")
        if (acme_eab_kid and not acme_eab_hmac_key) or (acme_eab_hmac_key and not acme_eab_kid):
            raise ValueError("acme_eab_kid and acme_eab_hmac_key must be set together")
        if acme_server == "actalis":
            _require_non_empty(acme_eab_kid, field_name="acme_eab_kid")
            _require_non_empty(acme_eab_hmac_key, field_name="acme_eab_hmac_key")
    else:
        _require_non_empty(cert_file, field_name="cert_file")
        _require_non_empty(key_file, field_name="key_file")

    admin_password = _require_non_empty(merged.get("admin_password"), field_name="admin_password")
    admin_session_secret = (
        str(merged.get("admin_session_secret", "") or "").strip()
        or _load_existing_admin_session_secret(config_path)
        or secrets.token_urlsafe(32)
    )
    if len(admin_session_secret) < 24:
        raise ValueError("admin_session_secret must be at least 24 characters when set")
    # The Home Assistant add-on no longer exposes this toggle.
    # Keep protocol auth enabled even if a stale stored option is present.
    protocol_auth_enabled = True
    new_connections_enabled = True
    protocol_login_email = _require_email(merged.get("protocol_login_email"), field_name="protocol_login_email")
    protocol_login_pin = _require_pin(merged.get("protocol_login_pin"), field_name="protocol_login_pin")

    password_hash = hash_password(admin_password)
    protocol_login_pin_hash = hash_password(protocol_login_pin)
    cloudflare_token_file = str(cloudflare_token_path)
    acme_eab_kid_file = str(acme_eab_kid_path) if acme_server == "actalis" else ""
    acme_eab_hmac_key_file = str(acme_eab_hmac_key_path) if acme_server == "actalis" else ""

    lines = [
        "[network]",
        f"stack_fqdn = {_toml_string(stack_fqdn)}",
        'bind_host = "0.0.0.0"',
        f"https_port = {https_port}",
        f"mqtt_tls_port = {mqtt_tls_port}",
        f"advertised_https_port = {advertised_https_port}",
        f"advertised_mqtt_tls_port = {advertised_mqtt_tls_port}",
        f"region = {_toml_string(region)}",
        "",
        "[broker]",
        f"mode = {_toml_string(broker_mode)}",
        f"host = {_toml_string(broker_host)}",
        f"port = {broker_port}",
        'mosquitto_binary = "mosquitto"',
        "enable_topic_bridge = true",
        "",
        "[storage]",
        'data_dir = "/data"',
        "",
        "[tls]",
        f"mode = {_toml_string(effective_tls_mode)}",
    ]
    if effective_tls_mode == "cloudflare_acme":
        lines.extend(
            [
                f"base_domain = {_toml_string(tls_base_domain)}",
                f"email = {_toml_string(tls_email)}",
                f"cloudflare_token_file = {_toml_string(cloudflare_token_file)}",
                "renew_days_before = 30",
                "renew_check_seconds = 43200",
                f"acme_server = {_toml_string(acme_server)}",
                'acme_eab_kid = ""',
                'acme_eab_hmac_key = ""',
                f"acme_eab_kid_file = {_toml_string(acme_eab_kid_file)}",
                f"acme_eab_hmac_key_file = {_toml_string(acme_eab_hmac_key_file)}",
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
                f"acme_server = {_toml_string(acme_server)}",
                'acme_eab_kid = ""',
                'acme_eab_hmac_key = ""',
                'acme_eab_kid_file = ""',
                'acme_eab_hmac_key_file = ""',
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
            f"new_connections_enabled = {_toml_bool(new_connections_enabled)}",
            f"protocol_login_email = {_toml_string(protocol_login_email)}",
            f"protocol_login_pin_hash = {_toml_string(protocol_login_pin_hash)}",
            "",
        ]
    )
    secrets_to_write: dict[Path, str] = {}
    if effective_tls_mode == "cloudflare_acme":
        secrets_to_write[cloudflare_token_path] = cloudflare_token
        if acme_server == "actalis":
            secrets_to_write[acme_eab_kid_path] = acme_eab_kid
            secrets_to_write[acme_eab_hmac_key_path] = acme_eab_hmac_key
    return "\n".join(lines), secrets_to_write


def write_config_from_home_assistant_options(
    *,
    options_path: Path = DEFAULT_OPTIONS_PATH,
    config_path: Path = DEFAULT_CONFIG_PATH,
    cloudflare_token_path: Path = DEFAULT_CLOUDFLARE_TOKEN_PATH,
    acme_eab_kid_path: Path = DEFAULT_ACME_EAB_KID_PATH,
    acme_eab_hmac_key_path: Path = DEFAULT_ACME_EAB_HMAC_KEY_PATH,
) -> Path:
    options = _load_options(options_path)
    config_text, secrets_to_write = _render_config_toml(
        options=options,
        config_path=config_path,
        cloudflare_token_path=cloudflare_token_path,
        acme_eab_kid_path=acme_eab_kid_path,
        acme_eab_hmac_key_path=acme_eab_hmac_key_path,
    )
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(config_text, encoding="utf-8")
    managed_secret_paths = (cloudflare_token_path, acme_eab_kid_path, acme_eab_hmac_key_path)
    for path, contents in secrets_to_write.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        if os.name != "nt":
            path.chmod(0o600)
    for path in managed_secret_paths:
        if path not in secrets_to_write and path.exists():
            path.unlink()
    return config_path


def main() -> int:
    write_config_from_home_assistant_options()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
