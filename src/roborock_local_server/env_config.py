"""Generate config.toml from ROBOROCK_SERVER_* environment variables.

This lets Docker Compose (and similar) deployments boot straight from
environment variables, without running the host-side `configure` wizard
first. It intentionally covers only the deployment/infrastructure-shaped
settings (network, broker, storage, tls); it is not meant to grow a
variable for every config.toml key.

The [admin] credentials (password, protocol login email/PIN) are optional
as a group: set none of them and the container boots straight into the
Setup Wizard (/admin) with network/broker/storage/tls already filled in
from these env vars - only the credentials are still asked for. Set all
of them for a fully headless boot with no browser step at all.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import tomllib
from typing import Callable, Mapping
from urllib.parse import urlsplit

from .configure import hash_password

ENV_PREFIX = "ROBOROCK_SERVER_"

_HOST_RE = re.compile(r"^[a-z0-9.-]+$")

DEFAULT_CONFIG_PATH = Path("/data/config.toml")
DEFAULT_CLOUDFLARE_TOKEN_PATH = Path("/run/secrets/cloudflare_token")
DEFAULT_ACME_EAB_KID_PATH = Path("/run/secrets/acme_eab_kid")
DEFAULT_ACME_EAB_HMAC_KEY_PATH = Path("/run/secrets/acme_eab_hmac_key")


def _toml_string(value: str) -> str:
    return json.dumps(value)


def _toml_bool(value: bool) -> str:
    return "true" if value else "false"


def _get(env: Mapping[str, str], name: str, default: str = "") -> str:
    return str(env.get(f"{ENV_PREFIX}{name}", "") or "").strip() or default


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


def _as_port(value: str, *, field_name: str, default: int) -> int:
    if not value:
        return default
    try:
        candidate = int(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if not (1 <= candidate <= 65535):
        raise ValueError(f"{field_name} must be between 1 and 65535")
    return candidate


def _as_bool(value: str, *, default: bool) -> bool:
    if not value:
        return default
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"expected a boolean value, got {value!r}")


def _as_trusted_proxies(value: str, *, default: tuple[str, ...]) -> tuple[str, ...]:
    if not value:
        return default
    entries: list[str] = []
    for item in value.split(","):
        text = item.strip()
        if not text:
            continue
        try:
            ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ValueError(f"trusted_proxies entry {text!r} is not a valid IP address or CIDR network") from exc
        entries.append(text)
    return tuple(entries) if entries else default


def _require_non_empty(value: str, *, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{ENV_PREFIX}{field_name} is required")
    return text


def _require_email(value: str, *, field_name: str) -> str:
    text = _require_non_empty(value, field_name=field_name)
    if "@" not in text:
        raise ValueError(f"{ENV_PREFIX}{field_name} must be an email address")
    return text


def _require_pin(value: str, *, field_name: str) -> str:
    text = _require_non_empty(value, field_name=field_name)
    if len(text) != 6 or not text.isdigit():
        raise ValueError(f"{ENV_PREFIX}{field_name} must be exactly 6 digits")
    return text


def _normalize_acme_server(value: str) -> str:
    normalized = value.strip().lower() or "zerossl"
    if normalized not in {"zerossl", "actalis"}:
        raise ValueError(f"{ENV_PREFIX}ACME_SERVER must be 'zerossl' or 'actalis'")
    return normalized


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


@dataclass(frozen=True)
class SecretPaths:
    """Where env-supplied plaintext secrets get written, and the Docker-secret
    style *_FILE overrides that skip writing entirely."""

    cloudflare_token_file: Path = DEFAULT_CLOUDFLARE_TOKEN_PATH
    acme_eab_kid_file: Path = DEFAULT_ACME_EAB_KID_PATH
    acme_eab_hmac_key_file: Path = DEFAULT_ACME_EAB_HMAC_KEY_PATH


def has_env_config(env: Mapping[str, str]) -> bool:
    """True when enough ROBOROCK_SERVER_* vars are present to attempt generation."""
    return bool(_get(env, "STACK_FQDN"))


def render_config_toml_from_env(
    env: Mapping[str, str],
    *,
    config_path: Path,
    secret_paths: SecretPaths = SecretPaths(),
) -> tuple[str, dict[Path, str]]:
    stack_fqdn = _normalize_hostname(_get(env, "STACK_FQDN"), field_name="STACK_FQDN", require_api_prefix=True)
    listener_mode = _get(env, "LISTENER_MODE", "local_tls").lower()
    if listener_mode not in {"local_tls", "external_tls"}:
        raise ValueError(f"{ENV_PREFIX}LISTENER_MODE must be 'local_tls' or 'external_tls'")
    bind_host = _get(env, "BIND_HOST", "0.0.0.0")
    region = _get(env, "REGION", "us").lower()
    https_port = _as_port(_get(env, "HTTPS_PORT"), field_name=f"{ENV_PREFIX}HTTPS_PORT", default=555)
    mqtt_tls_port = _as_port(_get(env, "MQTT_TLS_PORT"), field_name=f"{ENV_PREFIX}MQTT_TLS_PORT", default=8881)
    advertised_https_port = _as_port(
        _get(env, "ADVERTISED_HTTPS_PORT"),
        field_name=f"{ENV_PREFIX}ADVERTISED_HTTPS_PORT",
        default=https_port,
    )
    advertised_mqtt_tls_port = _as_port(
        _get(env, "ADVERTISED_MQTT_TLS_PORT"),
        field_name=f"{ENV_PREFIX}ADVERTISED_MQTT_TLS_PORT",
        default=mqtt_tls_port,
    )
    trusted_proxies = _as_trusted_proxies(_get(env, "TRUSTED_PROXIES"), default=("127.0.0.1", "::1"))

    broker_mode = _get(env, "BROKER_MODE", "embedded").lower()
    if broker_mode not in {"embedded", "external"}:
        raise ValueError(f"{ENV_PREFIX}BROKER_MODE must be 'embedded' or 'external'")
    if broker_mode == "embedded":
        broker_host = _get(env, "BROKER_HOST", "127.0.0.1")
        broker_port = _as_port(_get(env, "BROKER_PORT"), field_name=f"{ENV_PREFIX}BROKER_PORT", default=18830)
    else:
        broker_host = _require_non_empty(_get(env, "BROKER_HOST"), field_name="BROKER_HOST")
        broker_port = _as_port(_get(env, "BROKER_PORT"), field_name=f"{ENV_PREFIX}BROKER_PORT", default=1883)

    data_dir = _get(env, "DATA_DIR", "/data")

    tls_mode = _get(env, "TLS_MODE", "cloudflare_acme").lower()
    if tls_mode not in {"cloudflare_acme", "provided"}:
        raise ValueError(f"{ENV_PREFIX}TLS_MODE must be 'cloudflare_acme' or 'provided'")
    if listener_mode == "external_tls" and tls_mode != "provided":
        raise ValueError(
            f"{ENV_PREFIX}LISTENER_MODE='external_tls' requires {ENV_PREFIX}TLS_MODE='provided' "
            "(the proxy terminates TLS; the server does not issue certificates)"
        )

    tls_base_domain = ""
    tls_email = ""
    acme_server = "zerossl"
    cloudflare_token_file = ""
    acme_eab_kid_file = ""
    acme_eab_hmac_key_file = ""
    cert_file = ""
    key_file = ""
    secrets_to_write: dict[Path, str] = {}

    if listener_mode == "local_tls":
        if tls_mode == "cloudflare_acme":
            tls_base_domain = _normalize_hostname(_get(env, "TLS_BASE_DOMAIN"), field_name="TLS_BASE_DOMAIN")
            tls_email = _require_non_empty(_get(env, "TLS_EMAIL"), field_name="TLS_EMAIL")
            acme_server = _normalize_acme_server(_get(env, "ACME_SERVER", "zerossl"))

            cloudflare_token_file_override = _get(env, "CLOUDFLARE_TOKEN_FILE")
            cloudflare_token = _get(env, "CLOUDFLARE_TOKEN")
            if cloudflare_token_file_override:
                cloudflare_token_file = cloudflare_token_file_override
            elif cloudflare_token:
                cloudflare_token_file = str(secret_paths.cloudflare_token_file)
                secrets_to_write[secret_paths.cloudflare_token_file] = cloudflare_token
            else:
                raise ValueError(
                    f"{ENV_PREFIX}CLOUDFLARE_TOKEN or {ENV_PREFIX}CLOUDFLARE_TOKEN_FILE is required "
                    f"when {ENV_PREFIX}TLS_MODE='cloudflare_acme'"
                )

            if acme_server == "actalis":
                eab_kid_file_override = _get(env, "ACME_EAB_KID_FILE")
                eab_kid = _get(env, "ACME_EAB_KID")
                eab_hmac_file_override = _get(env, "ACME_EAB_HMAC_KEY_FILE")
                eab_hmac = _get(env, "ACME_EAB_HMAC_KEY")
                if not (eab_kid_file_override or eab_kid):
                    raise ValueError(f"Actalis requires {ENV_PREFIX}ACME_EAB_KID or {ENV_PREFIX}ACME_EAB_KID_FILE")
                if not (eab_hmac_file_override or eab_hmac):
                    raise ValueError(
                        f"Actalis requires {ENV_PREFIX}ACME_EAB_HMAC_KEY or {ENV_PREFIX}ACME_EAB_HMAC_KEY_FILE"
                    )
                acme_eab_kid_file = eab_kid_file_override or str(secret_paths.acme_eab_kid_file)
                if not eab_kid_file_override:
                    secrets_to_write[secret_paths.acme_eab_kid_file] = eab_kid
                acme_eab_hmac_key_file = eab_hmac_file_override or str(secret_paths.acme_eab_hmac_key_file)
                if not eab_hmac_file_override:
                    secrets_to_write[secret_paths.acme_eab_hmac_key_file] = eab_hmac
        else:
            cert_file = _require_non_empty(_get(env, "CERT_FILE"), field_name="CERT_FILE")
            key_file = _require_non_empty(_get(env, "KEY_FILE"), field_name="KEY_FILE")

    # The [admin] fields are optional as a group: set none of them to leave
    # credentials to the Setup Wizard (it fills in just [admin] on top of
    # this network/broker/storage/tls config), or set all of them for a
    # fully headless, no-browser-step boot.
    raw_admin_password = _get(env, "ADMIN_PASSWORD")
    raw_protocol_login_email = _get(env, "PROTOCOL_LOGIN_EMAIL")
    raw_protocol_login_pin = _get(env, "PROTOCOL_LOGIN_PIN")
    admin_fields_present = (bool(raw_admin_password), bool(raw_protocol_login_email), bool(raw_protocol_login_pin))
    if any(admin_fields_present) and not all(admin_fields_present):
        raise ValueError(
            f"Set all of {ENV_PREFIX}ADMIN_PASSWORD, {ENV_PREFIX}PROTOCOL_LOGIN_EMAIL, and "
            f"{ENV_PREFIX}PROTOCOL_LOGIN_PIN together, or none of them (and finish setup in the "
            "Setup Wizard at /admin instead)."
        )
    include_admin = all(admin_fields_present)

    lines = [
        "[network]",
        f"stack_fqdn = {_toml_string(stack_fqdn)}",
        f"listener_mode = {_toml_string(listener_mode)}",
        f"bind_host = {_toml_string(bind_host)}",
        f"https_port = {https_port}",
        f"mqtt_tls_port = {mqtt_tls_port}",
        f"advertised_https_port = {advertised_https_port}",
        f"advertised_mqtt_tls_port = {advertised_mqtt_tls_port}",
        f"region = {_toml_string(region)}",
        f"trusted_proxies = [{', '.join(_toml_string(p) for p in trusted_proxies)}]",
        "",
        "[broker]",
        f"mode = {_toml_string(broker_mode)}",
        f"host = {_toml_string(broker_host)}",
        f"port = {broker_port}",
        'mosquitto_binary = "mosquitto"',
        "enable_topic_bridge = true",
        "",
        "[storage]",
        f"data_dir = {_toml_string(data_dir)}",
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

    if include_admin:
        admin_session_secret = (
            _get(env, "ADMIN_SESSION_SECRET")
            or _load_existing_admin_session_secret(config_path)
            or secrets.token_urlsafe(32)
        )
        if len(admin_session_secret) < 24:
            raise ValueError(f"{ENV_PREFIX}ADMIN_SESSION_SECRET must be at least 24 characters when set")
        new_connections_enabled = _as_bool(_get(env, "NEW_CONNECTIONS_ENABLED"), default=True)
        protocol_login_email = _require_email(raw_protocol_login_email, field_name="PROTOCOL_LOGIN_EMAIL")
        protocol_login_pin = _require_pin(raw_protocol_login_pin, field_name="PROTOCOL_LOGIN_PIN")
        password_hash = hash_password(raw_admin_password)
        protocol_login_pin_hash = hash_password(protocol_login_pin)

        lines.extend(
            [
                "",
                "[admin]",
                f"password_hash = {_toml_string(password_hash)}",
                f"session_secret = {_toml_string(admin_session_secret)}",
                "session_ttl_seconds = 86400",
                "protocol_auth_enabled = true",
                f"new_connections_enabled = {_toml_bool(new_connections_enabled)}",
                f"protocol_login_email = {_toml_string(protocol_login_email)}",
                f"protocol_login_pin_hash = {_toml_string(protocol_login_pin_hash)}",
                "",
            ]
        )
    return "\n".join(lines), secrets_to_write


@dataclass(frozen=True)
class _Setting:
    """One config.toml key an environment variable can set."""

    env: str
    section: str
    key: str
    parse: Callable[[str], object]
    secret: bool = False


def _text(name: str) -> Callable[[str], object]:
    def parse(value: str) -> object:
        text = value.strip()
        if not text:
            raise ValueError(f"{ENV_PREFIX}{name} is empty")
        return text

    return parse


def _choice(name: str, allowed: set[str]) -> Callable[[str], object]:
    def parse(value: str) -> object:
        text = value.strip().lower()
        if text not in allowed:
            raise ValueError(f"{ENV_PREFIX}{name} must be one of {sorted(allowed)}")
        return text

    return parse


def _port_of(name: str) -> Callable[[str], object]:
    return lambda value: _as_port(value.strip(), field_name=f"{ENV_PREFIX}{name}", default=0)


def _bool_of(name: str) -> Callable[[str], object]:
    return lambda value: _as_bool(value.strip(), default=False)


def _int_of(name: str) -> Callable[[str], object]:
    def parse(value: str) -> object:
        try:
            number = int(value.strip())
        except ValueError as exc:
            raise ValueError(f"{ENV_PREFIX}{name} must be an integer") from exc
        if number <= 0:
            raise ValueError(f"{ENV_PREFIX}{name} must be greater than 0")
        return number

    return parse


def _turn_secret(name: str) -> Callable[[str], object]:
    def parse(value: str) -> object:
        text = value.strip()
        if not text or any(character in text for character in "\r\n:="):
            raise ValueError(f"{ENV_PREFIX}{name} cannot be empty or contain newlines, colons or equals signs")
        return text

    return parse


def _hostname_of(name: str, *, api_prefix: bool = False) -> Callable[[str], object]:
    return lambda value: _normalize_hostname(value, field_name=f"{ENV_PREFIX}{name}", require_api_prefix=api_prefix)


# Only the simple, single-value settings. Secrets files, EAB credentials and the admin login are not patched.
SETTINGS: tuple[_Setting, ...] = (
    _Setting("STACK_FQDN", "network", "stack_fqdn", _hostname_of("STACK_FQDN", api_prefix=True)),
    _Setting("LISTENER_MODE", "network", "listener_mode", _choice("LISTENER_MODE", {"local_tls", "external_tls"})),
    _Setting("BIND_HOST", "network", "bind_host", _text("BIND_HOST")),
    _Setting("HTTPS_PORT", "network", "https_port", _port_of("HTTPS_PORT")),
    _Setting("MQTT_TLS_PORT", "network", "mqtt_tls_port", _port_of("MQTT_TLS_PORT")),
    _Setting("ADVERTISED_HTTPS_PORT", "network", "advertised_https_port", _port_of("ADVERTISED_HTTPS_PORT")),
    _Setting("ADVERTISED_MQTT_TLS_PORT", "network", "advertised_mqtt_tls_port", _port_of("ADVERTISED_MQTT_TLS_PORT")),
    _Setting("REGION", "network", "region", lambda v: _text("REGION")(v).lower()),
    _Setting("TRUSTED_PROXIES", "network", "trusted_proxies", lambda v: list(_as_trusted_proxies(v.strip(), default=()))),
    _Setting("BROKER_MODE", "broker", "mode", _choice("BROKER_MODE", {"embedded", "external"})),
    _Setting("BROKER_HOST", "broker", "host", _text("BROKER_HOST")),
    _Setting("BROKER_PORT", "broker", "port", _port_of("BROKER_PORT")),
    _Setting("DATA_DIR", "storage", "data_dir", _text("DATA_DIR")),
    _Setting("TLS_MODE", "tls", "mode", _choice("TLS_MODE", {"cloudflare_acme", "provided"})),
    _Setting("TLS_BASE_DOMAIN", "tls", "base_domain", _hostname_of("TLS_BASE_DOMAIN")),
    _Setting("TLS_EMAIL", "tls", "email", _text("TLS_EMAIL")),
    _Setting("ACME_SERVER", "tls", "acme_server", lambda v: _normalize_acme_server(v.strip())),
    _Setting("CERT_FILE", "tls", "cert_file", _text("CERT_FILE")),
    _Setting("KEY_FILE", "tls", "key_file", _text("KEY_FILE")),
    _Setting("OTA_ENABLE_INSTALL", "ota", "enable_install", _bool_of("OTA_ENABLE_INSTALL")),
    _Setting("MATTER_KEY_PROXY", "matter", "key_proxy", _bool_of("MATTER_KEY_PROXY")),
    _Setting("TURN_MODE", "turn", "mode", _choice("TURN_MODE", {"disabled", "provided", "external"})),
    _Setting("TURN_HOST", "turn", "host", _text("TURN_HOST")),
    _Setting("TURN_PORT", "turn", "port", _port_of("TURN_PORT")),
    _Setting("TURN_USERNAME", "turn", "username", _turn_secret("TURN_USERNAME")),
    _Setting("TURN_PASSWORD", "turn", "password", _turn_secret("TURN_PASSWORD"), secret=True),
    _Setting("TURN_REALM", "turn", "realm", _turn_secret("TURN_REALM")),
    _Setting("TURN_TTL", "turn", "ttl", _int_of("TURN_TTL")),
)

_SECTION_RE = re.compile(r"^\s*\[([A-Za-z0-9_.-]+)\]\s*(#.*)?$")


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return _toml_bool(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_string(str(item)) for item in value) + "]"
    return _toml_string(str(value))


def _set_key(lines: list[str], section: str, key: str, value: str) -> None:
    """Sets one key in the section, changing only that line (or adding it); everything else stays as written."""
    key_re = re.compile(rf"^\s*{re.escape(key)}\s*=")
    start = None
    for index, line in enumerate(lines):
        match = _SECTION_RE.match(line)
        if match and match.group(1) == section:
            start = index
            break
    if start is None:
        while lines and not lines[-1].strip():
            lines.pop()
        lines.extend(["", f"[{section}]", f"{key} = {value}"])
        return
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if _SECTION_RE.match(lines[index]) or lines[index].lstrip().startswith("[["):
            end = index
            break
    last_content = start
    for index in range(start + 1, end):
        if key_re.match(lines[index]):
            indent = re.match(r"\s*", lines[index]).group(0)
            stop = index
            # an array can run over several lines: replace all of them
            first = lines[index].split("=", 1)[1]
            if first.count("[") > first.count("]"):
                depth = first.count("[") - first.count("]")
                while depth > 0 and stop + 1 < end:
                    stop += 1
                    depth += lines[stop].count("[") - lines[stop].count("]")
            lines[index : stop + 1] = [f"{indent}{key} = {value}"]
            return
        if lines[index].strip() and not lines[index].lstrip().startswith("#"):
            last_content = index
    lines.insert(last_content + 1, f"{key} = {value}")


def plan_config_patch(env: Mapping[str, str], text: str) -> tuple[str, list[str]]:
    """The config text with the environment's settings applied, and a line for each change made.

    Only variables that are set are looked at, and only a key whose value differs is touched. A variable that is set
    but invalid is reported and skipped, so a typo never stops the server from starting.
    """
    newline = "\r\n" if "\r\n" in text else "\n"
    try:
        current = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return text, [f"config.toml is not valid TOML ({exc}); left unchanged"]
    lines = text.replace("\r\n", "\n").split("\n")
    changes: list[str] = []
    for setting in SETTINGS:
        raw = _get(env, setting.env)
        if not raw:
            continue
        try:
            wanted = setting.parse(raw)
        except ValueError as exc:
            changes.append(f"skipped {ENV_PREFIX}{setting.env}: {exc}")
            continue
        existing = (current.get(setting.section) or {}).get(setting.key)
        if existing == wanted:
            continue
        _set_key(lines, setting.section, setting.key, _toml_value(wanted))
        shown_old = "unset" if existing is None else ("***" if setting.secret else repr(existing))
        shown_new = "***" if setting.secret else repr(wanted)
        changes.append(f"{setting.section}.{setting.key}: {shown_old} -> {shown_new} (from {ENV_PREFIX}{setting.env})")
    return newline.join(lines), changes


def patch_config_from_env(env: Mapping[str, str], *, config_path: Path) -> list[str]:
    """Applies the environment to an existing config.toml in place. Returns what changed (empty when nothing did)."""
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError:
        return []
    patched, changes = plan_config_patch(env, text)
    applied = [change for change in changes if not change.startswith(("skipped", "config.toml is not valid"))]
    if applied and patched != text:
        temp = config_path.with_name(config_path.name + ".tmp")
        try:
            temp.write_text(patched, encoding="utf-8")
            os.replace(temp, config_path)
        except OSError:
            # a bind-mounted single file cannot be replaced; write it in place instead
            temp.unlink(missing_ok=True)
            config_path.write_text(patched, encoding="utf-8")
    return changes


def write_config_from_env(
    env: Mapping[str, str],
    *,
    config_path: Path = DEFAULT_CONFIG_PATH,
    secret_paths: SecretPaths = SecretPaths(),
) -> Path:
    config_text, secrets_to_write = render_config_toml_from_env(
        env,
        config_path=config_path,
        secret_paths=secret_paths,
    )
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(config_text, encoding="utf-8")
    for path, contents in secrets_to_write.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        if os.name != "nt":
            path.chmod(0o600)
    return config_path
