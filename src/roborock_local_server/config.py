"""Configuration loader for the release stack."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib


@dataclass(frozen=True)
class NetworkConfig:
    stack_fqdn: str
    bind_host: str
    https_port: int
    mqtt_tls_port: int
    region: str
    localkey: str
    duid: str
    mqtt_username: str
    mqtt_password: str
    mqtt_client_id: str


@dataclass(frozen=True)
class BrokerConfig:
    mode: str
    host: str
    port: int
    mosquitto_binary: str
    enable_topic_bridge: bool


@dataclass(frozen=True)
class StorageConfig:
    data_dir: str


@dataclass(frozen=True)
class TlsConfig:
    mode: str
    base_domain: str
    email: str
    cloudflare_token_file: str
    renew_days_before: int
    renew_check_seconds: int
    acme_server: str
    cert_file: str
    key_file: str


@dataclass(frozen=True)
class AdminConfig:
    password_hash: str
    session_secret: str
    session_ttl_seconds: int


@dataclass(frozen=True)
class AppConfig:
    network: NetworkConfig
    broker: BrokerConfig
    storage: StorageConfig
    tls: TlsConfig
    admin: AdminConfig


@dataclass(frozen=True)
class AppPaths:
    config_file: Path
    data_dir: Path
    runtime_dir: Path
    state_dir: Path
    certs_dir: Path
    acme_dir: Path
    inventory_path: Path
    cloud_snapshot_path: Path
    protocol_auth_sessions_path: Path
    runtime_credentials_path: Path
    device_key_state_path: Path
    http_jsonl_path: Path
    mqtt_jsonl_path: Path
    cloudflare_token_file: Path
    cert_file: Path
    key_file: Path


def _get_section(parsed: dict[str, object], key: str) -> dict[str, object]:
    section = parsed.get(key)
    return section if isinstance(section, dict) else {}


def _require_non_empty(value: object, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field_name} is required")
    return text


def _as_int(value: object, field_name: str, default: int) -> int:
    if value in (None, ""):
        return default
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc


def _as_bool(value: object, default: bool) -> bool:
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


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path).resolve()
    parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))

    network = _get_section(parsed, "network")
    broker = _get_section(parsed, "broker")
    storage = _get_section(parsed, "storage")
    tls = _get_section(parsed, "tls")
    admin = _get_section(parsed, "admin")
    broker_mode = str(broker.get("mode", "embedded")).strip().lower()
    if broker_mode not in {"embedded", "external"}:
        raise ValueError("broker.mode must be 'embedded' or 'external'")

    tls_mode = str(tls.get("mode", "cloudflare_acme")).strip().lower()
    if tls_mode not in {"cloudflare_acme", "provided"}:
        raise ValueError("tls.mode must be 'cloudflare_acme' or 'provided'")

    raw_broker_host = broker.get("host")
    broker_host = str(raw_broker_host).strip() if raw_broker_host is not None else "127.0.0.1"
    if broker_mode == "embedded" and not broker_host:
        broker_host = "127.0.0.1"
    broker_port_default = 18830 if broker_mode == "embedded" else 1883

    config = AppConfig(
        network=NetworkConfig(
            stack_fqdn=_require_non_empty(network.get("stack_fqdn"), "network.stack_fqdn"),
            bind_host=str(network.get("bind_host", "0.0.0.0")).strip() or "0.0.0.0",
            https_port=_as_int(network.get("https_port"), "network.https_port", 443),
            mqtt_tls_port=_as_int(network.get("mqtt_tls_port"), "network.mqtt_tls_port", 8883),
            region=str(network.get("region", "us")).strip().lower() or "us",
            localkey=str(network.get("localkey", "")).strip(),
            duid=str(network.get("duid", "")).strip(),
            mqtt_username=str(network.get("mqtt_username", "")).strip(),
            mqtt_password=str(network.get("mqtt_password", "")).strip(),
            mqtt_client_id=str(network.get("mqtt_client_id", "")).strip(),
        ),
        broker=BrokerConfig(
            mode=broker_mode,
            host=broker_host,
            port=_as_int(broker.get("port"), "broker.port", broker_port_default),
            mosquitto_binary=str(broker.get("mosquitto_binary", "mosquitto")).strip() or "mosquitto",
            enable_topic_bridge=_as_bool(broker.get("enable_topic_bridge"), True),
        ),
        storage=StorageConfig(
            data_dir=str(storage.get("data_dir", "/data")).strip() or "/data",
        ),
        tls=TlsConfig(
            mode=tls_mode,
            base_domain=str(tls.get("base_domain", "")).strip(),
            email=str(tls.get("email", "")).strip(),
            cloudflare_token_file=str(tls.get("cloudflare_token_file", "")).strip(),
            renew_days_before=_as_int(tls.get("renew_days_before"), "tls.renew_days_before", 30),
            renew_check_seconds=_as_int(tls.get("renew_check_seconds"), "tls.renew_check_seconds", 43200),
            acme_server=str(tls.get("acme_server", "zerossl")).strip() or "zerossl",
            cert_file=str(tls.get("cert_file", "")).strip(),
            key_file=str(tls.get("key_file", "")).strip(),
        ),
        admin=AdminConfig(
            password_hash=_require_non_empty(admin.get("password_hash"), "admin.password_hash"),
            session_secret=_require_non_empty(admin.get("session_secret"), "admin.session_secret"),
            session_ttl_seconds=_as_int(admin.get("session_ttl_seconds"), "admin.session_ttl_seconds", 86400),
        ),
    )

    if len(config.admin.session_secret) < 24:
        raise ValueError("admin.session_secret must be at least 24 characters")

    if config.broker.mode == "external":
        _require_non_empty(config.broker.host, "broker.host")

    if config.tls.mode == "cloudflare_acme":
        _require_non_empty(config.tls.base_domain, "tls.base_domain")
        _require_non_empty(config.tls.email, "tls.email")
        _require_non_empty(config.tls.cloudflare_token_file, "tls.cloudflare_token_file")
    else:
        _require_non_empty(config.tls.cert_file, "tls.cert_file")
        _require_non_empty(config.tls.key_file, "tls.key_file")
    return config


def resolve_paths(config_file: str | Path, config: AppConfig) -> AppPaths:
    config_path = Path(config_file).resolve()
    config_root = config_path.parent
    data_dir = Path(config.storage.data_dir)
    if not data_dir.is_absolute():
        data_dir = (config_root / data_dir).resolve()

    runtime_dir = data_dir / "runtime"
    state_dir = data_dir / "state"
    certs_dir = data_dir / "certs"
    acme_dir = data_dir / "acme"

    cert_file = Path(config.tls.cert_file) if config.tls.cert_file else certs_dir / "fullchain.pem"
    key_file = Path(config.tls.key_file) if config.tls.key_file else certs_dir / "privkey.pem"
    if not cert_file.is_absolute():
        cert_file = (config_root / cert_file).resolve()
    if not key_file.is_absolute():
        key_file = (config_root / key_file).resolve()

    cloudflare_token_file = Path(config.tls.cloudflare_token_file or state_dir / "cloudflare_token")
    if not cloudflare_token_file.is_absolute():
        cloudflare_token_file = (config_root / cloudflare_token_file).resolve()

    return AppPaths(
        config_file=config_path,
        data_dir=data_dir,
        runtime_dir=runtime_dir,
        state_dir=state_dir,
        certs_dir=certs_dir,
        acme_dir=acme_dir,
        inventory_path=runtime_dir / "web_api_inventory.json",
        cloud_snapshot_path=runtime_dir / "web_api_inventory_full_snapshot.json",
        protocol_auth_sessions_path=state_dir / "protocol_auth_sessions.json",
        runtime_credentials_path=runtime_dir / "runtime_credentials.json",
        device_key_state_path=state_dir / "device_key_state.json",
        http_jsonl_path=runtime_dir / "decompiled_http.jsonl",
        mqtt_jsonl_path=runtime_dir / "decompiled_mqtt.jsonl",
        cloudflare_token_file=cloudflare_token_file,
        cert_file=cert_file,
        key_file=key_file,
    )
