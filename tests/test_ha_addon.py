from __future__ import annotations

import json
from pathlib import Path
import tomllib

import pytest

from roborock_local_server.ha_addon import write_config_from_home_assistant_options


def _write_options(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_write_config_from_home_assistant_options_provided_tls(tmp_path: Path) -> None:
    options_path = tmp_path / "options.json"
    config_path = tmp_path / "config.toml"
    token_path = tmp_path / "cloudflare_token"

    _write_options(
        options_path,
        {
            "stack_fqdn": "https://api-roborock.example.com",
            "listener_mode": "local_tls",
            "https_port": 8443,
            "mqtt_tls_port": 9443,
            "listen_https_port": 8080,
            "listen_mqtt_port": 18883,
            "region": "us",
            "use_external_broker": True,
            "broker_host": "mqtt.internal",
            "broker_port": 1883,
            "enable_topic_bridge": False,
            "tls_mode": "provided",
            "cert_file": "/ssl/fullchain.pem",
            "key_file": "/ssl/privkey.pem",
            "admin_password": "super-secret-password",
            "admin_session_secret": "a" * 32,
            "protocol_auth_enabled": True,
            "protocol_login_email": "user@example.com",
            "protocol_login_pin": "123456",
        },
    )

    write_config_from_home_assistant_options(
        options_path=options_path,
        config_path=config_path,
        cloudflare_token_path=token_path,
    )

    parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    assert parsed["network"]["stack_fqdn"] == "api-roborock.example.com"
    assert parsed["network"]["listener_mode"] == "local_tls"
    assert parsed["network"]["https_port"] == 8443
    assert parsed["network"]["mqtt_tls_port"] == 9443
    assert parsed["network"]["listen_https_port"] == 8080
    assert parsed["network"]["listen_mqtt_port"] == 18883
    assert parsed["broker"]["mode"] == "external"
    assert parsed["broker"]["host"] == "mqtt.internal"
    assert parsed["broker"]["enable_topic_bridge"] is False
    assert parsed["tls"]["mode"] == "provided"
    assert parsed["tls"]["cert_file"] == "/ssl/fullchain.pem"
    assert parsed["tls"]["key_file"] == "/ssl/privkey.pem"
    assert parsed["admin"]["protocol_login_email"] == "user@example.com"
    assert str(parsed["admin"]["password_hash"]).startswith("pbkdf2_sha256$")
    assert str(parsed["admin"]["protocol_login_pin_hash"]).startswith("pbkdf2_sha256$")
    assert token_path.exists() is False


def test_write_config_from_home_assistant_options_cloudflare(tmp_path: Path) -> None:
    options_path = tmp_path / "options.json"
    config_path = tmp_path / "config.toml"
    token_path = tmp_path / "run" / "secrets" / "cloudflare_token"

    _write_options(
        options_path,
        {
            "stack_fqdn": "api-roborock.example.com",
            "tls_mode": "cloudflare_acme",
            "tls_base_domain": "example.com",
            "tls_email": "acme@example.com",
            "cloudflare_token": "cloudflare-token-123",
            "admin_password": "secret",
            "protocol_login_email": "user@example.com",
            "protocol_login_pin": "654321",
        },
    )

    write_config_from_home_assistant_options(
        options_path=options_path,
        config_path=config_path,
        cloudflare_token_path=token_path,
    )

    parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    assert parsed["tls"]["mode"] == "cloudflare_acme"
    assert parsed["tls"]["base_domain"] == "example.com"
    assert parsed["tls"]["email"] == "acme@example.com"
    assert parsed["tls"]["cloudflare_token_file"] == str(token_path)
    assert token_path.read_text(encoding="utf-8") == "cloudflare-token-123"


def test_write_config_from_home_assistant_options_external_tls_does_not_require_certs(tmp_path: Path) -> None:
    options_path = tmp_path / "options.json"
    config_path = tmp_path / "config.toml"

    _write_options(
        options_path,
        {
            "stack_fqdn": "api-roborock.example.com",
            "listener_mode": "external_tls",
            "https_port": 443,
            "mqtt_tls_port": 8883,
            "listen_https_port": 8080,
            "listen_mqtt_port": 18883,
            "admin_password": "secret",
            "protocol_login_email": "user@example.com",
            "protocol_login_pin": "654321",
        },
    )

    write_config_from_home_assistant_options(
        options_path=options_path,
        config_path=config_path,
    )

    parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    assert parsed["network"]["listener_mode"] == "external_tls"
    assert parsed["network"]["listen_https_port"] == 8080
    assert parsed["network"]["listen_mqtt_port"] == 18883


def test_write_config_from_home_assistant_options_requires_admin_password(tmp_path: Path) -> None:
    options_path = tmp_path / "options.json"
    config_path = tmp_path / "config.toml"

    _write_options(
        options_path,
        {
            "stack_fqdn": "api-roborock.example.com",
            "protocol_login_email": "user@example.com",
            "protocol_login_pin": "123456",
        },
    )

    with pytest.raises(ValueError, match="admin_password is required"):
        write_config_from_home_assistant_options(
            options_path=options_path,
            config_path=config_path,
        )


def test_write_config_from_home_assistant_options_requires_api_prefix(tmp_path: Path) -> None:
    options_path = tmp_path / "options.json"
    config_path = tmp_path / "config.toml"

    _write_options(
        options_path,
        {
            "stack_fqdn": "lashleyhomeassist.duckdns.org",
            "admin_password": "super-secret-password",
            "protocol_login_email": "user@example.com",
            "protocol_login_pin": "123456",
        },
    )

    with pytest.raises(ValueError, match="stack_fqdn must start with api-"):
        write_config_from_home_assistant_options(
            options_path=options_path,
            config_path=config_path,
        )
