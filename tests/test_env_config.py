from __future__ import annotations

from pathlib import Path
import tomllib

import pytest

from roborock_local_server.env_config import SecretPaths, has_env_config, write_config_from_env

_BASE_ENV = {
    "ROBOROCK_SERVER_STACK_FQDN": "api-roborock.example.com",
    "ROBOROCK_SERVER_TLS_MODE": "provided",
    "ROBOROCK_SERVER_CERT_FILE": "/ssl/fullchain.pem",
    "ROBOROCK_SERVER_KEY_FILE": "/ssl/privkey.pem",
    "ROBOROCK_SERVER_ADMIN_PASSWORD": "super-secret-password",
    "ROBOROCK_SERVER_PROTOCOL_LOGIN_EMAIL": "user@example.com",
    "ROBOROCK_SERVER_PROTOCOL_LOGIN_PIN": "123456",
}


def test_has_env_config_requires_stack_fqdn() -> None:
    assert has_env_config({}) is False
    assert has_env_config({"ROBOROCK_SERVER_STACK_FQDN": "api-roborock.example.com"}) is True


def test_write_config_from_env_provided_tls(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"

    write_config_from_env(_BASE_ENV, config_path=config_path)

    parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    assert parsed["network"]["stack_fqdn"] == "api-roborock.example.com"
    assert parsed["network"]["listener_mode"] == "local_tls"
    assert parsed["network"]["https_port"] == 555
    assert parsed["network"]["mqtt_tls_port"] == 8881
    assert parsed["network"]["advertised_https_port"] == 555
    assert parsed["network"]["advertised_mqtt_tls_port"] == 8881
    assert parsed["network"]["trusted_proxies"] == ["127.0.0.1", "::1"]
    assert parsed["broker"]["mode"] == "embedded"
    assert parsed["broker"]["host"] == "127.0.0.1"
    assert parsed["broker"]["port"] == 18830
    assert parsed["tls"]["mode"] == "provided"
    assert parsed["tls"]["cert_file"] == "/ssl/fullchain.pem"
    assert parsed["tls"]["key_file"] == "/ssl/privkey.pem"
    assert parsed["admin"]["protocol_auth_enabled"] is True
    assert parsed["admin"]["new_connections_enabled"] is True
    assert parsed["admin"]["protocol_login_email"] == "user@example.com"
    assert len(str(parsed["admin"]["session_secret"])) >= 24
    assert str(parsed["admin"]["password_hash"]).startswith("pbkdf2_sha256$")
    assert str(parsed["admin"]["protocol_login_pin_hash"]).startswith("pbkdf2_sha256$")


def test_write_config_from_env_reverse_proxy_ports(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    env = dict(_BASE_ENV)
    env["ROBOROCK_SERVER_ADVERTISED_HTTPS_PORT"] = "443"
    env["ROBOROCK_SERVER_ADVERTISED_MQTT_TLS_PORT"] = "8883"

    write_config_from_env(env, config_path=config_path)

    parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    assert parsed["network"]["https_port"] == 555
    assert parsed["network"]["advertised_https_port"] == 443
    assert parsed["network"]["advertised_mqtt_tls_port"] == 8883


def test_write_config_from_env_external_tls_requires_provided(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    env = dict(_BASE_ENV)
    env["ROBOROCK_SERVER_LISTENER_MODE"] = "external_tls"
    env["ROBOROCK_SERVER_TLS_MODE"] = "cloudflare_acme"
    del env["ROBOROCK_SERVER_CERT_FILE"]
    del env["ROBOROCK_SERVER_KEY_FILE"]

    with pytest.raises(ValueError, match="external_tls"):
        write_config_from_env(env, config_path=config_path)


def test_write_config_from_env_external_broker_requires_host(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    env = dict(_BASE_ENV)
    env["ROBOROCK_SERVER_BROKER_MODE"] = "external"

    with pytest.raises(ValueError, match="BROKER_HOST"):
        write_config_from_env(env, config_path=config_path)


def test_write_config_from_env_external_broker(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    env = dict(_BASE_ENV)
    env["ROBOROCK_SERVER_BROKER_MODE"] = "external"
    env["ROBOROCK_SERVER_BROKER_HOST"] = "mqtt.internal"

    write_config_from_env(env, config_path=config_path)

    parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    assert parsed["broker"]["mode"] == "external"
    assert parsed["broker"]["host"] == "mqtt.internal"
    assert parsed["broker"]["port"] == 1883


def test_write_config_from_env_cloudflare_writes_secret(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    token_path = tmp_path / "run" / "secrets" / "cloudflare_token"
    env = dict(_BASE_ENV)
    env["ROBOROCK_SERVER_TLS_MODE"] = "cloudflare_acme"
    env["ROBOROCK_SERVER_TLS_BASE_DOMAIN"] = "example.com"
    env["ROBOROCK_SERVER_TLS_EMAIL"] = "acme@example.com"
    env["ROBOROCK_SERVER_CLOUDFLARE_TOKEN"] = "cloudflare-token-123"
    del env["ROBOROCK_SERVER_CERT_FILE"]
    del env["ROBOROCK_SERVER_KEY_FILE"]

    write_config_from_env(
        env,
        config_path=config_path,
        secret_paths=SecretPaths(cloudflare_token_file=token_path),
    )

    parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    assert parsed["tls"]["mode"] == "cloudflare_acme"
    assert parsed["tls"]["base_domain"] == "example.com"
    assert parsed["tls"]["cloudflare_token_file"] == str(token_path)
    assert token_path.read_text(encoding="utf-8") == "cloudflare-token-123"


def test_write_config_from_env_cloudflare_token_file_override_skips_write(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    existing_token_path = tmp_path / "existing-token"
    env = dict(_BASE_ENV)
    env["ROBOROCK_SERVER_TLS_MODE"] = "cloudflare_acme"
    env["ROBOROCK_SERVER_TLS_BASE_DOMAIN"] = "example.com"
    env["ROBOROCK_SERVER_TLS_EMAIL"] = "acme@example.com"
    env["ROBOROCK_SERVER_CLOUDFLARE_TOKEN_FILE"] = str(existing_token_path)
    del env["ROBOROCK_SERVER_CERT_FILE"]
    del env["ROBOROCK_SERVER_KEY_FILE"]

    write_config_from_env(env, config_path=config_path)

    parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    assert parsed["tls"]["cloudflare_token_file"] == str(existing_token_path)
    assert existing_token_path.exists() is False


def test_write_config_from_env_actalis_requires_eab(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    env = dict(_BASE_ENV)
    env["ROBOROCK_SERVER_TLS_MODE"] = "cloudflare_acme"
    env["ROBOROCK_SERVER_TLS_BASE_DOMAIN"] = "example.com"
    env["ROBOROCK_SERVER_TLS_EMAIL"] = "acme@example.com"
    env["ROBOROCK_SERVER_ACME_SERVER"] = "actalis"
    env["ROBOROCK_SERVER_CLOUDFLARE_TOKEN"] = "cloudflare-token-123"
    del env["ROBOROCK_SERVER_CERT_FILE"]
    del env["ROBOROCK_SERVER_KEY_FILE"]

    with pytest.raises(ValueError, match="ACME_EAB_KID"):
        write_config_from_env(env, config_path=config_path)


def test_write_config_from_env_actalis_writes_eab(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    token_path = tmp_path / "cloudflare_token"
    kid_path = tmp_path / "acme_eab_kid"
    hmac_path = tmp_path / "acme_eab_hmac_key"
    env = dict(_BASE_ENV)
    env["ROBOROCK_SERVER_TLS_MODE"] = "cloudflare_acme"
    env["ROBOROCK_SERVER_TLS_BASE_DOMAIN"] = "example.com"
    env["ROBOROCK_SERVER_TLS_EMAIL"] = "acme@example.com"
    env["ROBOROCK_SERVER_ACME_SERVER"] = "actalis"
    env["ROBOROCK_SERVER_ACME_EAB_KID"] = "kid-123"
    env["ROBOROCK_SERVER_ACME_EAB_HMAC_KEY"] = "hmac-456"
    env["ROBOROCK_SERVER_CLOUDFLARE_TOKEN"] = "cloudflare-token-123"
    del env["ROBOROCK_SERVER_CERT_FILE"]
    del env["ROBOROCK_SERVER_KEY_FILE"]

    write_config_from_env(
        env,
        config_path=config_path,
        secret_paths=SecretPaths(
            cloudflare_token_file=token_path,
            acme_eab_kid_file=kid_path,
            acme_eab_hmac_key_file=hmac_path,
        ),
    )

    parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    assert parsed["tls"]["acme_server"] == "actalis"
    assert parsed["tls"]["acme_eab_kid_file"] == str(kid_path)
    assert parsed["tls"]["acme_eab_hmac_key_file"] == str(hmac_path)
    assert kid_path.read_text(encoding="utf-8") == "kid-123"
    assert hmac_path.read_text(encoding="utf-8") == "hmac-456"


def test_write_config_from_env_rejects_partial_admin_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    env = dict(_BASE_ENV)
    del env["ROBOROCK_SERVER_ADMIN_PASSWORD"]

    with pytest.raises(ValueError, match="Set all of .*ADMIN_PASSWORD.*or none of them"):
        write_config_from_env(env, config_path=config_path)


def test_write_config_from_env_omits_admin_section_when_all_admin_fields_absent(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    env = dict(_BASE_ENV)
    del env["ROBOROCK_SERVER_ADMIN_PASSWORD"]
    del env["ROBOROCK_SERVER_PROTOCOL_LOGIN_EMAIL"]
    del env["ROBOROCK_SERVER_PROTOCOL_LOGIN_PIN"]

    write_config_from_env(env, config_path=config_path)

    parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    assert "admin" not in parsed
    # Network/broker/storage/tls are still fully written - the Setup Wizard
    # only needs to fill in [admin] on top of this.
    assert parsed["network"]["stack_fqdn"] == "api-roborock.example.com"
    assert parsed["tls"]["mode"] == "provided"


def test_write_config_from_env_writes_admin_section_when_all_admin_fields_present(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"

    write_config_from_env(_BASE_ENV, config_path=config_path)

    parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    assert parsed["admin"]["protocol_login_email"] == "user@example.com"


def test_write_config_from_env_requires_api_prefix(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    env = dict(_BASE_ENV)
    env["ROBOROCK_SERVER_STACK_FQDN"] = "roborock.example.com"

    with pytest.raises(ValueError, match="STACK_FQDN must start with api-"):
        write_config_from_env(env, config_path=config_path)


def test_write_config_from_env_rejects_bad_pin(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    env = dict(_BASE_ENV)
    env["ROBOROCK_SERVER_PROTOCOL_LOGIN_PIN"] = "12"

    with pytest.raises(ValueError, match="PROTOCOL_LOGIN_PIN must be exactly 6 digits"):
        write_config_from_env(env, config_path=config_path)


def test_write_config_from_env_reuses_existing_session_secret(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"

    write_config_from_env(_BASE_ENV, config_path=config_path)
    first_secret = tomllib.loads(config_path.read_text(encoding="utf-8"))["admin"]["session_secret"]

    write_config_from_env(_BASE_ENV, config_path=config_path)
    second_secret = tomllib.loads(config_path.read_text(encoding="utf-8"))["admin"]["session_secret"]

    assert len(str(first_secret)) >= 24
    assert second_secret == first_secret


def test_write_config_from_env_trusted_proxies(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    env = dict(_BASE_ENV)
    env["ROBOROCK_SERVER_TRUSTED_PROXIES"] = "10.0.0.0/8, 192.168.1.5"

    write_config_from_env(env, config_path=config_path)

    parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    assert parsed["network"]["trusted_proxies"] == ["10.0.0.0/8", "192.168.1.5"]


def test_write_config_from_env_rejects_invalid_trusted_proxy(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    env = dict(_BASE_ENV)
    env["ROBOROCK_SERVER_TRUSTED_PROXIES"] = "not-an-ip"

    with pytest.raises(ValueError, match="not a valid IP address"):
        write_config_from_env(env, config_path=config_path)
