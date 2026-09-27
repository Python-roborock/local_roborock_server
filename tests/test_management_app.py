from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from roborock_local_server.config import load_config
from roborock_local_server.management_app import (
    DEFAULT_BOOTSTRAP_HTTPS_PORT,
    bootstrap_port_from_env,
    create_management_app,
)

_VALID_PAYLOAD = {
    "stack_fqdn": "api-roborock.example.com",
    "https_port": 555,
    "mqtt_tls_port": 8881,
    "broker_mode": "embedded",
    "tls_mode": "provided",
    "admin_password": "super-secret-password",
    "protocol_login_email": "user@example.com",
    "protocol_login_pin": "123456",
}


def test_bootstrap_port_from_env_default() -> None:
    assert bootstrap_port_from_env({}) == DEFAULT_BOOTSTRAP_HTTPS_PORT


def test_bootstrap_port_from_env_reuses_https_port_var() -> None:
    assert bootstrap_port_from_env({"ROBOROCK_SERVER_HTTPS_PORT": "9090"}) == 9090


def test_bootstrap_port_from_env_rejects_bad_value() -> None:
    with pytest.raises(ValueError, match="must be an integer"):
        bootstrap_port_from_env({"ROBOROCK_SERVER_HTTPS_PORT": "not-a-port"})


def test_index_serves_setup_wizard_when_unconfigured(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    client = TestClient(create_management_app(config_file=config_file))

    response = client.get("/")

    assert response.status_code == 200
    assert "Roborock Local Server Setup" in response.text


def test_index_serves_status_page_when_configured(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text("already = true\n", encoding="utf-8")
    client = TestClient(create_management_app(config_file=config_file))

    response = client.get("/")

    assert response.status_code == 200
    assert "Setup is complete" in response.text


def test_setup_status_reflects_config_existence(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    client = TestClient(create_management_app(config_file=config_file))

    assert client.get("/admin/api/setup/status").json() == {"configured": False}

    config_file.write_text("done = true\n", encoding="utf-8")
    assert client.get("/admin/api/setup/status").json() == {"configured": True}


def test_submit_setup_writes_bootable_config(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    calls: list[str] = []
    client = TestClient(create_management_app(config_file=config_file, on_configured=lambda: calls.append("done")))

    response = client.post("/admin/api/setup", json=_VALID_PAYLOAD)

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert calls == ["done"]

    config = load_config(config_file)
    assert config.network.stack_fqdn == "api-roborock.example.com"
    assert config.admin.protocol_login_email == "user@example.com"


def test_submit_setup_with_external_broker_needs_no_manual_edit(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    client = TestClient(create_management_app(config_file=config_file))
    payload = dict(_VALID_PAYLOAD, broker_mode="external", broker_host="mqtt.internal")

    response = client.post("/admin/api/setup", json=payload)

    assert response.status_code == 200
    config = load_config(config_file)
    assert config.broker.mode == "external"
    assert config.broker.host == "mqtt.internal"


def test_submit_setup_rejects_missing_external_broker_host(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    client = TestClient(create_management_app(config_file=config_file))
    payload = dict(_VALID_PAYLOAD, broker_mode="external")

    response = client.post("/admin/api/setup", json=payload)

    assert response.status_code == 400
    assert "broker_host" in response.json()["error"]
    assert config_file.exists() is False


def test_submit_setup_rejects_bad_stack_fqdn(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    client = TestClient(create_management_app(config_file=config_file))
    payload = dict(_VALID_PAYLOAD, stack_fqdn="roborock.example.com")

    response = client.post("/admin/api/setup", json=payload)

    assert response.status_code == 400
    assert "must start with api-" in response.json()["error"]


def test_submit_setup_refuses_to_overwrite_existing_config(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text("existing = true\n", encoding="utf-8")
    client = TestClient(create_management_app(config_file=config_file))

    response = client.post("/admin/api/setup", json=_VALID_PAYLOAD)

    assert response.status_code == 409
    assert config_file.read_text(encoding="utf-8") == "existing = true\n"


def test_submit_setup_cloudflare_actalis_requires_eab(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    client = TestClient(create_management_app(config_file=config_file))
    payload = dict(
        _VALID_PAYLOAD,
        tls_mode="cloudflare_acme",
        base_domain="example.com",
        email="acme@example.com",
        cloudflare_token="cf-token",
        acme_server="actalis",
    )

    response = client.post("/admin/api/setup", json=payload)

    assert response.status_code == 400
    assert "Actalis" in response.json()["error"]
