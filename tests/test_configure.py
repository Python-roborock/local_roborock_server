from pathlib import Path

import pytest

from roborock_local_server.config import load_config
from roborock_local_server.configure import ConfigureAnswers, write_config_setup


def _answers(
    *,
    broker_mode: str = "embedded",
    tls_mode: str = "cloudflare_acme",
) -> ConfigureAnswers:
    return ConfigureAnswers(
        stack_fqdn="roborock.example.com",
        broker_mode=broker_mode,
        tls_mode=tls_mode,
        base_domain="example.com" if tls_mode == "cloudflare_acme" else "",
        email="you@example.com" if tls_mode == "cloudflare_acme" else "",
        cloudflare_token="cloudflare-token" if tls_mode == "cloudflare_acme" else "",
        password_hash="pbkdf2_sha256$600000$abc$def",
        session_secret="abcdefghijklmnopqrstuvwxyz123456",
    )


def test_write_config_setup_embedded_cloudflare(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"

    result = write_config_setup(config_file=config_file, answers=_answers())

    assert result.config_file == config_file.resolve()
    assert result.cloudflare_token_file == (tmp_path / "secrets" / "cloudflare_token").resolve()
    assert result.cloudflare_token_file.read_text(encoding="utf-8") == "cloudflare-token"
    assert not result.broker_template_needs_edit

    config = load_config(result.config_file)
    assert config.network.stack_fqdn == "roborock.example.com"
    assert config.broker.mode == "embedded"
    assert config.broker.host == "127.0.0.1"
    assert config.broker.port == 18830
    assert config.tls.mode == "cloudflare_acme"
    assert config.tls.cloudflare_token_file == "/run/secrets/cloudflare_token"
    assert config.admin.protocol_auth_enabled is True


def test_write_config_setup_external_broker_requires_host_before_serve(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"

    result = write_config_setup(
        config_file=config_file,
        answers=_answers(broker_mode="external", tls_mode="provided"),
    )

    assert result.cloudflare_token_file is None
    assert result.broker_template_needs_edit
    rendered = config_file.read_text(encoding="utf-8")
    assert 'mode = "external"' in rendered
    assert 'host = ""' in rendered
    assert "port = 1883" in rendered
    assert "protocol_auth_enabled = true" in rendered

    with pytest.raises(ValueError, match="broker.host is required"):
        load_config(config_file)


def test_write_config_setup_refuses_overwrite_without_force(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    write_config_setup(config_file=config_file, answers=_answers())

    with pytest.raises(FileExistsError, match="Refusing to overwrite existing file"):
        write_config_setup(config_file=config_file, answers=_answers())
