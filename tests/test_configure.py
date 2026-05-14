from pathlib import Path

import pytest

import roborock_local_server.configure as configure_module
from roborock_local_server.config import load_config
from roborock_local_server.configure import ConfigureAnswers, _validate_protocol_login_pin, collect_configure_answers, write_config_setup


def _answers(
    *,
    https_port: int = 555,
    mqtt_tls_port: int = 8881,
    broker_mode: str = "embedded",
    tls_mode: str = "cloudflare_acme",
    acme_server: str = "zerossl",
    acme_eab_kid: str = "",
    acme_eab_hmac_key: str = "",
) -> ConfigureAnswers:
    return ConfigureAnswers(
        stack_fqdn="api-roborock.example.com",
        https_port=https_port,
        mqtt_tls_port=mqtt_tls_port,
        broker_mode=broker_mode,
        tls_mode=tls_mode,
        base_domain="example.com" if tls_mode == "cloudflare_acme" else "",
        email="you@example.com" if tls_mode == "cloudflare_acme" else "",
        acme_server=acme_server,
        acme_eab_kid=acme_eab_kid,
        acme_eab_hmac_key=acme_eab_hmac_key,
        cloudflare_token="cloudflare-token" if tls_mode == "cloudflare_acme" else "",
        password_hash="pbkdf2_sha256$600000$abc$def",
        session_secret="abcdefghijklmnopqrstuvwxyz123456",
        protocol_login_email="user@example.com",
        protocol_login_pin_hash="pbkdf2_sha256$600000$ghi$jkl",
    )


def test_write_config_setup_embedded_cloudflare(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"

    result = write_config_setup(config_file=config_file, answers=_answers())

    assert result.config_file == config_file.resolve()
    assert result.cloudflare_token_file == (tmp_path / "secrets" / "cloudflare_token").resolve()
    assert result.cloudflare_token_file.read_text(encoding="utf-8") == "cloudflare-token"
    assert result.actalis_eab_kid_file is None
    assert result.actalis_eab_hmac_key_file is None
    assert not result.broker_template_needs_edit

    config = load_config(result.config_file)
    assert config.network.stack_fqdn == "api-roborock.example.com"
    assert config.network.https_port == 555
    assert config.network.mqtt_tls_port == 8881
    assert config.broker.mode == "embedded"
    assert config.broker.host == "127.0.0.1"
    assert config.broker.port == 18830
    assert config.tls.mode == "cloudflare_acme"
    assert config.tls.cloudflare_token_file == "/run/secrets/cloudflare_token"
    assert config.tls.acme_server == "zerossl"
    assert config.admin.protocol_auth_enabled is True
    assert config.admin.protocol_login_email == "user@example.com"


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
    assert 'protocol_login_email = "user@example.com"' in rendered

    with pytest.raises(ValueError, match="broker.host is required"):
        load_config(config_file)


def test_write_config_setup_refuses_overwrite_without_force(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    write_config_setup(config_file=config_file, answers=_answers())

    with pytest.raises(FileExistsError, match="Refusing to overwrite existing file"):
        write_config_setup(config_file=config_file, answers=_answers())


def test_write_config_setup_persists_custom_ports(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"

    result = write_config_setup(
        config_file=config_file,
        answers=_answers(https_port=8443, mqtt_tls_port=9443),
    )

    config = load_config(result.config_file)
    assert config.network.https_port == 8443
    assert config.network.mqtt_tls_port == 9443


def test_validate_protocol_login_pin_requires_exactly_six_digits() -> None:
    assert _validate_protocol_login_pin("123456") == "123456"

    with pytest.raises(ValueError, match="exactly 6 digits"):
        _validate_protocol_login_pin("12345")

    with pytest.raises(ValueError, match="exactly 6 digits"):
        _validate_protocol_login_pin("12345a")


def test_write_config_setup_embedded_actalis(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"

    result = write_config_setup(
        config_file=config_file,
        answers=_answers(acme_server="actalis", acme_eab_kid="kid-123", acme_eab_hmac_key="hmac-456"),
    )

    config = load_config(result.config_file)
    assert config.tls.acme_server == "actalis"
    assert config.tls.acme_eab_kid == ""
    assert config.tls.acme_eab_hmac_key == ""
    assert config.tls.acme_eab_kid_file == "/run/secrets/acme_eab_kid"
    assert config.tls.acme_eab_hmac_key_file == "/run/secrets/acme_eab_hmac_key"
    assert result.actalis_eab_kid_file == (tmp_path / "secrets" / "acme_eab_kid").resolve()
    assert result.actalis_eab_hmac_key_file == (tmp_path / "secrets" / "acme_eab_hmac_key").resolve()
    assert result.actalis_eab_kid_file.read_text(encoding="utf-8") == "kid-123"
    assert result.actalis_eab_hmac_key_file.read_text(encoding="utf-8") == "hmac-456"


def test_write_config_setup_rejects_blank_actalis_credentials(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"

    with pytest.raises(ValueError, match="Actalis requires both"):
        write_config_setup(
            config_file=config_file,
            answers=_answers(acme_server="actalis"),
        )


def test_collect_configure_answers_hides_actalis_hmac_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    prompts: list[str] = []
    input_values = iter(
        [
            "api-roborock.example.com",
            "",
            "",
            "",
            "",
            "example.com",
            "acme@example.com",
            "y",
            "kid-123",
            "user@example.com",
        ]
    )
    secret_values = iter(
        [
            "hmac-456",
            "cloudflare-token",
            "admin-password",
            "123456",
            "123456",
        ]
    )

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return next(input_values)

    def fake_getpass(prompt: str) -> str:
        prompts.append(prompt)
        return next(secret_values)

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(configure_module, "getpass", fake_getpass)

    answers = collect_configure_answers()

    assert answers.acme_server == "actalis"
    assert answers.acme_eab_kid == "kid-123"
    assert answers.acme_eab_hmac_key == "hmac-456"
    assert "Actalis EAB HMAC key (input hidden): " in prompts
