from pathlib import Path
import logging
import subprocess

import pytest
from roborock_local_server.certs import CertificateManager
from roborock_local_server.config import load_config, resolve_paths


def test_certificate_manager_passes_actalis_eab_to_register_account(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[network]
stack_fqdn = "api-roborock.example.com"

[broker]
mode = "embedded"

[storage]
data_dir = "data"

[tls]
mode = "cloudflare_acme"
base_domain = "example.com"
email = "acme@example.com"
cloudflare_token_file = "secrets/cloudflare_token"
acme_server = "actalis"
acme_eab_kid_file = "secrets/acme_eab_kid"
acme_eab_hmac_key_file = "secrets/acme_eab_hmac_key"

[admin]
password_hash = "pbkdf2_sha256$600000$abc$def"
session_secret = "abcdefghijklmnopqrstuvwxyz123456"
protocol_login_email = "user@example.com"
protocol_login_pin_hash = "pbkdf2_sha256$600000$ghi$jkl"
        """.strip(),
        encoding="utf-8",
    )
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    paths.cloudflare_token_file.parent.mkdir(parents=True, exist_ok=True)
    paths.cloudflare_token_file.write_text("cloudflare-token", encoding="utf-8")
    paths.acme_eab_kid_file.parent.mkdir(parents=True, exist_ok=True)
    paths.acme_eab_kid_file.write_text("kid-123", encoding="utf-8")
    paths.acme_eab_hmac_key_file.write_text("hmac-456", encoding="utf-8")
    manager = CertificateManager(config=config, paths=paths)
    calls: list[list[str]] = []

    def fake_run_acme(args: list[str]) -> None:
        calls.append(list(args))
        if "--install-cert" in args:
            paths.cert_file.parent.mkdir(parents=True, exist_ok=True)
            paths.key_file.parent.mkdir(parents=True, exist_ok=True)
            paths.cert_file.write_text("cert", encoding="utf-8")
            paths.key_file.write_text("key", encoding="utf-8")

    manager._run_acme = fake_run_acme  # type: ignore[method-assign]
    manager._provision_or_renew()

    assert calls[0] == [
        "--register-account",
        "-m",
        "acme@example.com",
        "--eab-kid",
        "kid-123",
        "--eab-hmac-key",
        "hmac-456",
    ]
    assert calls[1] == [
        "--issue",
        "--dns",
        "dns_cf",
        "-d",
        "api-roborock.example.com",
        "--keylength",
        "2048",
    ]
    assert calls[2][:3] == ["--install-cert", "-d", "api-roborock.example.com"]


def test_certificate_manager_rejects_missing_actalis_eab_files(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[network]
stack_fqdn = "api-roborock.example.com"

[broker]
mode = "embedded"

[storage]
data_dir = "data"

[tls]
mode = "cloudflare_acme"
base_domain = "example.com"
email = "acme@example.com"
cloudflare_token_file = "secrets/cloudflare_token"
acme_server = "actalis"
acme_eab_kid_file = "secrets/acme_eab_kid"
acme_eab_hmac_key_file = "secrets/acme_eab_hmac_key"

[admin]
password_hash = "pbkdf2_sha256$600000$abc$def"
session_secret = "abcdefghijklmnopqrstuvwxyz123456"
protocol_login_email = "user@example.com"
protocol_login_pin_hash = "pbkdf2_sha256$600000$ghi$jkl"
        """.strip(),
        encoding="utf-8",
    )
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    paths.cloudflare_token_file.parent.mkdir(parents=True, exist_ok=True)
    paths.cloudflare_token_file.write_text("cloudflare-token", encoding="utf-8")
    manager = CertificateManager(config=config, paths=paths)

    try:
        manager._provision_or_renew()
    except RuntimeError as exc:
        assert "Actalis ACME requires EAB credentials" in str(exc)
    else:
        raise AssertionError("Expected RuntimeError for missing Actalis EAB files")


def test_certificate_manager_keeps_wildcard_shape_for_zerossl(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[network]
stack_fqdn = "api-roborock.example.com"

[broker]
mode = "embedded"

[storage]
data_dir = "data"

[tls]
mode = "cloudflare_acme"
base_domain = "example.com"
email = "acme@example.com"
cloudflare_token_file = "secrets/cloudflare_token"
acme_server = "zerossl"

[admin]
password_hash = "pbkdf2_sha256$600000$abc$def"
session_secret = "abcdefghijklmnopqrstuvwxyz123456"
protocol_login_email = "user@example.com"
protocol_login_pin_hash = "pbkdf2_sha256$600000$ghi$jkl"
        """.strip(),
        encoding="utf-8",
    )
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    paths.cloudflare_token_file.parent.mkdir(parents=True, exist_ok=True)
    paths.cloudflare_token_file.write_text("cloudflare-token", encoding="utf-8")
    manager = CertificateManager(config=config, paths=paths)
    calls: list[list[str]] = []

    def fake_run_acme(args: list[str]) -> None:
        calls.append(list(args))
        if "--install-cert" in args:
            paths.cert_file.parent.mkdir(parents=True, exist_ok=True)
            paths.key_file.parent.mkdir(parents=True, exist_ok=True)
            paths.cert_file.write_text("cert", encoding="utf-8")
            paths.key_file.write_text("key", encoding="utf-8")

    manager._run_acme = fake_run_acme  # type: ignore[method-assign]
    manager._provision_or_renew()

    assert calls[1] == [
        "--issue",
        "--dns",
        "dns_cf",
        "-d",
        "example.com",
        "-d",
        "*.example.com",
        "--keylength",
        "2048",
    ]
    assert calls[2][:3] == ["--install-cert", "-d", "example.com"]


def test_run_acme_redacts_eab_credentials_in_logs_and_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[network]
stack_fqdn = "api-roborock.example.com"

[broker]
mode = "embedded"

[storage]
data_dir = "data"

[tls]
mode = "cloudflare_acme"
base_domain = "example.com"
email = "acme@example.com"
cloudflare_token_file = "secrets/cloudflare_token"
acme_server = "actalis"
acme_eab_kid = "kid-123"
acme_eab_hmac_key = "hmac-456"

[admin]
password_hash = "pbkdf2_sha256$600000$abc$def"
session_secret = "abcdefghijklmnopqrstuvwxyz123456"
protocol_login_email = "user@example.com"
protocol_login_pin_hash = "pbkdf2_sha256$600000$ghi$jkl"
        """.strip(),
        encoding="utf-8",
    )
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    paths.cloudflare_token_file.parent.mkdir(parents=True, exist_ok=True)
    paths.cloudflare_token_file.write_text("cloudflare-token", encoding="utf-8")
    manager = CertificateManager(config=config, paths=paths)

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=args[0], returncode=1, stdout="failed")

    monkeypatch.setattr("roborock_local_server.certs.ACME_SH_PATH", tmp_path / "acme.sh")
    (tmp_path / "acme.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr("roborock_local_server.certs.subprocess.run", fake_run)

    with caplog.at_level(logging.INFO, logger="roborock_local_server.certs"):
        with pytest.raises(RuntimeError) as excinfo:
            manager._run_acme(
                [
                    "--register-account",
                    "-m",
                    "acme@example.com",
                    "--eab-kid",
                    "kid-123",
                    "--eab-hmac-key",
                    "hmac-456",
                ]
            )

    combined_logs = "\n".join(caplog.messages)
    assert "kid-123" not in combined_logs
    assert "hmac-456" not in combined_logs
    assert "<redacted>" in combined_logs
    assert "kid-123" not in str(excinfo.value)
    assert "hmac-456" not in str(excinfo.value)
