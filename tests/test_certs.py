from datetime import datetime, timedelta, timezone
from pathlib import Path
import logging
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest
from roborock_local_server.certs import CertificateManager
from roborock_local_server.config import load_config, resolve_paths


def _write_certificate(
    cert_path: Path,
    *,
    common_name: str,
    san_names: list[str],
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in san_names]), critical=False)
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )
    cert_path.write_bytes(certificate.public_bytes(encoding=serialization.Encoding.PEM))


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
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout="failed with kid-123 hmac-456 and cloudflare-token",
        )

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
    assert "cloudflare-token" not in combined_logs
    assert "<redacted>" in combined_logs
    assert "kid-123" not in str(excinfo.value)
    assert "hmac-456" not in str(excinfo.value)


def test_certificate_manager_refreshes_when_cert_domains_do_not_match_config(tmp_path: Path) -> None:
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
    paths.cert_file.parent.mkdir(parents=True, exist_ok=True)
    paths.key_file.parent.mkdir(parents=True, exist_ok=True)
    _write_certificate(paths.cert_file, common_name="example.com", san_names=["example.com", "*.example.com"])
    paths.key_file.write_text("key", encoding="utf-8")
    manager = CertificateManager(config=config, paths=paths)
    called = {"value": False}

    def fake_provision() -> None:
        called["value"] = True

    manager._provision_or_renew = fake_provision  # type: ignore[method-assign]

    assert manager.ensure_certificate() is True
    assert called["value"] is True
