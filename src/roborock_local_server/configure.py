#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Interactive config.toml writer for opinionated local-server setups."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from getpass import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
from urllib.parse import urlsplit


def _urlsafe_b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def hash_password(password: str, *, iterations: int = 600_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return (
        f"pbkdf2_sha256${iterations}$"
        f"{_urlsafe_b64encode(salt)}$"
        f"{_urlsafe_b64encode(digest)}"
    )


_HOST_RE = re.compile(r"^[a-z0-9.-]+$")
_CLOUDFLARE_TOKEN_CONTAINER_PATH = "/run/secrets/cloudflare_token"


@dataclass(frozen=True)
class ConfigureAnswers:
    stack_fqdn: str
    https_port: int
    mqtt_tls_port: int
    broker_mode: str
    tls_mode: str
    base_domain: str
    email: str
    cloudflare_token: str
    password_hash: str
    session_secret: str
    protocol_login_email: str
    protocol_login_pin_hash: str


@dataclass(frozen=True)
class ConfigureResult:
    config_file: Path
    cloudflare_token_file: Path | None
    broker_template_needs_edit: bool


def _toml_string(value: str) -> str:
    return json.dumps(value)


def _normalize_hostname(raw_value: str, *, field_name: str) -> str:
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
    return normalized


def _prompt_non_empty(prompt: str) -> str:
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("A value is required.")


def _prompt_hostname(prompt: str, *, field_name: str) -> str:
    while True:
        raw_value = _prompt_non_empty(prompt)
        try:
            return _normalize_hostname(raw_value, field_name=field_name)
        except ValueError as exc:
            print(exc)


def _prompt_port(prompt: str, *, default: int) -> int:
    while True:
        raw_value = input(f"{prompt} [{default}]: ").strip()
        if not raw_value:
            return default
        try:
            port = int(raw_value)
        except ValueError:
            print("Please enter a valid port number.")
            continue
        if 1 <= port <= 65535:
            return port
        print("Port must be between 1 and 65535.")


def _prompt_yes_no(prompt: str, *, default: bool) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        raw_value = input(f"{prompt} [{suffix}]: ").strip().lower()
        if not raw_value:
            return default
        if raw_value in {"y", "yes"}:
            return True
        if raw_value in {"n", "no"}:
            return False
        print("Please answer yes or no.")


def _prompt_password() -> str:
    while True:
        password = getpass("Admin password (input hidden): ")
        if password:
            return password
        print("A password is required.")


def _prompt_protocol_login_email() -> str:
    while True:
        email = _prompt_non_empty("Protocol login email for app/HA sign-in: ")
        if "@" in email:
            return email
        print("Protocol login email must look like an email address.")


def _validate_protocol_login_pin(pin: str) -> str:
    normalized = str(pin or "").strip()
    if len(normalized) != 6 or not normalized.isdigit():
        raise ValueError("Protocol login PIN must be exactly 6 digits.")
    return normalized


def _prompt_protocol_login_pin() -> str:
    while True:
        pin = getpass("Protocol login PIN (6 digits, input hidden): ").strip()
        try:
            normalized_pin = _validate_protocol_login_pin(pin)
        except ValueError as exc:
            print(exc)
            continue
        confirmation = getpass("Confirm protocol login PIN: ").strip()
        if normalized_pin != confirmation:
            print("PIN entries did not match.")
            continue
        return normalized_pin


def collect_configure_answers() -> ConfigureAnswers:
    print("This writes a small config.toml with opinionated defaults.")
    stack_fqdn = _prompt_hostname(
        "Stack FQDN (hostname only (no 'https://'); it needs to start with api-): ",
        field_name="stack_fqdn",
    )
    https_port = _prompt_port("HTTPS port to advertise and listen on", default=443)
    mqtt_tls_port = _prompt_port("MQTT TLS port to advertise and listen on", default=8883)
    use_external_broker = _prompt_yes_no("Use your own MQTT broker instead of the embedded one?", default=False)
    use_cloudflare_acme = _prompt_yes_no("Use Cloudflare DNS-01 for automatic TLS renewal?", default=True)

    broker_mode = "external" if use_external_broker else "embedded"
    tls_mode = "cloudflare_acme" if use_cloudflare_acme else "provided"

    base_domain = ""
    email = ""
    cloudflare_token = ""
    if use_cloudflare_acme:
        base_domain = _prompt_hostname(
            "Base domain for the wildcard certificate (example.com): ",
            field_name="tls.base_domain",
        )
        email = _prompt_non_empty("Email for the ACME account: ")
        cloudflare_token = getpass("Cloudflare API token (input hidden): ").strip()
        while not cloudflare_token:
            print("A Cloudflare API token is required.")
            cloudflare_token = getpass("Cloudflare API token (input hidden): ").strip()

    password = _prompt_password()
    protocol_login_email = _prompt_protocol_login_email()
    protocol_login_pin = _prompt_protocol_login_pin()
    return ConfigureAnswers(
        stack_fqdn=stack_fqdn,
        https_port=https_port,
        mqtt_tls_port=mqtt_tls_port,
        broker_mode=broker_mode,
        tls_mode=tls_mode,
        base_domain=base_domain,
        email=email,
        cloudflare_token=cloudflare_token,
        password_hash=hash_password(password),
        session_secret=secrets.token_urlsafe(32),
        protocol_login_email=protocol_login_email,
        protocol_login_pin_hash=hash_password(protocol_login_pin),
    )


def render_config_toml(answers: ConfigureAnswers) -> str:
    lines = [
        "[network]",
        f"stack_fqdn = {_toml_string(answers.stack_fqdn)}",
        'bind_host = "0.0.0.0"',
        f"https_port = {answers.https_port}",
        f"mqtt_tls_port = {answers.mqtt_tls_port}",
        'region = "us"',
        "",
        "[broker]",
        f'mode = "{answers.broker_mode}"',
    ]
    if answers.broker_mode == "embedded":
        lines.extend(
            [
                'host = "127.0.0.1"',
                "port = 18830",
                'mosquitto_binary = "mosquitto"',
                "enable_topic_bridge = true",
            ]
        )
    else:
        lines.extend(
            [
                "# Fill this in with your existing MQTT broker hostname or IP before starting the stack.",
                'host = ""',
                "port = 1883",
                'mosquitto_binary = "mosquitto"',
                "enable_topic_bridge = true",
            ]
        )

    lines.extend(
        [
            "",
            "[storage]",
            'data_dir = "/data"',
            "",
            "[tls]",
            f'mode = "{answers.tls_mode}"',
        ]
    )
    if answers.tls_mode == "cloudflare_acme":
        lines.extend(
            [
                f"base_domain = {_toml_string(answers.base_domain)}",
                f"email = {_toml_string(answers.email)}",
                f"cloudflare_token_file = {_toml_string(_CLOUDFLARE_TOKEN_CONTAINER_PATH)}",
                "renew_days_before = 30",
                "renew_check_seconds = 43200",
                'acme_server = "zerossl"',
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
                'acme_server = "zerossl"',
                'cert_file = "/data/certs/fullchain.pem"',
                'key_file = "/data/certs/privkey.pem"',
            ]
        )

    lines.extend(
        [
            "",
            "[admin]",
            f"password_hash = {_toml_string(answers.password_hash)}",
            f"session_secret = {_toml_string(answers.session_secret)}",
            "session_ttl_seconds = 86400",
            "protocol_auth_enabled = true",
            f"protocol_login_email = {_toml_string(answers.protocol_login_email)}",
            f"protocol_login_pin_hash = {_toml_string(answers.protocol_login_pin_hash)}",
            "",
        ]
    )
    return "\n".join(lines)


def write_config_setup(
    *,
    config_file: str | Path,
    answers: ConfigureAnswers,
    force: bool = False,
) -> ConfigureResult:
    config_path = Path(config_file).resolve()
    token_path = config_path.parent / "secrets" / "cloudflare_token"

    protected_paths = [config_path]
    if answers.tls_mode == "cloudflare_acme":
        protected_paths.append(token_path)

    if not force:
        existing = [path for path in protected_paths if path.exists()]
        if existing:
            joined = ", ".join(str(path) for path in existing)
            raise FileExistsError(f"Refusing to overwrite existing file(s): {joined}. Re-run with --force to replace them.")

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(render_config_toml(answers), encoding="utf-8")

    written_token_path: Path | None = None
    if answers.tls_mode == "cloudflare_acme":
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(answers.cloudflare_token, encoding="utf-8")
        if os.name != "nt":
            token_path.chmod(0o600)
        written_token_path = token_path

    return ConfigureResult(
        config_file=config_path,
        cloudflare_token_file=written_token_path,
        broker_template_needs_edit=answers.broker_mode == "external",
    )


def run_configure(*, config_file: str | Path, force: bool = False) -> ConfigureResult:
    answers = collect_configure_answers()
    return write_config_setup(config_file=config_file, answers=answers, force=force)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate config.toml for roborock-local-server")
    parser.add_argument("--config", default="config.toml", help="Output path (default: config.toml)")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files")
    args = parser.parse_args()

    result = run_configure(config_file=args.config, force=args.force)

    print(f"\nWrote {result.config_file}")
    if result.cloudflare_token_file:
        print(f"Wrote {result.cloudflare_token_file}")
    if result.broker_template_needs_edit:
        print("NOTE: You chose an external broker — edit config.toml to set broker.host before starting.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
