from pathlib import Path
import pytest

from roborock_local_server.config import load_config, resolve_paths


def test_load_config_and_resolve_paths(tmp_path: Path) -> None:
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
mode = "provided"
cert_file = "certs/fullchain.pem"
key_file = "certs/privkey.pem"

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

    assert config.network.stack_fqdn == "api-roborock.example.com"
    assert config.network.https_port == 555
    assert config.network.mqtt_tls_port == 8881
    assert config.network.advertised_https_port == 555
    assert config.network.advertised_mqtt_tls_port == 8881
    assert config.admin.protocol_auth_enabled is True
    assert config.admin.new_connections_enabled is True
    assert config.admin.protocol_login_email == "user@example.com"
    assert paths.data_dir == (tmp_path / "data").resolve()
    assert paths.cert_file == (tmp_path / "certs" / "fullchain.pem").resolve()
    assert paths.key_file == (tmp_path / "certs" / "privkey.pem").resolve()


def test_load_config_requires_protocol_login_credentials(tmp_path: Path) -> None:
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
mode = "provided"
cert_file = "certs/fullchain.pem"
key_file = "certs/privkey.pem"

[admin]
password_hash = "pbkdf2_sha256$600000$abc$def"
session_secret = "abcdefghijklmnopqrstuvwxyz123456"
        """.strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="admin.protocol_login_email is required"):
        load_config(config_file)


def test_load_config_requires_api_prefix_for_stack_fqdn(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[network]
stack_fqdn = "lashleyhomeassist.duckdns.org"

[broker]
mode = "embedded"

[storage]
data_dir = "data"

[tls]
mode = "provided"
cert_file = "certs/fullchain.pem"
key_file = "certs/privkey.pem"

[admin]
password_hash = "pbkdf2_sha256$600000$abc$def"
session_secret = "abcdefghijklmnopqrstuvwxyz123456"
protocol_login_email = "user@example.com"
protocol_login_pin_hash = "pbkdf2_sha256$600000$ghi$jkl"
        """.strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="network.stack_fqdn must start with api-"):
        load_config(config_file)


def test_load_config_rejects_external_tls(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[network]
stack_fqdn = "api-roborock.example.com"
listener_mode = "external_tls"
https_port = 443
mqtt_tls_port = 8883

[broker]
mode = "embedded"

[storage]
data_dir = "data"

[tls]
mode = "provided"

[admin]
password_hash = "pbkdf2_sha256$600000$abc$def"
session_secret = "abcdefghijklmnopqrstuvwxyz123456"
protocol_login_email = "user@example.com"
protocol_login_pin_hash = "pbkdf2_sha256$600000$ghi$jkl"
        """.strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="external_tls"):
        load_config(config_file)


def test_load_config_normalizes_stack_fqdn_and_validates_cloudflare_base_domain(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[network]
stack_fqdn = "https://API-Roborock.Example.com:8443/path"

[broker]
mode = "embedded"

[storage]
data_dir = "data"

[tls]
mode = "cloudflare_acme"
base_domain = "https://Example.com/path"
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

    assert config.network.stack_fqdn == "api-roborock.example.com"
    assert config.tls.base_domain == "example.com"


def test_load_config_requires_actalis_eab(tmp_path: Path) -> None:
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

[admin]
password_hash = "pbkdf2_sha256$600000$abc$def"
session_secret = "abcdefghijklmnopqrstuvwxyz123456"
protocol_login_email = "user@example.com"
protocol_login_pin_hash = "pbkdf2_sha256$600000$ghi$jkl"
        """.strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Actalis requires"):
        load_config(config_file)


def test_load_config_accepts_actalis_eab_file_paths(tmp_path: Path) -> None:
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
    assert config.tls.acme_server == "actalis"
    assert config.tls.acme_eab_kid == ""
    assert config.tls.acme_eab_hmac_key == ""
    assert paths.acme_eab_kid_file == (tmp_path / "secrets" / "acme_eab_kid").resolve()
    assert paths.acme_eab_hmac_key_file == (tmp_path / "secrets" / "acme_eab_hmac_key").resolve()


def test_load_config_accepts_legacy_inline_actalis_eab(tmp_path: Path) -> None:
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
    assert config.tls.acme_eab_kid == "kid-123"
    assert config.tls.acme_eab_hmac_key == "hmac-456"


def test_load_config_normalizes_mixed_case_actalis(tmp_path: Path) -> None:
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
acme_server = "Actalis"
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
    assert config.tls.acme_server == "actalis"


def test_load_config_rejects_invalid_ports(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[network]
stack_fqdn = "api-roborock.example.com"
https_port = 70000

[broker]
mode = "embedded"

[storage]
data_dir = "data"

[tls]
mode = "provided"
cert_file = "certs/fullchain.pem"
key_file = "certs/privkey.pem"

[admin]
password_hash = "pbkdf2_sha256$600000$abc$def"
session_secret = "abcdefghijklmnopqrstuvwxyz123456"
protocol_login_email = "user@example.com"
protocol_login_pin_hash = "pbkdf2_sha256$600000$ghi$jkl"
        """.strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="network.https_port must be between 1 and 65535"):
        load_config(config_file)


def test_load_config_accepts_reverse_proxy_network_settings(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[network]
stack_fqdn = "api-roborock.example.com"
https_port = 555
mqtt_tls_port = 8881
advertised_https_port = 443
advertised_mqtt_tls_port = 8883

[broker]
mode = "embedded"

[storage]
data_dir = "data"

[tls]
mode = "provided"
cert_file = "certs/fullchain.pem"
key_file = "certs/privkey.pem"

[admin]
password_hash = "pbkdf2_sha256$600000$abc$def"
session_secret = "abcdefghijklmnopqrstuvwxyz123456"
protocol_login_email = "user@example.com"
protocol_login_pin_hash = "pbkdf2_sha256$600000$ghi$jkl"
        """.strip(),
        encoding="utf-8",
    )

    config = load_config(config_file)

    assert config.network.https_port == 555
    assert config.network.mqtt_tls_port == 8881
    assert config.network.advertised_https_port == 443
    assert config.network.advertised_mqtt_tls_port == 8883
