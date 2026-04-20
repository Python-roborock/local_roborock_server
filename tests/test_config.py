from pathlib import Path
import pytest

from roborock_local_server.config import load_config, resolve_paths


def test_load_config_and_resolve_paths(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[network]
stack_fqdn = "roborock.example.com"

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

    assert config.network.stack_fqdn == "roborock.example.com"
    assert config.admin.protocol_auth_enabled is True
    assert config.admin.protocol_login_email == "user@example.com"
    assert paths.data_dir == (tmp_path / "data").resolve()
    assert paths.cert_file == (tmp_path / "certs" / "fullchain.pem").resolve()
    assert paths.key_file == (tmp_path / "certs" / "privkey.pem").resolve()


def test_load_config_requires_protocol_login_credentials(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[network]
stack_fqdn = "roborock.example.com"

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
