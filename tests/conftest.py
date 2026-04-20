from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
root_str = str(ROOT)
if root_str not in sys.path:
    sys.path.insert(0, root_str)
SRC = ROOT / "src"
src_str = str(SRC)
if src_str not in sys.path:
    sys.path.insert(0, src_str)

from roborock_local_server.security import hash_password


def write_release_config(
    tmp_path: Path,
    *,
    stack_fqdn: str = "roborock.example.com",
    https_port: int = 443,
    mqtt_tls_port: int = 8883,
    broker_mode: str = "external",
    enable_topic_bridge: bool = False,
    protocol_auth_enabled: bool = True,
    protocol_login_email: str = "user@example.com",
    protocol_login_pin: str = "123456",
) -> Path:
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    (cert_dir / "fullchain.pem").write_text("test-cert\n", encoding="utf-8")
    (cert_dir / "privkey.pem").write_text("test-key\n", encoding="utf-8")

    config_file = tmp_path / "config.toml"
    config_file.write_text(
        f"""
[network]
stack_fqdn = "{stack_fqdn}"
https_port = {https_port}
mqtt_tls_port = {mqtt_tls_port}

[broker]
mode = "{broker_mode}"
host = "127.0.0.1"
port = 1883
enable_topic_bridge = {"true" if enable_topic_bridge else "false"}

[storage]
data_dir = "data"

[tls]
mode = "provided"
cert_file = "certs/fullchain.pem"
key_file = "certs/privkey.pem"

[admin]
password_hash = "{hash_password("correct horse battery staple", iterations=10_000)}"
session_secret = "abcdefghijklmnopqrstuvwxyz123456"
session_ttl_seconds = 3600
protocol_auth_enabled = {"true" if protocol_auth_enabled else "false"}
protocol_login_email = "{protocol_login_email}"
protocol_login_pin_hash = "{hash_password(protocol_login_pin, iterations=10_000)}"
        """.strip(),
        encoding="utf-8",
    )
    return config_file
