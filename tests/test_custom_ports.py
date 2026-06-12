import json

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor


def _write_json(path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_server_advertises_custom_https_and_mqtt_ports(tmp_path) -> None:
    config_file = write_release_config(
        tmp_path,
        stack_fqdn="api-roborock.example.com",
        https_port=8443,
        mqtt_tls_port=9443,
    )
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    _write_json(paths.inventory_path, {"home": {"id": 12345, "name": "Test Home"}, "devices": []})
    _write_json(
        paths.cloud_snapshot_path,
        {
            "user_data": {
                "uid": 1001,
                "token": "local-token-123",
                "rruid": "local-rruid-123",
                "rriot": {
                    "u": "hawk-user-123",
                    "s": "hawk-session-123",
                    "h": "hawk-secret-123",
                    "k": "hawk-mqtt-key-123",
                    "r": {
                        "r": "US",
                        "a": "https://api-us.roborock.com",
                        "m": "ssl://mqtt-us.roborock.com:8883",
                        "l": "https://wood-us.roborock.com",
                    },
                },
            }
        },
    )

    supervisor = ReleaseSupervisor(config=config, paths=paths)
    client = TestClient(supervisor.app)

    region_response = client.get("/region", headers={"host": "api-roborock.example.com:8443"})
    assert region_response.status_code == 200
    region_payload = region_response.json()["data"]
    assert region_payload["apiUrl"] == "https://api-roborock.example.com:8443"
    assert region_payload["mqttUrl"] == "ssl://api-roborock.example.com:9443"

    assert supervisor.context.api_url() == "https://api-roborock.example.com:8443"
    assert supervisor.context.mqtt_url() == "ssl://api-roborock.example.com:9443"
    assert supervisor.context.wood_url() == "https://api-roborock.example.com:8443"


def test_server_advertises_reverse_proxy_public_ports(tmp_path) -> None:
    config_file = tmp_path / "config.toml"
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    (cert_dir / "fullchain.pem").write_text("test-cert\n", encoding="utf-8")
    (cert_dir / "privkey.pem").write_text("test-key\n", encoding="utf-8")
    config_file.write_text(
        """
[network]
stack_fqdn = "api-roborock.example.com"
https_port = 555
mqtt_tls_port = 8881
advertised_https_port = 443
advertised_mqtt_tls_port = 8883

[broker]
mode = "external"
host = "127.0.0.1"
port = 1883
enable_topic_bridge = false

[storage]
data_dir = "data"

[tls]
mode = "provided"
cert_file = "certs/fullchain.pem"
key_file = "certs/privkey.pem"

[admin]
password_hash = "pbkdf2_sha256$600000$abc$def"
session_secret = "abcdefghijklmnopqrstuvwxyz123456"
session_ttl_seconds = 3600
protocol_auth_enabled = true
new_connections_enabled = true
protocol_login_email = "user@example.com"
protocol_login_pin_hash = "pbkdf2_sha256$600000$ghi$jkl"
        """.strip(),
        encoding="utf-8",
    )
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    _write_json(paths.inventory_path, {"home": {"id": 12345, "name": "Test Home"}, "devices": []})

    supervisor = ReleaseSupervisor(config=config, paths=paths)
    client = TestClient(supervisor.app)

    region_response = client.get(
        "/region",
        headers={"host": "api-roborock.example.com"},
    )

    assert region_response.status_code == 200
    region_payload = region_response.json()["data"]
    assert region_payload["apiUrl"] == "https://api-roborock.example.com"
    assert region_payload["mqttUrl"] == "ssl://api-roborock.example.com:8883"
    assert supervisor.context.api_url() == "https://api-roborock.example.com"
    assert supervisor.context.mqtt_url() == "ssl://api-roborock.example.com:8883"
