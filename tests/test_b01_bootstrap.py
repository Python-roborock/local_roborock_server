"""Synthetic contract vectors checked against Q7 ARM code in Unicorn."""

import base64
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from fastapi.testclient import TestClient
import pytest

from conftest import write_release_config
from roborock_local_server.b01_bootstrap import (
    encrypt_result,
    mqtt_credentials,
    request_signature,
)
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor

SECRET = "0123456789abcdef0123456789abcdef"
NONCE = "0123456789abcdef"
DID = "123456789"
DUID = "synthetic-cloud-duid"
MODEL = "roborock.vacuum.sc05"
SESSION = "abcdefghijklmnop"
TOKEN = "fedcba9876543210"
REGION_QUERY = f"d={DID}&m={MODEL}&r=rr-lab.example/&s={SESSION}&t={TOKEN}"
NC_BODY = f"d={DID}&m={MODEL}&n=Synthetic&p=B01&r=rr-lab.example/&s={SESSION}&scheme=1&t={TOKEN}"


def headers(path, wire):
    return {
        "nonce": NONCE,
        "ts": "123456",
        "sign": request_signature(SECRET, path, wire.encode(), NONCE, "123456"),
    }


def decrypt(response):
    # Exact key and IV observed at firmware 0x1a010; independent crypto library.
    cipher = AES.new(b"89abcdef01234567", AES.MODE_CBC, b"5123906e58e06714")
    return json.loads(
        unpad(cipher.decrypt(base64.b64decode(response.json()["result"])), 16)
    )


@pytest.fixture
def stack(tmp_path):
    config_file = write_release_config(tmp_path, https_port=8443, mqtt_tls_port=9443)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    (paths.state_dir / "b01_devices.json").write_text(
        json.dumps({"devices": {DID: {"secret": SECRET, "duid": DUID, "model": MODEL}}})
    )
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.runtime_credentials.ensure_device(
        did=DID, duid=DUID, model=MODEL, localkey="0123456789abcdef"
    )
    return TestClient(supervisor.app), supervisor, paths


def test_signature_matches_firmware_trace():
    assert (
        request_signature(SECRET, "/b/region", REGION_QUERY.encode(), NONCE, "123456")
        == "MWgBDF13JqtaXi8l024LeUjx21H6qOPJwGZ5dnxCB6M="
    )


@pytest.mark.parametrize(
    "token,password",
    [
        (TOKEN, "01a3fc9993655075ecef7cabcf76af48"),
        ("12345678", "cde0a3149b622a8c642008273eb40eed"),
    ],
)
def test_mqtt_credentials_match_firmware_trace(token, password):
    assert mqtt_credentials(DUID, "0123456789abcdef", SESSION, token) == {
        "client_id": "4d12f0da94689dbb",
        "username": "943561986905f676",
        "password": password,
    }


@pytest.mark.parametrize("prefix", ["", "/.roborock.com"])
def test_region_uses_aes_and_configured_endpoints(stack, prefix):
    client, _, _ = stack
    response = client.get(
        prefix + "/b/region?" + REGION_QUERY,
        headers={
            **headers("/b/region", REGION_QUERY),
            "host": "api-untrusted.example:1234",
        },
    )
    assert response.status_code == 200
    assert decrypt(response) == {
        "apiUrl": "https://api-roborock.example.com:8443",
        "mqttUrl": "ssl://api-roborock.example.com:9443",
    }


def test_nc_returns_cloud_duid_and_registers_matching_mqtt_credentials(stack):
    client, supervisor, _ = stack
    response = client.post(
        "/.roborock.com/b/nc",
        content=NC_BODY,
        headers={
            **headers("/b/nc", NC_BODY),
            "content-type": "application/x-www-form-urlencoded",
        },
    )
    assert response.status_code == 200
    assert decrypt(response) == {"k": "0123456789abcdef", "d": DUID}
    device = supervisor.runtime_credentials.resolve_device(did=DID)
    assert device["device_mqtt_usr"] == "943561986905f676"
    assert device["device_mqtt_pass"] == "01a3fc9993655075ecef7cabcf76af48"


def test_missing_secret_does_not_fall_back_to_rsa(stack):
    client, _, paths = stack
    (paths.state_dir / "b01_devices.json").unlink()
    response = client.get(
        "/b/region?" + REGION_QUERY, headers=headers("/b/region", REGION_QUERY)
    )
    assert response.status_code == 503
    assert response.json()["msg"] == "b01_device_secret_required"


@pytest.mark.parametrize(
    "change", [{"sign": "bad"}, {"nonce": "bad"}, {"ts": "bad"}, {"v": "v2"}]
)
def test_invalid_or_unimplemented_auth_is_explicit(stack, change):
    client, supervisor, _ = stack
    before = supervisor.runtime_credentials.devices()
    response = client.post(
        "/b/nc", content=NC_BODY, headers={**headers("/b/nc", NC_BODY), **change}
    )
    assert response.status_code == (501 if "v" in change else 401)
    assert supervisor.runtime_credentials.devices() == before


@pytest.mark.parametrize(
    "body",
    [
        NC_BODY.replace("p=B01", "p=1.0"),
        NC_BODY.replace("scheme=1", "scheme=2"),
        NC_BODY + "&d=other",
        NC_BODY.replace("s=" + SESSION, "s=x"),
        NC_BODY.replace(MODEL, "roborock.vacuum.sc01"),
    ],
)
def test_invalid_nc_does_not_mutate_credentials(stack, body):
    client, supervisor, _ = stack
    before = supervisor.runtime_credentials.devices()
    response = client.post("/b/nc", content=body, headers=headers("/b/nc", body))
    assert response.status_code == 400
    assert supervisor.runtime_credentials.devices() == before


def test_disabled_onboarding_still_blocks_b01(tmp_path):
    config_file = write_release_config(tmp_path, new_connections_enabled=False)
    config = load_config(config_file)
    supervisor = ReleaseSupervisor(
        config=config, paths=resolve_paths(config_file, config)
    )
    response = TestClient(supervisor.app).get(
        "/.roborock.com/b/region?" + REGION_QUERY,
        headers=headers("/b/region", REGION_QUERY),
    )
    assert response.status_code == 403
    logged = supervisor.paths.http_jsonl_path.read_text()
    assert SESSION not in logged and TOKEN not in logged
    assert SESSION not in json.dumps(supervisor.runtime_state.health_snapshot())


def test_b01_logs_do_not_contain_activation_tokens(stack):
    client, _, paths = stack
    client.get("/b/region?" + REGION_QUERY, headers=headers("/b/region", REGION_QUERY))
    log = paths.http_jsonl_path.read_text()
    assert SESSION not in log and TOKEN not in log and SECRET not in log
    assert json.loads(log.splitlines()[-1])["body_redacted"] is True


def test_wrong_method_rejected(stack):
    client, _, _ = stack
    assert (
        client.get("/b/nc?" + NC_BODY, headers=headers("/b/nc", NC_BODY)).status_code
        == 405
    )


def test_encrypt_result_rejects_short_secrets():
    with pytest.raises(ValueError):
        encrypt_result("short", NONCE, {})
