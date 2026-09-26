"""Exercise NC onboarding with synthetic keys and firmware-style multipart fields."""

import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient
import pytest

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor


DID = "1234567890123"
DUID = "synthetic-cloud-device"
LOCAL_KEY = "0123456789abcdef"
MODEL = "roborock.vacuum.a298"


@pytest.fixture(scope="module")
def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


@pytest.fixture
def supervisor(tmp_path, private_key):
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    for path, payload in (
        (paths.inventory_path, {"devices": [{"duid": DUID, "model": MODEL, "local_key": LOCAL_KEY}]}),
        (
            paths.runtime_credentials_path,
            {"schema_version": 2, "devices": [{"did": DID, "duid": DUID, "model": MODEL, "localkey": LOCAL_KEY}]},
        ),
        (
            paths.device_key_state_path,
            {"devices": {DID: {"modulus_hex": format(private_key.public_key().public_numbers().n, "x")}}},
        ),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
    instance = ReleaseSupervisor(config=config, paths=paths)
    instance.runtime_state.start_onboarding_session(target_duid=DUID, target_did=DID, target_name="Synthetic")
    return instance


@pytest.mark.parametrize("prefix", ["", "/.roborock.com"])
@pytest.mark.parametrize("encoding", ["multipart", "urlencoded"])
def test_nc_recognizes_device_and_encrypts_reply(supervisor, private_key, prefix, encoding):
    fields = {
        "d": DID,
        "m": MODEL,
        "n": "Lab vacuum é",
        "s": "synthetic+session%2B=1",
        "t": "synthetic+token%2F=2",
        "scheme": "1",
        "extra": ["", "literal+%2B=value"],
    }
    # Header names overlap form names; their values must not replace the fields.
    headers = {"v": "v2", "n": "nonce1", "t": "1234567890", "s": base64.b64encode(b"S" * 512).decode()}
    with TestClient(supervisor.app) as client:
        region = client.get(f"{prefix}/region", params={"d": DID, "m": MODEL}, headers={"v": "v2"})
        assert region.status_code == 200
        assert isinstance(region.json()["result"], str)
        if encoding == "multipart":
            parts = [
                (name, (None, value))
                for name, values in fields.items()
                for value in (values if isinstance(values, list) else [values])
            ]
            request = client.build_request("POST", f"{prefix}/nc", files=parts, headers=headers)
            # Curl may quote the boundary parameter. Both forms are valid MIME.
            content_type, boundary = request.headers["content-type"].split("boundary=")
            request.headers["content-type"] = f'{content_type}boundary="{boundary}"'
        else:
            request = client.build_request("POST", f"{prefix}/nc", data=fields, headers=headers)
        wire_body = request.read()
        response = client.send(request)

    assert response.status_code == 200
    assert response.json()["code"] == 200
    assert isinstance(response.json()["result"], str)
    ciphertext = base64.b64decode(response.json()["result"], validate=True)
    assert len(ciphertext) == 512
    plain = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
    )
    assert json.loads(plain) == {"d": DID, "k": LOCAL_KEY, "s": fields["s"], "t": fields["t"]}

    entries = [json.loads(line) for line in supervisor.paths.http_jsonl_path.read_text(encoding="utf-8").splitlines()]
    entry = entries[-1]
    assert entry["route"] == "nc_prepare"
    assert entry["did"] == DID and entry["pid"] == MODEL
    assert entry["body_form"]["extra"] == fields["extra"]
    assert entry["body_form"]["n"] == [fields["n"]]
    assert base64.b64decode(entry["body_b64"]) == wire_body
    assert entry["body_sha256"] == hashlib.sha256(wire_body).hexdigest()
    assert entry["response_json"] == response.json()
    vacuum = next(item for item in supervisor.runtime_state.vacuum_snapshot() if item["duid"] == DUID)
    assert vacuum["onboarding"]["missing_steps"] == []
    assert vacuum["onboarding"]["public_key_ready"] is True
    assert supervisor.runtime_state.pairing_snapshot()["checks"]["nc"] is True


@pytest.mark.parametrize(
    "content_type, body",
    [
        ("multipart/form-data", b"missing boundary"),
        ("multipart/form-data; boundary=example", b"invalid multipart body"),
    ],
)
def test_invalid_multipart_is_rejected_before_nc_registration(supervisor, content_type, body):
    with TestClient(supervisor.app) as client:
        response = client.post("/nc", content=body, headers={"content-type": content_type})
    assert response.status_code == 400
    assert not any(event.get("route") == "nc_prepare" for event in supervisor.runtime_state.recent_events())


def test_nc_multipart_rejects_file_parts(supervisor):
    with TestClient(supervisor.app) as client:
        response = client.post("/nc", files={"d": ("device.txt", DID)})
    assert response.status_code == 400
    assert not any(event.get("route") == "nc_prepare" for event in supervisor.runtime_state.recent_events())
