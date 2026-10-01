"""Tests for the local ``/f/c`` (rrcheck) access-grant route -- issue #120.

The route forges an accepted grant that the vacuum decrypts with the same RSA
private key it uses for ``/region``. Here we play the device: build a keypair,
register the public modulus the way onboarding recovery does, drive the request
through ``resolve_route``, then decrypt the response and assert it is accepted.
"""

from __future__ import annotations

import base64
import json
import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

# Importing the backend bridge puts the bundled_backend dir on sys.path so the
# bare ``shared`` / ``https_server`` imports inside the route modules resolve.
import roborock_local_server.backend as backend  # noqa: E402
from shared.context import ServerContext  # noqa: E402


def _make_context(tmp_path, *, did: str, region: str = "eu", with_key: bool = True):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_state = tmp_path / "device_keys.json"
    if with_key:
        modulus = key.public_key().public_numbers().n
        key_state.write_text(
            json.dumps({"devices": {did: {"modulus_hex": format(modulus, "x")}}}),
            encoding="utf-8",
        )
    else:
        key_state.write_text(json.dumps({"devices": {}}), encoding="utf-8")

    ctx = ServerContext(
        api_host="api.example.com",
        mqtt_host="mqtt.example.com",
        wood_host="wood.example.com",
        region=region,
        protocol_login_email="user@example.com",
        localkey="0123456789abcdef",
        duid=did,
        mqtt_usr="mqtt_usr",
        mqtt_passwd="mqtt_passwd",
        mqtt_clientid="mqtt_clientid",
        https_port=443,
        mqtt_tls_port=8883,
        http_jsonl=tmp_path / "http.jsonl",
        mqtt_jsonl=tmp_path / "mqtt.jsonl",
        loggers={"real_stack": logging.getLogger("test.real_stack")},
        key_state_file=key_state,
    )
    return ctx, key


def _decrypt_grant(private_key, payload: dict) -> dict:
    aes_key = private_key.decrypt(
        base64.b64decode(payload["k"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    decryptor = Cipher(algorithms.AES(aes_key), modes.ECB()).decryptor()
    padded = decryptor.update(base64.b64decode(payload["d"])) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return json.loads(plaintext)


def test_fc_returns_decryptable_accepted_grant(tmp_path):
    did = "1234567890"
    ctx, key = _make_context(tmp_path, did=did, region="eu")

    route_name, payload = backend.resolve_route(
        rules=backend.default_endpoint_rules(),
        context=ctx,
        clean_path="/f/c",
        query_params={},
        body_params={"did": [did]},
        method="POST",
    )

    assert route_name == "fw_check"
    assert set(payload) >= {"k", "d"}
    inner = _decrypt_grant(key, payload)
    assert inner["f"] == "t"  # accepted flag
    assert inner["c"] == "EU"
    assert isinstance(inner["t"], int)


def test_fc_matches_common_path_variants(tmp_path):
    did = "42"
    ctx, key = _make_context(tmp_path, did=did)
    for path in ("/f/c", "/api/f/c", "/b/f/c", "/f/c/"):
        route_name, payload = backend.resolve_route(
            rules=backend.default_endpoint_rules(),
            context=ctx,
            clean_path=path,
            query_params={},
            body_params={"did": [did]},
            method="POST",
        )
        assert route_name == "fw_check", path
        assert _decrypt_grant(key, payload)["f"] == "t"


def test_fc_falls_back_to_catchall_without_key(tmp_path):
    did = "99"
    ctx, _key = _make_context(tmp_path, did=did, with_key=False)

    route_name, payload = backend.resolve_route(
        rules=backend.default_endpoint_rules(),
        context=ctx,
        clean_path="/f/c",
        query_params={},
        body_params={"did": [did]},
        method="POST",
    )

    # Route still matches, but with no device key it must not emit a bogus grant;
    # it falls back to the previous catchall response shape instead.
    assert route_name == "fw_check"
    assert "k" not in payload and "d" not in payload
