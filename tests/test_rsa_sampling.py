"""Recover public keys from independent cryptography-generated signatures."""

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import pytest

from roborock_local_server.bundled_backend.shared.device_key_recovery import (
    recover_modulus_from_samples,
)


@pytest.mark.parametrize(
    "key_size,hash_name,algorithm",
    [
        (2048, "sha256", hashes.SHA256()),
        (4096, "sha384", hashes.SHA384()),
    ],
)
def test_recovers_exact_public_key_from_samples(key_size, hash_name, algorithm):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    messages = [f"synthetic-exact-wire-message-{i}" for i in range(3)]
    samples = [
        (
            message,
            base64.b64encode(
                key.sign(message.encode(), padding.PKCS1v15(), algorithm)
            ).decode(),
        )
        for message in messages
    ]
    diagnostics = {}
    # Exercise the original default as well as the newly explicit SHA-384 mode.
    options = {} if hash_name == "sha256" else {"hash_name": hash_name}
    modulus = recover_modulus_from_samples(samples, diagnostics=diagnostics, **options)
    assert modulus == key.public_key().public_numbers().n
    assert diagnostics["hash_name"] == hash_name


def test_hmac_sized_samples_are_not_treated_as_rsa():
    samples = [
        ("one", base64.b64encode(bytes(32)).decode()),
        ("two", base64.b64encode(bytes([1]) * 32).decode()),
    ]
    diagnostics = {}
    assert recover_modulus_from_samples(samples, diagnostics=diagnostics) is None
    assert "HMAC" in diagnostics["reason"]


def test_unsupported_hash_is_explicit():
    with pytest.raises(ValueError, match="sha256 or sha384"):
        recover_modulus_from_samples([], hash_name="md5")
