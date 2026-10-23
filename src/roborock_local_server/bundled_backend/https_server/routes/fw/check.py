"""Local answer for firmware access renewal (rrcheck) via ``POST /f/c`` and ``GET /devices/{did}/sh``.

Background (issue #120): the vacuum periodically calls ``/f/c`` to renew a local
access grant. When the server had no route for it, the request fell through to the
generic catchall, which returns ``{"ok": true, ...}`` -- not a valid grant. The
firmware scores every check as failed, tolerates the failures for a ~48h grace
period, then flips its RPC ``AccessControl`` state to denied. From that point every
command comes back as ``-10002 / rrcheck access denied`` while MQTT stays connected.
Re-onboarding only resets the grace window, so control returns for another ~48h.

This route forges an *accepted* grant locally, so the robot never has to reach the
Roborock cloud. The response contract is reconstructed from the S7-family firmware:

    { "k": base64(RSA-OAEP-SHA1(device_pubkey, aes128_key)),
      "d": base64(AES-128-ECB(pkcs7({"f": "t", "c": <country>, "t": <unix>}))) }

``f == "t"`` is the accepted flag; ``t`` must be within +/-300s of the device clock
(the robot syncs its clock from our ``/time/now``). The device unwraps ``k`` with the
same RSA private key it uses for ``/region``, so the public key the server already
recovered during onboarding is exactly what we need -- no Roborock key is involved.

Note: the ``{k, d}`` / ``{f, c, t}`` shape is verified on S7 firmware (via ``/f/c``)
and on the Saros 10R / a143 (via ``/devices/{did}/sh``). For ``/sh`` requests,
the payload is wrapped in the expected response envelope. Other newer models
querying ``/sh`` fall into this same flow. If we have no recovered key for the
device we fall back to the catchall so behaviour is unchanged.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from shared.context import ServerContext

from ..bootstrap.catchall import build as _build_catchall

# Hosts differ per region/model but the firmware always posts to this path.
_MATCH_PATHS = {"/f/c", "/api/f/c", "/b/f/c", "/api/b/f/c"}

# Inner flag the firmware requires to mark the grant accepted.
_ACCEPT_FLAG = "t"

# The firmware decrypts the inner JSON into a 128-byte stack buffer; keep the
# plaintext well under that. "c" is copied but does not affect acceptance.
_MAX_INNER_BYTES = 120


def match(path: str, _method: str = "POST") -> bool:
    clean = path.rstrip("/")
    if clean in _MATCH_PATHS:
        return True
    if clean.startswith("/devices/") and clean.endswith("/sh"):
        return True
    return False


def build_fw_check_payload(pubkey: Any, country: str, now: int) -> dict[str, str]:
    """Build the ``{k, d}`` acceptance envelope for one device public key.

    Raises ``ValueError`` if the inner JSON would exceed the firmware buffer.
    """
    inner = json.dumps(
        {"f": _ACCEPT_FLAG, "c": country, "t": int(now)},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(inner) >= _MAX_INNER_BYTES:
        raise ValueError("rrcheck inner payload too large for firmware buffer")

    aes_key = secrets.token_bytes(16)
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(inner) + padder.finalize()
    encryptor = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    wrapped_key = pubkey.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    return {
        "k": base64.b64encode(wrapped_key).decode("ascii"),
        "d": base64.b64encode(ciphertext).decode("ascii"),
    }


def build(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    clean_path: str,
) -> dict[str, Any]:
    did = ctx.extract_did(query_params, body_params)
    if not did and clean_path.startswith("/devices/"):
        parts = clean_path.strip("/").split("/")
        if len(parts) >= 2:
            did = parts[1]
    pubkey = ctx.device_public_key(did) if did else None
    if pubkey is None:
        # No recovered key -> we cannot forge a valid grant; keep prior behaviour.
        return _build_catchall(ctx, query_params, body_params, clean_path)
    country = (getattr(ctx, "region", "") or "us").upper()
    try:
        payload = build_fw_check_payload(pubkey, country, int(time.time()))
        if clean_path.rstrip("/").endswith("/sh"):
            return {
                "k": payload["k"],
                "d": payload["d"],
                "success": True,
                "code": 200,
                "msg": "success",
                "data": payload,
                "result": payload,
            }
        return payload
    except Exception:
        return _build_catchall(ctx, query_params, body_params, clean_path)
