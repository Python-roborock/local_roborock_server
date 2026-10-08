"""Experimental Q7 sc05 bootstrap, recovered from firmware 03.01.74.

This implements the HMAC request branch and AES response format. The alternate
4096-bit RSA request branch and live device compatibility are not yet verified.
Device secrets must be explicitly imported into state/b01_devices.json.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import parse_qs

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def canonical_path(path: str) -> str | None:
    """Called after stripping the injected /.roborock.com prefix."""
    return path if path in ("/b/region", "/b/nc") else None


def request_signature(
    secret: str, path: str, params: bytes, nonce: str, timestamp: str
) -> str:
    """Firmware 0x19e70..0x19f0e: MD5 path/params, then HMAC-SHA256."""
    material = (
        f"{nonce}:{timestamp}:{hashlib.md5(path.encode()).hexdigest()}:"
        f"{hashlib.md5(params).hexdigest()}:"
    )
    return base64.b64encode(
        hmac.new(
            secret.encode("ascii"), material.encode("ascii"), hashlib.sha256
        ).digest()
    ).decode("ascii")


def encrypt_result(secret: str, nonce: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Firmware 0x1a00a/0x1a4d0: ASCII slices, not hex-decoded bytes."""
    secret_bytes = secret.encode("ascii")
    if not 24 <= len(secret_bytes) <= 64:
        raise ValueError("B01 device secret must contain 24 to 64 ASCII bytes")
    iv = hashlib.md5(nonce.encode("ascii")).hexdigest()[12:28].encode("ascii")
    plaintext = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode(
        "ascii"
    )
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(secret_bytes[8:24]), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return {"code": 200, "result": base64.b64encode(ciphertext).decode("ascii")}


def mqtt_credentials(
    duid: str, localkey: str, session: str, token: str
) -> dict[str, str]:
    """Firmware 0x1a5d8..0x1a70a; distinct from the V1 MQTT derivation."""
    if not (
        1 <= len(duid.encode("ascii")) <= 32 and len(localkey.encode("ascii")) == 16
    ):
        raise ValueError(
            "B01 requires a DUID of at most 32 bytes and a 16-byte local key"
        )
    if not (
        6 <= len(session.encode("ascii")) <= 64
        and 8 <= len(token.encode("ascii")) <= 64
    ):
        raise ValueError("B01 activation session/token lengths are invalid")
    digest = hashlib.sha256(
        f"{duid}:{session[1:5]}:{localkey[3:11]}".encode("ascii")
    ).hexdigest()
    # The firmware copies six bytes at token+3 even for an eight-byte token.
    token_slice = (token.encode("ascii") + b"\0")[3:9]
    pass_digest = hashlib.sha256(
        session[2:6].encode("ascii")
        + b":"
        + token_slice
        + b":"
        + localkey[9:15].encode("ascii")
    ).hexdigest()
    return {
        "client_id": digest[11:27],
        "username": digest[27:43],
        "password": hashlib.md5(pass_digest[21:53].encode("ascii")).hexdigest(),
    }


def build_response(
    *,
    ctx: Any,
    state_file: Path,
    path: str,
    method: str,
    query: str,
    body: bytes,
    headers: Mapping[str, str],
) -> tuple[str, int, dict[str, Any]]:
    """Explicitly opted-in HMAC bootstrap; authenticate before storing credentials."""

    def error(status: int, message: str) -> tuple[str, int, dict[str, Any]]:
        return "b01_bootstrap_error", status, {"code": status, "msg": message}

    if path not in ("/b/region", "/b/nc"):
        return error(404, "unknown_b01_bootstrap_path")
    expected_method = "GET" if path == "/b/region" else "POST"
    if method != expected_method:
        return error(405, "b01_bootstrap_method_not_allowed")
    # The firmware signs the exact query for region, and exact form body for NC.
    try:
        wire = query.encode("ascii") if method == "GET" else body
        params = parse_qs(
            wire.decode("ascii"), keep_blank_values=True, strict_parsing=True
        )
        required = {"d", "m", "r", "s", "t"}
        if path == "/b/nc":
            required |= {"n", "p", "scheme"}
        if not required.issubset(params) or any(
            len(v) != 1 or not v[0] for v in params.values()
        ):
            return error(400, "invalid_b01_bootstrap_parameters")
        did, model = params["d"][0], params["m"][0]
        if model != "roborock.vacuum.sc05":
            return error(400, "b01_model_not_validated")
        if path == "/b/nc" and (params["p"][0] != "B01" or params["scheme"][0] != "1"):
            return error(400, "unsupported_b01_nc_scheme")
        state = json.loads(state_file.read_text(encoding="utf-8"))
        device = state["devices"][did]
        secret, duid = device["secret"], device["duid"]
        if (
            device.get("model") != model
            or not isinstance(secret, str)
            or not isinstance(duid, str)
        ):
            return error(503, "invalid_b01_device_configuration")
        if (
            not 24 <= len(secret.encode("ascii")) <= 64
            or not 1 <= len(duid.encode("ascii")) <= 32
        ):
            return error(503, "invalid_b01_device_configuration")
    except (OSError, KeyError):
        return error(503, "b01_device_secret_required")
    except (ValueError, TypeError, AttributeError):
        return error(400, "invalid_b01_bootstrap_input")

    if headers.get("v", "").lower() == "v2":
        return error(501, "b01_rsa_request_branch_not_implemented")
    nonce, ts, sign = (
        headers.get("nonce", ""),
        headers.get("ts", ""),
        headers.get("sign", ""),
    )
    if not re.fullmatch(r"[0-9a-fA-F]{16}", nonce) or not re.fullmatch(
        r"[0-9]{1,10}", ts
    ):
        return error(401, "b01_nonce_or_timestamp_missing")
    # Do not apply wall-clock freshness: a freshly reset robot may lack correct time.
    expected_sign = request_signature(secret, path, wire, nonce, ts)
    if not hmac.compare_digest(expected_sign.encode(), sign.encode()):
        return error(401, "b01_signature_invalid")

    if path == "/b/region":
        # Use configured endpoints; the unauthenticated Host header cannot redirect them.
        return (
            "region",
            200,
            encrypt_result(
                secret, nonce, {"apiUrl": ctx.api_url(), "mqttUrl": ctx.mqtt_url()}
            ),
        )

    session, token = params["s"][0], params["t"][0]
    try:
        # Validate tokens before resolving or mutating credentials.
        mqtt_credentials(duid, "0123456789abcdef", session, token)
        localkey = ctx.resolve_device_localkey(
            did=did, duid=duid, model=model, source="b01_nc"
        )
        mqtt = mqtt_credentials(duid, localkey, session, token)
    except (ValueError, UnicodeError):
        return error(400, "invalid_b01_nc_credentials")
    result = encrypt_result(secret, nonce, {"k": localkey, "d": duid})
    if ctx.runtime_credentials is not None:
        ctx.runtime_credentials.ensure_device(
            did=did,
            duid=duid,
            model=model,
            localkey=localkey,
            local_key_source="b01_nc",
            device_mqtt_usr=mqtt["username"],
            device_mqtt_pass=mqtt["password"],
            last_nc_at=datetime.now(timezone.utc).isoformat(),
        )
    return "nc_prepare", 200, result
