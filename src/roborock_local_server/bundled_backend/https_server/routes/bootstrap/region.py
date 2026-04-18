from __future__ import annotations

import json
from typing import Any

from shared.context import split_host_port
from shared.context import ServerContext
from shared.http_helpers import wrap_response

from .service import request_host_override

_RSA_OAEP_SHA1_MAX_PLAINTEXT = 214


def match(path: str) -> bool:
    return path.rstrip("/") in ("", "/region", "/api/region", "/b/region", "/api/b/region")


def build(
    ctx: ServerContext,
    query_params: dict[str, list[str]],
    body_params: dict[str, list[str]],
    _clean_path: str,
) -> dict[str, Any]:
    did = ctx.extract_did(query_params, body_params)
    host_override = request_host_override(query_params)
    override_host, override_port = split_host_port(host_override)
    api_host = override_host or ctx.api_host
    mqtt_host = override_host or ctx.mqtt_host
    api_url = ctx.api_url(host=api_host, port=override_port if override_host else None)
    mqtt_url = ctx.mqtt_url(host=mqtt_host)
    region_payload = {
        "apiUrl": api_url,
        "mqttUrl": mqtt_url,
        "api_url": api_url,
        "mqtt_url": mqtt_url,
    }
    # Keep encrypted bootstrap payload within a single RSA-OAEP block for firmware compatibility.
    if len(json.dumps(region_payload, ensure_ascii=True, separators=(",", ":"))) > _RSA_OAEP_SHA1_MAX_PLAINTEXT:
        region_payload = {"apiUrl": api_url, "mqttUrl": mqtt_url}
    encrypted = ctx.encrypt_bootstrap_result(did, region_payload)
    if encrypted is not None:
        return encrypted
    return wrap_response(region_payload)

