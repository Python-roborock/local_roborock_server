"""Tests for the local ``.../fwapi/createca`` TURN route -- issue #18.

When a TURN server is configured the route answers the robot's camera TURN request
with a plain-JSON credential body; when it is not, the request falls through to the
catchall so behaviour is unchanged.
"""

from __future__ import annotations

import logging

# Importing the backend bridge puts the bundled_backend dir on sys.path so the
# bare ``shared`` / ``https_server`` imports inside the route modules resolve.
import roborock_local_server.backend as backend  # noqa: E402
from shared.context import ServerContext  # noqa: E402


def _make_context(tmp_path, *, turn_enabled: bool):
    return ServerContext(
        api_host="api.example.com",
        mqtt_host="mqtt.example.com",
        wood_host="wood.example.com",
        region="us",
        protocol_login_email="user@example.com",
        localkey="0123456789abcdef",
        duid="1234567890",
        mqtt_usr="mqtt_usr",
        mqtt_passwd="mqtt_passwd",
        mqtt_clientid="mqtt_clientid",
        https_port=443,
        mqtt_tls_port=8883,
        http_jsonl=tmp_path / "http.jsonl",
        mqtt_jsonl=tmp_path / "mqtt.jsonl",
        loggers={"real_stack": logging.getLogger("test.real_stack")},
        turn_enabled=turn_enabled,
        turn_host="192.168.1.10",
        turn_port=3478,
        turn_username="rrturn",
        turn_password="s3cret",
        turn_realm="rrgui.v6.rocks",
        turn_ttl=86400,
    )


def _resolve(ctx, path):
    return backend.resolve_route(
        rules=backend.default_endpoint_rules(),
        context=ctx,
        clean_path=path,
        query_params={},
        body_params={"did": ["1234567890"]},
        method="POST",
    )


def test_createca_returns_turn_payload_when_enabled(tmp_path):
    ctx = _make_context(tmp_path, turn_enabled=True)

    route_name, payload = _resolve(ctx, "/iot.roborock.com/fwapi/createca")

    assert route_name == "fw_createca"
    assert payload["code"] == 200
    assert payload["msg"] == "success"
    data = payload["data"]
    assert data["url"] == "turn:192.168.1.10:3478"
    assert data["user"] == "rrturn" and data["pwd"] == "s3cret"
    # ICE-style aliases also present for the firmware's alternate parser.
    assert data["username"] == "rrturn" and data["credential"] == "s3cret"
    assert data["realm"] == "rrgui.v6.rocks"
    assert data["ttl"] == 86400
    assert "stun:192.168.1.10:3478" in data["urls"]
    # ``result`` mirrors ``data``.
    assert payload["result"] == data


def test_createca_matches_common_path_variants(tmp_path):
    ctx = _make_context(tmp_path, turn_enabled=True)
    for path in (
        "/iot.roborock.com/fwapi/createca",
        "/fwapi/createca",
        "/api/iot.roborock.com/fwapi/createca",
        "/iot.roborock.com/fwapi/createca/",
    ):
        route_name, payload = _resolve(ctx, path)
        assert route_name == "fw_createca", path
        assert payload["code"] == 200, path


def test_createca_falls_back_to_catchall_when_disabled(tmp_path):
    ctx = _make_context(tmp_path, turn_enabled=False)

    route_name, payload = _resolve(ctx, "/iot.roborock.com/fwapi/createca")

    # Route still matches, but with TURN disabled it must not emit credentials;
    # it falls back to the previous catchall response instead.
    assert route_name == "fw_createca"
    assert "data" not in payload or "url" not in payload.get("data", {})
