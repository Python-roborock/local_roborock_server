from pathlib import Path

import pytest

from roborock_local_server.backend import (
    ServerContext,
    default_endpoint_rules,
    resolve_route,
)


def _make_context(tmp_path: Path) -> ServerContext:
    return ServerContext(
        api_host="api.example.com",
        mqtt_host="mqtt.example.com",
        wood_host="wood.example.com",
        region="us",
        protocol_login_email="user@example.com",
        localkey="key123",
        duid="duid-1",
        mqtt_usr="usr",
        mqtt_passwd="pwd",
        mqtt_clientid="cid",
        https_port=443,
        mqtt_tls_port=8883,
        http_jsonl=tmp_path / "http.jsonl",
        mqtt_jsonl=tmp_path / "mqtt.jsonl",
        loggers={},
    )


def _resolve(tmp_path: Path, path: str) -> tuple[str, dict]:
    return resolve_route(
        rules=default_endpoint_rules(),
        context=_make_context(tmp_path),
        clean_path=path,
        query_params={},
        body_params={},
        method="GET",
    )


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/api/v1/activity/latest", {"i": 0, "t": 0}),
        ("/api/v2/activity/current", []),
        ("/api/v1/activity/nps", []),
        ("/api/v1/recommendation/agreement/status", {}),
        ("/api/v1/activity/latest/", {"i": 0, "t": 0}),
    ],
)
def test_catchall_returns_typed_empty_payload_for_known_app_routes(
    tmp_path: Path, path: str, expected: object
) -> None:
    route, payload = _resolve(tmp_path, path)

    assert route == "catchall"
    assert payload["success"] is True
    assert payload["data"] == expected
    assert payload["result"] == expected


def test_catchall_typed_payloads_are_not_shared_between_requests(tmp_path: Path) -> None:
    _, first = _resolve(tmp_path, "/api/v2/activity/current")
    first["data"].append("mutated")

    _, second = _resolve(tmp_path, "/api/v2/activity/current")

    assert second["data"] == []


def test_catchall_keeps_generic_payload_for_unknown_routes(tmp_path: Path) -> None:
    route, payload = _resolve(tmp_path, "/api/v1/some/unknown/route")

    assert route == "catchall"
    assert payload["data"] == {"ok": True, "route": "/api/v1/some/unknown/route"}
