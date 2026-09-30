from pathlib import Path

import pytest

from roborock_local_server.backend import (
    ServerContext,
    default_endpoint_rules,
    resolve_route,
)
from roborock_local_server.bundled_backend.https_server.routes.bootstrap import location
from roborock_local_server.config import _as_timezone


def _make_context(
    tmp_path: Path,
    *,
    region: str = "us",
    timezone: str | None = None,
) -> ServerContext:
    return ServerContext(
        api_host="api.example.com",
        mqtt_host="mqtt.example.com",
        wood_host="wood.example.com",
        region=region,
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
        timezone=timezone,
    )


def test_location_match() -> None:
    assert location.match("/location")
    assert location.match("/api/location")
    assert not location.match("/region")


@pytest.mark.parametrize(
    ("region_input", "expected_country", "expected_timezone"),
    [
        ("eu", "EU", "Europe/Berlin"),
        ("EU", "EU", "Europe/Berlin"),
        ("Eu", "EU", "Europe/Berlin"),
        ("us", "US", "America/New_York"),
        ("US", "US", "America/New_York"),
        ("cn", "CN", "Asia/Shanghai"),
        ("CN", "CN", "Asia/Shanghai"),
        ("ru", "RU", "Europe/Moscow"),
        ("RU", "RU", "Europe/Moscow"),
        ("unknown", "UNKNOWN", "America/New_York"),
        ("", "US", "America/New_York"),
    ],
)
def test_location_build_region_mapping(
    tmp_path: Path,
    region_input: str,
    expected_country: str,
    expected_timezone: str,
) -> None:
    ctx = _make_context(tmp_path, region=region_input)
    response = location.build(ctx, {}, {}, "/location")

    assert response["success"] is True
    assert response["code"] == 200
    assert response["result"] == {
        "country": expected_country,
        "timezone": expected_timezone,
    }


def test_location_build_prefers_explicit_context_timezone(tmp_path: Path) -> None:
    ctx = _make_context(tmp_path, region="eu", timezone="Europe/Paris")
    response = location.build(ctx, {}, {}, "/location")

    assert response["result"]["country"] == "EU"
    assert response["result"]["timezone"] == "Europe/Paris"


def test_config_as_timezone_validation() -> None:
    assert _as_timezone("Europe/Berlin", "network.timezone") == "Europe/Berlin"
    assert _as_timezone("America/New_York", "network.timezone") == "America/New_York"
    assert _as_timezone("UTC", "network.timezone") == "UTC"
    assert _as_timezone("", "network.timezone") == ""
    assert _as_timezone(None, "network.timezone") == ""

    with pytest.raises(ValueError, match="network.timezone must be a valid timezone name"):
        _as_timezone("invalid_timezone", "network.timezone")


def test_location_resolve_route(tmp_path: Path) -> None:
    ctx = _make_context(tmp_path, region="eu")
    route, payload = resolve_route(
        rules=default_endpoint_rules(),
        context=ctx,
        clean_path="/location",
        query_params={},
        body_params={},
        method="GET",
    )

    assert route == "location"
    assert payload["success"] is True
    assert payload["result"] == {"country": "EU", "timezone": "Europe/Berlin"}
