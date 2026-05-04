import urllib.parse
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor, resolve_route


def _build_supervisor(tmp_path: Path) -> ReleaseSupervisor:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    return ReleaseSupervisor(config=config, paths=paths)


def test_api_v1_plugins_returns_proxied_category_urls(tmp_path: Path) -> None:
    supervisor = _build_supervisor(tmp_path)
    client = TestClient(supervisor.app)

    response = client.get("/api/v1/plugins")
    assert response.status_code == 200

    payload = response.json()
    assert payload["code"] == 200
    records = payload["data"]["categoryPluginList"]
    assert isinstance(records, list)
    assert records

    for item in records:
        url = str(item["url"])
        assert url.startswith("https://api-roborock.example.com/plugin/proxy/")
        parsed = urllib.parse.urlsplit(url)
        source = urllib.parse.parse_qs(parsed.query).get("src", [""])[0]
        assert source.startswith("https://")


def test_app_plugin_endpoints_return_proxied_urls(tmp_path: Path) -> None:
    supervisor = _build_supervisor(tmp_path)
    client = TestClient(supervisor.app)

    app_plugin_response = client.get("/api/v1/appplugin")
    assert app_plugin_response.status_code == 200
    app_plugin_payload = app_plugin_response.json()
    assert app_plugin_payload["code"] == 200
    for item in app_plugin_payload["data"]:
        assert str(item["url"]).startswith("https://api-roborock.example.com/plugin/proxy/")

    feature_response = client.get("/api/v1/appfeatureplugin")
    assert feature_response.status_code == 200
    feature_payload = feature_response.json()
    assert feature_payload["code"] == 200
    for item in feature_payload["data"]["plugins"]:
        assert str(item["url"]).startswith("https://api-roborock.example.com/plugin/proxy/")


def test_plugin_category_zip_uses_expected_source_and_cache(tmp_path: Path, monkeypatch) -> None:
    from https_server.routes.plugin import common as plugin_common

    supervisor = _build_supervisor(tmp_path)
    client = TestClient(supervisor.app)
    downloaded_sources: list[str] = []

    async def fake_download(source_url: str) -> tuple[bytes, str]:
        downloaded_sources.append(source_url)
        return b"fake-zip-bytes", "application/zip"

    monkeypatch.setattr(plugin_common, "download_plugin_zip", fake_download)

    expected_source = plugin_common.LEGACY_CATEGORY_PLUGIN_SOURCES["robot_vacuum_cleaner"]
    first = client.get("/plugin/category/robot_vacuum_cleaner.zip")
    assert first.status_code == 200
    assert first.content == b"fake-zip-bytes"
    assert first.headers["X-RR-Plugin-Cache"] == "miss"
    assert downloaded_sources == [expected_source]

    second = client.get("/plugin/category/robot_vacuum_cleaner.zip")
    assert second.status_code == 200
    assert second.content == b"fake-zip-bytes"
    assert second.headers["X-RR-Plugin-Cache"] == "hit"
    assert downloaded_sources == [expected_source]


def test_plugin_proxy_rejects_non_https_and_unknown_hosts(tmp_path: Path, monkeypatch) -> None:
    from https_server.routes.plugin import common as plugin_common

    supervisor = _build_supervisor(tmp_path)
    client = TestClient(supervisor.app)

    async def fail_download(source_url: str) -> tuple[bytes, str]:
        raise AssertionError(f"download should not be called for {source_url}")

    monkeypatch.setattr(plugin_common, "download_plugin_zip", fail_download)

    blocked_sources = (
        "http://files.roborock.com/iot/plugin/blocked.zip",
        "https://example.com/iot/plugin/blocked.zip",
    )
    for source in blocked_sources:
        encoded = urllib.parse.quote(source, safe="")
        response = client.get(f"/plugin/proxy/blocked.zip?src={encoded}")
        assert response.status_code == 200
        payload = response.json()
        assert payload["success"] is True
        assert payload["data"]["route"] == "/plugin/proxy/blocked.zip"


def test_non_plugin_routes_still_resolve_to_same_handlers(tmp_path: Path) -> None:
    supervisor = _build_supervisor(tmp_path)
    route_name, payload = resolve_route(
        rules=supervisor.endpoint_rules,
        context=supervisor.context,
        clean_path="/api/v1/userInfo",
        query_params={},
        body_params={},
        method="GET",
    )
    assert route_name == "user_info"
    assert payload["code"] == 200

