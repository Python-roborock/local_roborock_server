import asyncio
import json
import urllib.parse
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor, resolve_route


def _build_supervisor(tmp_path: Path) -> ReleaseSupervisor:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    return ReleaseSupervisor(config=config, paths=paths)


def _source_from_proxied_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.parse_qs(parsed.query).get("src", [""])[0]


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
        source = _source_from_proxied_url(url)
        assert source.startswith("https://")


def test_plugin_endpoints_prefer_cloud_snapshot_catalogs(tmp_path: Path) -> None:
    supervisor = _build_supervisor(tmp_path)
    snapshot = {
        "web_api_cache": {
            "plugin_catalogs": {
                "plugins": {
                    "data": {
                        "categoryPluginList": [
                            {
                                "categoryId": 99,
                                "category": "robot.vacuum.cleaner",
                                "version": 9999,
                                "apiLevel": 10043,
                                "url": "https://files.roborock.com/iot/plugin/cloud-category.zip",
                                "pluginLevel": 1,
                            }
                        ]
                    }
                },
                "appfeatureplugin": {
                    "data": {
                        "plugins": [
                            {
                                "moduleType": "PERSONAL_CENTER",
                                "version": 999,
                                "apiLevel": 10043,
                                "url": "https://app-files.roborock.com/iot/plugin/cloud-feature.zip",
                                "pluginLevel": 3002,
                                "scope": "cloud",
                            }
                        ]
                    }
                },
                "appplugin": {
                    "data": [
                        {
                            "version": 8888,
                            "url": "https://rrpkg-us.roborock.com/iot/plugin/cloud-product.zip",
                            "pluginLevel": 3001,
                            "productid": 110,
                            "apilevel": 10043,
                        }
                    ]
                },
            }
        }
    }
    supervisor.paths.cloud_snapshot_path.write_text(json.dumps(snapshot) + "\n", encoding="utf-8")
    client = TestClient(supervisor.app)

    category_payload = client.get("/api/v1/plugins").json()
    category_record = category_payload["data"]["categoryPluginList"][0]
    assert category_record["version"] == 9999
    assert _source_from_proxied_url(category_record["url"]) == "https://files.roborock.com/iot/plugin/cloud-category.zip"

    feature_payload = client.get("/api/v1/appfeatureplugin").json()
    feature_record = feature_payload["data"]["plugins"][0]
    assert feature_record["version"] == 999
    assert _source_from_proxied_url(feature_record["url"]) == "https://app-files.roborock.com/iot/plugin/cloud-feature.zip"

    app_plugin_payload = client.get("/api/v1/appplugin").json()
    app_plugin_record = app_plugin_payload["data"][0]
    assert app_plugin_record["version"] == 8888
    assert _source_from_proxied_url(app_plugin_record["url"]) == "https://rrpkg-us.roborock.com/iot/plugin/cloud-product.zip"


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


class _FakePluginResponse:
    def __init__(self, payload: bytes) -> None:
        self.status = 200
        self.headers = {"Content-Type": "application/zip"}
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc) -> None:
        return None

    async def read(self) -> bytes:
        return self._payload


def _fake_client_session(payload: bytes):
    class _FakeClientSession:
        def __init__(self, *args, **kwargs) -> None:
            _ = args, kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc) -> None:
            return None

        def get(self, *_args, **_kwargs) -> _FakePluginResponse:
            return _FakePluginResponse(payload)

    return _FakeClientSession


def test_download_plugin_zip_accepts_large_device_plugin(monkeypatch) -> None:
    from https_server.routes.plugin import common as plugin_common

    # Real device plugins have grown past the former 32 MB limit (~55 MB seen).
    payload = b"\0" * (55 * 1024 * 1024)
    monkeypatch.setattr(plugin_common.aiohttp, "ClientSession", _fake_client_session(payload))

    data, content_type = asyncio.run(plugin_common.download_plugin_zip("https://files.roborock.com/plugin.zip"))

    assert len(data) == len(payload)
    assert content_type == "application/zip"


def test_download_plugin_zip_still_rejects_oversized_payload(monkeypatch) -> None:
    from https_server.routes.plugin import common as plugin_common

    monkeypatch.setattr(plugin_common, "PLUGIN_PROXY_MAX_BYTES", 1024)
    monkeypatch.setattr(plugin_common.aiohttp, "ClientSession", _fake_client_session(b"\0" * 1025))

    with pytest.raises(RuntimeError, match="plugin too large"):
        asyncio.run(plugin_common.download_plugin_zip("https://files.roborock.com/plugin.zip"))


def _write_app_plugin_snapshot(supervisor: ReleaseSupervisor, catalogs: dict) -> None:
    snapshot = {"web_api_cache": {"plugin_catalogs": catalogs}}
    supervisor.paths.cloud_snapshot_path.write_text(json.dumps(snapshot) + "\n", encoding="utf-8")


def _app_plugin_catalog(url: str) -> dict:
    return {"data": [{"version": 6846, "url": url, "pluginLevel": 3002, "productid": 199, "apilevel": 10030}]}


ANDROID_ZIP = "https://app-files.roborock.com/iot/plugin/android.zip"
IOS_ZIP = "https://app-files.roborock.com/iot/plugin/ios.zip"


@pytest.mark.parametrize(("app_type", "expected"), [(1, IOS_ZIP), (2, ANDROID_ZIP)])
def test_app_plugin_answers_per_platform_type(tmp_path: Path, app_type: int, expected: str) -> None:
    # The cloud serves a different zip for the same plugin version to iOS (type 1)
    # and Android (type 2); the iOS app cannot load the Android one.
    supervisor = _build_supervisor(tmp_path)
    _write_app_plugin_snapshot(
        supervisor,
        {"appplugin": _app_plugin_catalog(ANDROID_ZIP), "appplugin_ios": _app_plugin_catalog(IOS_ZIP)},
    )
    client = TestClient(supervisor.app)

    response = client.post("/api/v1/appplugin", json={"type": app_type, "apilevel": "40740", "productids": [199]})

    [record] = response.json()["data"]
    assert _source_from_proxied_url(record["url"]) == expected


def test_app_plugin_ios_falls_back_to_android_catalog_from_older_imports(tmp_path: Path) -> None:
    supervisor = _build_supervisor(tmp_path)
    _write_app_plugin_snapshot(supervisor, {"appplugin": _app_plugin_catalog(ANDROID_ZIP)})
    client = TestClient(supervisor.app)

    response = client.post("/api/v1/appplugin", json={"type": 1, "productids": [199]})

    [record] = response.json()["data"]
    assert _source_from_proxied_url(record["url"]) == ANDROID_ZIP
