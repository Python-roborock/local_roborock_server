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


def _pair_devices(supervisor: ReleaseSupervisor, *models: str) -> None:
    # /api/v1/appplugin answers a built-in record only for a product id that
    # /api/v5/product gives to the model of the record. /api/v5/product lists
    # the inventory devices that have paired with the server.
    devices = [
        {"duid": f"duid-{index}", "name": model, "model": model, "product_id": f"rriot-{model}"}
        for index, model in enumerate(models)
    ]
    supervisor.paths.inventory_path.write_text(json.dumps({"devices": devices}) + "\n", encoding="utf-8")
    for device in devices:
        supervisor.runtime_credentials.ensure_device(
            did=f"did-{device['duid']}",
            duid=device["duid"],
            model=device["model"],
            product_id=device["product_id"],
        )


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


def _app_plugin_product_ids(payload: dict) -> list[int]:
    assert payload["code"] == 200
    return [item["productid"] for item in payload["data"]]


def test_app_plugin_answers_only_requested_product_ids(tmp_path: Path) -> None:
    supervisor = _build_supervisor(tmp_path)
    _pair_devices(supervisor, "roborock.vacuum.a15")
    client = TestClient(supervisor.app)

    # The app posts this JSON body and installs the first record it gets back.
    response = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [23], "type": 2})

    assert response.status_code == 200
    assert _app_plugin_product_ids(response.json()) == [23]
    [record] = response.json()["data"]
    assert record["url"].startswith("https://api-roborock.example.com/plugin/proxy/")


def test_app_plugin_reads_product_ids_from_form_body(tmp_path: Path) -> None:
    supervisor = _build_supervisor(tmp_path)
    _pair_devices(supervisor, "roborock.vacuum.a15", "roborock.vacuum.sc05")
    client = TestClient(supervisor.app)

    repeated = client.post("/api/v1/appplugin", data={"type": "2", "productids": ["23", "10001"]})
    joined = client.post("/api/v1/appplugin", data={"type": "2", "productids": "23,10001"})

    assert _app_plugin_product_ids(repeated.json()) == [23, 10001]
    assert _app_plugin_product_ids(joined.json()) == [23, 10001]


def _write_android_app_plugin_snapshot(supervisor: ReleaseSupervisor, records: list[dict]) -> None:
    _write_app_plugin_snapshot(supervisor, {"appplugin": {"data": records}})


_SNAPSHOT_APP_PLUGIN_RECORD = {
    "version": 7777,
    "url": "https://rrpkg-us.roborock.com/iot/plugin/cloud-only.zip",
    "pluginLevel": 3001,
    "productid": 4242,
    "apilevel": 10043,
}

# Run each case once with the built-in list and once with a cloud snapshot catalog.
_APP_PLUGIN_CATALOGS = pytest.mark.parametrize(
    "snapshot_records",
    [None, [_SNAPSHOT_APP_PLUGIN_RECORD]],
    ids=["built_in", "snapshot"],
)


@_APP_PLUGIN_CATALOGS
def test_app_plugin_answers_full_list_without_product_ids(tmp_path: Path, snapshot_records: list[dict] | None) -> None:
    from https_server.routes.plugin import common as plugin_common

    supervisor = _build_supervisor(tmp_path)
    if snapshot_records is not None:
        _write_android_app_plugin_snapshot(supervisor, snapshot_records)
    client = TestClient(supervisor.app)
    full_list = [record["productid"] for record in snapshot_records or plugin_common.APPPLUGIN_LIST]

    no_body = client.post("/api/v1/appplugin")
    no_ids = client.post("/api/v1/appplugin", json={"apilevel": 10046, "type": 2})
    empty_ids = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [], "type": 2})

    assert _app_plugin_product_ids(no_body.json()) == full_list
    assert _app_plugin_product_ids(no_ids.json()) == full_list
    assert _app_plugin_product_ids(empty_ids.json()) == full_list


@_APP_PLUGIN_CATALOGS
def test_app_plugin_answers_no_plugin_for_unmatched_product_ids(
    tmp_path: Path, snapshot_records: list[dict] | None
) -> None:
    supervisor = _build_supervisor(tmp_path)
    if snapshot_records is not None:
        _write_android_app_plugin_snapshot(supervisor, snapshot_records)
    client = TestClient(supervisor.app)

    # The app would install the first record of a full list, which is the plugin of another model.
    unknown_id = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [659231], "type": 2})
    # Ids that are no valid product ids match nothing either.
    invalid_ids = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": ["abc", 0], "type": 2})
    invalid_form_id = client.post("/api/v1/appplugin", data={"productids": "abc"})

    assert _app_plugin_product_ids(unknown_id.json()) == []
    assert _app_plugin_product_ids(invalid_ids.json()) == []
    assert _app_plugin_product_ids(invalid_form_id.json()) == []


def test_app_plugin_filters_cloud_snapshot_catalog(tmp_path: Path) -> None:
    supervisor = _build_supervisor(tmp_path)
    snapshot = {
        "web_api_cache": {
            "plugin_catalogs": {
                "appplugin": {
                    "data": [
                        {
                            "version": 8888,
                            "url": "https://rrpkg-us.roborock.com/iot/plugin/cloud-first.zip",
                            "pluginLevel": 3001,
                            "productid": 110,
                            "apilevel": 10043,
                        },
                        {
                            "version": 7777,
                            "url": "https://rrpkg-us.roborock.com/iot/plugin/cloud-second.zip",
                            "pluginLevel": 3002,
                            "productid": 4242,
                            "apilevel": 10043,
                        },
                    ]
                },
            }
        }
    }
    supervisor.paths.cloud_snapshot_path.write_text(json.dumps(snapshot) + "\n", encoding="utf-8")
    client = TestClient(supervisor.app)

    response = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [4242], "type": 2})

    [record] = response.json()["data"]
    assert record["version"] == 7777
    assert _source_from_proxied_url(record["url"]) == "https://rrpkg-us.roborock.com/iot/plugin/cloud-second.zip"


def test_app_plugin_falls_back_to_built_in_list_for_ids_missing_from_snapshot(tmp_path: Path) -> None:
    from https_server.routes.plugin import common as plugin_common

    supervisor = _build_supervisor(tmp_path)
    # A device added after the snapshot import has no record in the snapshot.
    _write_android_app_plugin_snapshot(supervisor, [_SNAPSHOT_APP_PLUGIN_RECORD])
    _pair_devices(supervisor, "roborock.vacuum.a15")
    client = TestClient(supervisor.app)

    missing = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [23], "type": 2})
    mixed = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [23, 4242], "type": 2})

    [record] = missing.json()["data"]
    [built_in_23] = [item for item in plugin_common.APPPLUGIN_LIST if item["productid"] == 23]
    assert record["productid"] == 23
    assert record["version"] == built_in_23["version"]
    assert _source_from_proxied_url(record["url"]) == built_in_23["url"]
    # Snapshot records come first, built-in records after them.
    assert _app_plugin_product_ids(mixed.json()) == [4242, 23]


def test_app_plugin_prefers_snapshot_record_over_built_in_record(tmp_path: Path) -> None:
    from https_server.routes.plugin import common as plugin_common

    supervisor = _build_supervisor(tmp_path)
    _write_android_app_plugin_snapshot(
        supervisor,
        [
            {
                "version": 9999,
                "url": "https://rrpkg-us.roborock.com/iot/plugin/cloud-23.zip",
                "pluginLevel": 3001,
                "productid": 23,
                "apilevel": 10043,
            }
        ],
    )
    _pair_devices(supervisor, "roborock.vacuum.a15", "roborock.vacuum.sc05")
    client = TestClient(supervisor.app)

    response = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [23, 10001], "type": 2})

    records = response.json()["data"]
    [built_in_10001] = [item for item in plugin_common.APPPLUGIN_LIST if item["productid"] == 10001]
    assert [(item["productid"], item["version"]) for item in records] == [
        (23, 9999),
        (10001, built_in_10001["version"]),
    ]
    assert _source_from_proxied_url(records[0]["url"]) == "https://rrpkg-us.roborock.com/iot/plugin/cloud-23.zip"


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


def _app_plugin_record(product_id: int, url: str) -> dict:
    return {"version": 6846, "url": url, "pluginLevel": 3002, "productid": product_id, "apilevel": 10030}


IOS_ONLY_ZIP = "https://app-files.roborock.com/iot/plugin/ios-only.zip"
ANDROID_ONLY_ZIP = "https://app-files.roborock.com/iot/plugin/android-only.zip"
ANDROID_23_ZIP = "https://app-files.roborock.com/iot/plugin/android-23.zip"


def _ios_app_plugin_client(tmp_path: Path) -> TestClient:
    # Product 199 is in both catalogs, and 300 is only in the iOS catalog. Products 23
    # and 4242 are only in the Android catalog. The built-in list also has 23, which
    # the paired a15 gets.
    supervisor = _build_supervisor(tmp_path)
    _write_app_plugin_snapshot(
        supervisor,
        {
            "appplugin": {
                "data": [
                    _app_plugin_record(199, ANDROID_ZIP),
                    _app_plugin_record(23, ANDROID_23_ZIP),
                    _app_plugin_record(4242, ANDROID_ONLY_ZIP),
                ]
            },
            "appplugin_ios": {"data": [_app_plugin_record(199, IOS_ZIP), _app_plugin_record(300, IOS_ONLY_ZIP)]},
        },
    )
    _pair_devices(supervisor, "roborock.vacuum.a15")
    return TestClient(supervisor.app)


def _app_plugin_sources(payload: dict) -> list[tuple[int, str]]:
    assert payload["code"] == 200
    return [(item["productid"], _source_from_proxied_url(item["url"])) for item in payload["data"]]


def test_app_plugin_ios_answers_requested_ids_from_ios_catalog(tmp_path: Path) -> None:
    client = _ios_app_plugin_client(tmp_path)

    response = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [199], "type": 1})

    assert _app_plugin_sources(response.json()) == [(199, IOS_ZIP)]


def test_app_plugin_ios_ignores_android_catalog_if_ios_catalog_exists(tmp_path: Path) -> None:
    from https_server.routes.plugin import common as plugin_common

    client = _ios_app_plugin_client(tmp_path)
    [built_in_23] = [record for record in plugin_common.APPPLUGIN_LIST if record["productid"] == 23]

    # The iOS catalog replaces the whole Android catalog. So an id that only the
    # Android catalog has gets the built-in record, or nothing.
    android_only = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [4242], "type": 1})
    built_in = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [23], "type": 1})

    assert _app_plugin_sources(android_only.json()) == []
    assert _app_plugin_sources(built_in.json()) == [(23, built_in_23["url"])]


def test_app_plugin_ios_answers_no_plugin_for_unmatched_product_ids(tmp_path: Path) -> None:
    client = _ios_app_plugin_client(tmp_path)

    response = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [659231], "type": 1})

    assert _app_plugin_sources(response.json()) == []


def test_app_plugin_ios_answers_full_ios_catalog_without_product_ids(tmp_path: Path) -> None:
    client = _ios_app_plugin_client(tmp_path)

    no_ids = client.post("/api/v1/appplugin", json={"apilevel": 10046, "type": 1})
    empty_ids = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [], "type": 1})

    assert _app_plugin_sources(no_ids.json()) == [(199, IOS_ZIP), (300, IOS_ONLY_ZIP)]
    assert _app_plugin_sources(empty_ids.json()) == [(199, IOS_ZIP), (300, IOS_ONLY_ZIP)]


@pytest.mark.parametrize(
    ("model", "product_id", "version", "source"),
    [
        # Saros 20 Flow
        ("roborock.vacuum.a307", 263, 7046, "https://app-files.roborock.com/iot/plugin/de0ceb1351854a819a0374fdcbf17831.zip"),
        # Qrevo Curv 2 Pro
        ("roborock.vacuum.a226", 199, 6846, "https://app-files.roborock.com/iot/plugin/69588500d2c54b0bb154a967646dd57b.zip"),
        # F25 Ultra
        ("roborock.wdv.a194", 180, 2674, "https://app-files.roborock.com/iot/plugin/6d5e1e8589e54a1e81351ee54b75eed7.zip"),
        # RockNeo Q1
        ("roborock.mower.a222", 224, 856, "https://app-files.roborock.com/iot/plugin/9dbe90bcb3b343458086800d7f556ab2.zip"),
    ],
)
def test_app_plugin_answers_built_in_record_without_cloud_snapshot(
    tmp_path: Path, model: str, product_id: int, version: int, source: str
) -> None:
    supervisor = _build_supervisor(tmp_path)
    _pair_devices(supervisor, model)
    client = TestClient(supervisor.app)

    response = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [product_id], "type": 2})

    [record] = response.json()["data"]
    assert record["productid"] == product_id
    assert record["version"] == version
    assert _source_from_proxied_url(record["url"]) == source


def test_app_plugin_cloud_snapshot_wins_over_built_in_records(tmp_path: Path) -> None:
    supervisor = _build_supervisor(tmp_path)
    snapshot = {
        "web_api_cache": {
            "plugin_catalogs": {
                "appplugin": {
                    "data": [
                        {
                            "version": 9999,
                            "url": "https://app-files.roborock.com/iot/plugin/cloud-a307.zip",
                            "pluginLevel": 3002,
                            "productid": 263,
                            "apilevel": 10030,
                        }
                    ]
                },
            }
        }
    }
    supervisor.paths.cloud_snapshot_path.write_text(json.dumps(snapshot) + "\n", encoding="utf-8")
    client = TestClient(supervisor.app)

    response = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [263], "type": 2})

    [record] = response.json()["data"]
    assert record["version"] == 9999
    assert _source_from_proxied_url(record["url"]) == "https://app-files.roborock.com/iot/plugin/cloud-a307.zip"



def _cloud_product_catalog(products: dict[str, int]) -> dict:
    product_list = [{"id": product_id, "model": model} for model, product_id in products.items()]
    return {"data": {"categoryDetailList": [{"category": {"id": 1}, "productList": product_list}]}}


@pytest.mark.parametrize(
    ("model", "import_id"),
    [
        # The EU ids 199 and 110 belong to the a226 and the roborock.wm.a91.
        ("roborock.vacuum.a199", 199),
        ("roborock.vacuum.a87", 110),
    ],
)
def test_app_plugin_answers_built_in_record_of_the_model_that_gets_the_id(
    tmp_path: Path, model: str, import_id: int
) -> None:
    from shared.device_plugin_catalog import catalog_for_region

    # The import of another region gives the id to another model than the
    # built-in list. The device was added after the import, so the snapshot
    # has no record for it.
    supervisor = _build_supervisor(tmp_path)
    _write_app_plugin_snapshot(
        supervisor,
        {
            "product": _cloud_product_catalog({model: import_id, "roborock.vacuum.a15": 23}),
            "appplugin": {"data": [_app_plugin_record(23, ANDROID_23_ZIP)]},
        },
    )
    _pair_devices(supervisor, model)
    client = TestClient(supervisor.app)

    response = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [import_id], "type": 2})

    # No catalog of the import's region exists, so the record comes from the EU catalog.
    eu_record = catalog_for_region("eu").records_by_model[model]
    assert _app_plugin_sources(response.json()) == [(import_id, eu_record["url"])]


def test_app_plugin_answers_built_in_record_if_import_ids_agree(tmp_path: Path) -> None:
    from https_server.routes.plugin import common as plugin_common

    # The import gives the a307 the same id as the built-in list. The device
    # was added after the import, so the snapshot has no record for it.
    supervisor = _build_supervisor(tmp_path)
    _write_app_plugin_snapshot(
        supervisor,
        {
            "product": _cloud_product_catalog({"roborock.vacuum.a307": 263, "roborock.vacuum.a226": 199}),
            "appplugin": {"data": [_app_plugin_record(199, ANDROID_ZIP)]},
        },
    )
    _pair_devices(supervisor, "roborock.vacuum.a307")
    client = TestClient(supervisor.app)
    [built_in_263] = [record for record in plugin_common.APPPLUGIN_LIST if record["productid"] == 263]

    response = client.post("/api/v1/appplugin", json={"apilevel": 10046, "productids": [263], "type": 2})

    assert _app_plugin_sources(response.json()) == [(263, built_in_263["url"])]


def test_built_in_plugin_records_match_built_in_products() -> None:
    from https_server.routes.plugin.common import is_allowed_plugin_source
    from shared import device_plugin_catalog

    assert "eu" in device_plugin_catalog.CATALOGS
    for region, catalog in device_plugin_catalog.CATALOGS.items():
        product_ids = list(catalog.product_ids.values())
        record_ids = [record["productid"] for record in catalog.appplugin_records]

        # The app installs the first record for its product id, so each id
        # needs one model and at most one record.
        assert len(product_ids) == len(set(product_ids))
        assert len(record_ids) == len(set(record_ids))
        assert set(record_ids) <= set(product_ids)
        for record in catalog.appplugin_records:
            assert is_allowed_plugin_source(record["url"])
        path = device_plugin_catalog.CATALOG_DIR / f"device_plugin_catalog_{region}.json"
        assert json.loads(path.read_text(encoding="utf-8"))["source"]["region"] == region
