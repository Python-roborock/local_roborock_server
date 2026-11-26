import argparse
import asyncio
import json
import types
from pathlib import Path
from typing import Any

import pytest

import scripts.refresh_device_plugin_catalog as refresh
from scripts.refresh_device_plugin_catalog import (
    build_catalog,
    catalog_path,
    catalog_region,
    fetch_cloud_answers,
    write_catalog,
)

CLOUD_PRODUCTS = {
    "categoryDetailList": [
        {
            "category": {"id": 1, "code": "robot.vacuum.cleaner"},
            "productList": [
                {"id": 263, "model": "roborock.vacuum.a307", "name": "Saros 20 Flow", "rriotid": "rriot-a307"},
                {"id": 23, "model": "roborock.vacuum.a15", "name": "S7", "rriotid": "rriot-a15"},
            ],
        },
        {
            "category": {"id": 9, "code": "roborock.mowbs"},
            "productList": [{"id": 314, "model": "roborock.mowbs.a355", "name": "WiFi Amplifier Charging Station"}],
        },
    ]
}

CLOUD_RECORDS = [
    {"version": 7046, "url": "https://app-files.roborock.com/iot/plugin/a307.zip", "pluginLevel": 3002, "productid": 263, "apilevel": 10030},
    {"version": 5208, "url": "https://app-files.roborock.com/iot/plugin/a15.zip", "pluginLevel": 3001, "productid": 23, "apilevel": 10028},
]


def test_refresh_requests_all_product_ids_and_sorts_the_catalog() -> None:
    requests: list[tuple[str, str, dict[str, Any] | None]] = []

    async def fake_call(path: str, *, method: str = "get", json_body: dict[str, Any] | None = None) -> Any:
        requests.append((path, method, json_body))
        return CLOUD_PRODUCTS if path == "/api/v5/product" else CLOUD_RECORDS

    products, records = asyncio.run(fetch_cloud_answers(fake_call))
    catalog = build_catalog(
        products,
        records,
        base_url="https://euiot.roborock.com",
        region="eu",
        fetched_at_utc="2026-11-21T00:00:00+00:00",
    )

    # The app sends this body; one request covers every product.
    assert requests[1] == (
        "/api/v1/appplugin",
        "post",
        {"type": 2, "apilevel": 10046, "productids": [23, 263, 314]},
    )
    assert list(catalog["products"]) == ["roborock.mowbs.a355", "roborock.vacuum.a15", "roborock.vacuum.a307"]
    assert catalog["products"]["roborock.vacuum.a307"] == {
        "id": 263,
        "name": "Saros 20 Flow",
        "category": "robot.vacuum.cleaner",
    }
    assert [record["productid"] for record in catalog["appplugin"]] == [23, 263]
    assert catalog["source"]["base_url"] == "https://euiot.roborock.com"
    assert catalog["source"]["region"] == "eu"
    # The catalog in the checkout has the same source keys as a new one.
    eu_catalog = json.loads(catalog_path("eu").read_text(encoding="utf-8"))
    assert list(eu_catalog["source"]) == list(catalog["source"])
    assert catalog["source"]["fetched_at_utc"] == "2026-11-21T00:00:00+00:00"


def test_stored_login_of_raw_user_data_takes_the_email_as_username(tmp_path: Path, monkeypatch) -> None:
    clients: list[tuple[str, str | None]] = []

    class FakeApiClient:
        def __init__(self, *, username: str, base_url: str | None, session: Any) -> None:
            clients.append((username, base_url))

    monkeypatch.setattr(refresh, "RoborockApiClient", FakeApiClient)
    monkeypatch.setattr(refresh, "UserData", types.SimpleNamespace(from_dict=lambda data: data))
    # Raw user data, as the app stores it, has no username.
    source = tmp_path / "raw-user-data.json"
    source.write_text(json.dumps({"uid": 1, "rruid": "rr-user"}), encoding="utf-8")
    args = argparse.Namespace(source_json=source, email="user@example.com", base_url="https://euiot.roborock.com")

    _api, user_data = asyncio.run(refresh._login(args, session=None))

    assert clients == [("user@example.com", "https://euiot.roborock.com")]
    assert user_data == {"uid": 1, "rruid": "rr-user"}


@pytest.mark.parametrize(
    ("base_url", "region", "expected"),
    [
        ("https://euiot.roborock.com", None, "eu"),
        ("https://usiot.roborock.com", None, "us"),
        ("https://cniot.roborock.com", None, "cn"),
        ("https://ruiot.roborock.com", None, "ru"),
        ("https://usiot.roborock.com", "us", "us"),
        ("https://newiot.roborock.com", "sg", "sg"),
    ],
)
def test_catalog_region_comes_from_the_cloud_host(base_url: str, region: str | None, expected: str) -> None:
    assert catalog_region(base_url, region) == expected


def test_catalog_region_of_an_unknown_host_needs_the_region_option() -> None:
    with pytest.raises(RuntimeError, match="Pass --region"):
        catalog_region("https://newiot.roborock.com")
    with pytest.raises(RuntimeError, match="does not match"):
        catalog_region("https://euiot.roborock.com", "us")


def test_catalog_path_is_the_file_that_the_server_loads() -> None:
    from shared import device_plugin_catalog

    assert catalog_path("us").name == "device_plugin_catalog_us.json"
    assert catalog_path("eu") == device_plugin_catalog.CATALOG_DIR / "device_plugin_catalog_eu.json"
    assert catalog_path("eu").exists()


@pytest.mark.parametrize("answer", [{"list": []}, [], None, ["not a record"]])
def test_refresh_fails_if_the_cloud_answers_no_plugin_record(answer: Any) -> None:
    async def fake_call(path: str, *, method: str = "get", json_body: dict[str, Any] | None = None) -> Any:
        return CLOUD_PRODUCTS if path == "/api/v5/product" else answer

    with pytest.raises(RuntimeError, match="no plugin record"):
        asyncio.run(fetch_cloud_answers(fake_call))


def test_write_catalog_replaces_the_file_and_leaves_no_temporary_file(tmp_path: Path) -> None:
    path = tmp_path / "device_plugin_catalog_eu.json"
    path.write_text('{"old": true}\n', encoding="utf-8")

    write_catalog(path, {"products": {}, "appplugin": []})

    assert json.loads(path.read_text(encoding="utf-8")) == {"products": {}, "appplugin": []}
    assert [file.name for file in tmp_path.iterdir()] == ["device_plugin_catalog_eu.json"]


def test_failed_write_keeps_the_old_catalog_and_leaves_no_temporary_file(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "device_plugin_catalog_eu.json"
    path.write_text('{"old": true}\n', encoding="utf-8")

    def fail_replace(self: Path, target: Path) -> Path:
        raise OSError("disk full")

    # The .tmp file is complete, and the replace fails.
    monkeypatch.setattr(Path, "replace", fail_replace)
    with pytest.raises(OSError, match="disk full"):
        write_catalog(path, {"products": {}, "appplugin": []})

    assert json.loads(path.read_text(encoding="utf-8")) == {"old": True}
    assert [file.name for file in tmp_path.iterdir()] == ["device_plugin_catalog_eu.json"]
