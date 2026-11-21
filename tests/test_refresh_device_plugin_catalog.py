import asyncio
from typing import Any

from scripts.refresh_device_plugin_catalog import build_catalog, fetch_cloud_answers

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
    assert catalog["source"]["fetched_at_utc"] == "2026-11-21T00:00:00+00:00"
