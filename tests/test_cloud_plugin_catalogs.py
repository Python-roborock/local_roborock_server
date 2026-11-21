import asyncio
from typing import Any

from roborock.data import HomeData

import roborock_local_server.backend  # noqa: F401  (puts the bundled backend on sys.path)
import import_web_inventory_from_cloud as importer


CLOUD_PRODUCTS = {
    "categoryDetailList": [
        {
            "category": {"id": 1, "code": "robot.vacuum.cleaner"},
            "productList": [{"id": 199, "model": "roborock.vacuum.a226"}],
        }
    ]
}


def _home_data() -> HomeData:
    # Home data lists newer models under a string product id on both the product
    # and the device.
    return HomeData.from_dict(
        {
            "id": 1,
            "name": "Home",
            "products": [{"id": "30uADinyLKa3Qpga60B1Ke", "name": "Qrevo Curv 2 Pro", "model": "roborock.vacuum.a226", "category": "robot.vacuum.cleaner"}],
            "devices": [{"duid": "duid-1", "name": "Vacuum", "productId": "30uADinyLKa3Qpga60B1Ke", "localKey": "key"}],
        }
    )


def test_plugin_catalogs_resolve_string_product_ids_and_fetch_both_platforms(monkeypatch) -> None:
    requests: list[tuple[str, dict[str, Any] | None]] = []

    async def fake_request(_api, _user_data, path, *, method="get", params=None, json_body=None):
        requests.append((path, json_body))
        if path == "/api/v5/product":
            return CLOUD_PRODUCTS
        if path == "/api/v1/appplugin":
            return [{"productid": 199, "url": f"https://app-files.roborock.com/iot/plugin/type{json_body['type']}.zip"}]
        return {}

    monkeypatch.setattr(importer, "_request_cloud_api_data", fake_request)

    catalogs = asyncio.run(importer._fetch_plugin_catalogs(None, None, _home_data()))

    assert catalogs["product"]["data"] == CLOUD_PRODUCTS
    app_plugin_bodies = [body for path, body in requests if path == "/api/v1/appplugin"]
    assert sorted(body["type"] for body in app_plugin_bodies) == [1, 2]
    assert all(body["productids"] == [199] for body in app_plugin_bodies)
    assert catalogs["appplugin"]["data"][0]["url"].endswith("/type2.zip")
    assert catalogs["appplugin_ios"]["data"][0]["url"].endswith("/type1.zip")
