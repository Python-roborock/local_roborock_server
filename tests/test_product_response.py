import json
from pathlib import Path

import pytest

from roborock_local_server.backend import (
    ServerContext,
    default_endpoint_rules,
    resolve_route,
)


class _PairedRuntimeCredentials:
    """Treat every inventory device as paired so home_payload keeps it."""

    def resolve_device(self, *, duid: str = "", **_kwargs):
        return {"did": f"did-{duid}", "device_mqtt_usr": "mqtt-user"}

    def __getattr__(self, _name):
        return lambda *args, **kwargs: None


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
        runtime_credentials=_PairedRuntimeCredentials(),
    )


def _products_v5(tmp_path: Path, devices: list[dict[str, object]]) -> dict:
    (tmp_path / "web_api_inventory.json").write_text(
        json.dumps({"home": {"id": 424242, "name": "Test Home"}, "devices": devices}) + "\n",
        encoding="utf-8",
    )
    route, payload = resolve_route(
        rules=default_endpoint_rules(),
        context=_make_context(tmp_path),
        clean_path="/api/v5/product",
        query_params={},
        body_params={},
        method="GET",
    )
    assert route == "get_products_v5"
    return payload["data"]


_DEVICE = {
    "duid": "device-a",
    "name": "Vacuum A",
    "model": "roborock.vacuum.a15",
    "product_id": "iot-product-a",
}


def test_product_entry_carries_rriotid_category_id_and_agreements(tmp_path: Path) -> None:
    data = _products_v5(tmp_path, [_DEVICE])

    [category_detail] = data["categoryDetailList"]
    category = category_detail["category"]
    [product] = category_detail["productList"]

    # Product.rriotid is what the app joins the home data device's productId on.
    assert product["rriotid"] == "iot-product-a"
    assert product["categoryId"] == category["id"]
    assert product["agreements"] == []


def test_product_category_carries_code(tmp_path: Path) -> None:
    data = _products_v5(tmp_path, [_DEVICE])

    category = data["categoryDetailList"][0]["category"]

    assert category["code"] == "robot.vacuum.cleaner"
    assert category["displayName"] == "robot.vacuum.cleaner"


def test_product_rriotid_matches_home_data_device_product_id(tmp_path: Path) -> None:
    from roborock_local_server.bundled_backend.https_server.routes.user.homes.service import home_payload

    data = _products_v5(tmp_path, [_DEVICE])
    home = home_payload(_make_context(tmp_path))

    device_product_ids = {device["productId"] for device in home["devices"]}
    rriotids = {
        product["rriotid"]
        for category_detail in data["categoryDetailList"]
        for product in category_detail["productList"]
    }
    assert device_product_ids == rriotids


def test_product_picture_fields_use_app_json_names(tmp_path: Path) -> None:
    device = dict(_DEVICE, iconUrl="https://images.example.com/vacuum.png")

    data = _products_v5(tmp_path, [device])

    [product] = data["categoryDetailList"][0]["productList"]
    # Product$$serializer only knows the lower-case names picurl/cardpicurl.
    assert product["picurl"] == "https://images.example.com/vacuum.png"
    assert product["cardpicurl"] == "https://images.example.com/vacuum.png"
    assert "cardPicUrl" not in product


def test_string_product_id_uses_cloud_numeric_id_by_model(tmp_path: Path) -> None:
    # The cloud lists newer models (e.g. a226) under a string product id in home
    # data. The numeric id the app requests plugins with comes from the cloud's
    # /api/v5/product, which the import stores in the snapshot.
    snapshot = {
        "web_api_cache": {
            "plugin_catalogs": {
                "product": {
                    "data": {
                        "categoryDetailList": [
                            {
                                "category": {"id": 1, "code": "robot.vacuum.cleaner"},
                                "productList": [{"id": 199, "model": "roborock.vacuum.a226"}],
                            }
                        ]
                    }
                }
            }
        }
    }
    (tmp_path / "web_api_inventory_full_snapshot.json").write_text(json.dumps(snapshot), encoding="utf-8")
    device = dict(_DEVICE, model="roborock.vacuum.a226", product_id="30uADinyLKa3Qpga60B1Ke")

    data = _products_v5(tmp_path, [device])

    [product] = data["categoryDetailList"][0]["productList"]
    assert product["id"] == 199
    assert product["rriotid"] == "30uADinyLKa3Qpga60B1Ke"


@pytest.mark.parametrize(
    ("model", "rriotid", "expected_id"),
    [
        # The rriotids are the ones in product_catalog.json, which onboarding stores.
        ("roborock.vacuum.a307", "4J89YHjAc2uUG9W0HLxKPP", 263),
        ("roborock.vacuum.a87", "5gUei3OIJIXVD3eD85Balg", 103),
        ("roborock.vacuum.a15", "1YYW18rpgyAJTISwb1NM91", 23),
        ("roborock.vacuum.sc05", "5ayEx3aKgStqZZ0v5IpMBP", 10001),
        ("roborock.wdv.a194", "MUKZV1YH7JkqlXXjJnO64", 180),
    ],
)
def test_product_uses_built_in_cloud_product_id(tmp_path: Path, model: str, rriotid: str, expected_id: int) -> None:
    device = dict(_DEVICE, model=model, product_id=rriotid)

    data = _products_v5(tmp_path, [device])

    [product] = data["categoryDetailList"][0]["productList"]
    # The app requests the device plugin with this id.
    assert product["id"] == expected_id
    assert product["rriotid"] == rriotid


def test_product_of_unknown_model_keeps_hashed_id(tmp_path: Path) -> None:
    from shared.data_helpers import stable_int

    device = dict(_DEVICE, model="roborock.vacuum.zz99", product_id="iot-product-z")

    data = _products_v5(tmp_path, [device])

    [product] = data["categoryDetailList"][0]["productList"]
    assert product["id"] == stable_int("iot-product-z") % 1_000_000


def test_numeric_inventory_product_id_wins_over_built_in_id(tmp_path: Path) -> None:
    device = dict(_DEVICE, model="roborock.vacuum.a307", product_id="4242")

    data = _products_v5(tmp_path, [device])

    [product] = data["categoryDetailList"][0]["productList"]
    assert product["id"] == 4242


def _write_cloud_products(tmp_path: Path, products: dict[str, int]) -> None:
    # The import stores the cloud's /api/v5/product answer in the snapshot.
    product_list = [{"id": product_id, "model": model} for model, product_id in products.items()]
    catalog = {"data": {"categoryDetailList": [{"category": {"id": 1}, "productList": product_list}]}}
    snapshot = {"web_api_cache": {"plugin_catalogs": {"product": catalog}}}
    (tmp_path / "web_api_inventory_full_snapshot.json").write_text(json.dumps(snapshot), encoding="utf-8")


@pytest.mark.parametrize(
    ("model", "rriotid", "import_id"),
    [
        # The built-in ids come from the EU cloud: 185 for the a199 and 103 for the a87.
        ("roborock.vacuum.a199", "3PWf17rt73QjM3F1DaZelu", 199),
        ("roborock.vacuum.a87", "5gUei3OIJIXVD3eD85Balg", 110),
        # A hardcoded 110 for the a87 used to win over the import.
        ("roborock.vacuum.a87", "5gUei3OIJIXVD3eD85Balg", 103),
        # The import also wins over a numeric id in home data.
        ("roborock.vacuum.a307", "4242", 263),
    ],
)
def test_cloud_import_product_id_wins_over_built_in_id(
    tmp_path: Path, model: str, rriotid: str, import_id: int
) -> None:
    # Product ids differ by cloud region, so the account's own import decides.
    _write_cloud_products(tmp_path, {model: import_id})
    device = dict(_DEVICE, model=model, product_id=rriotid)

    data = _products_v5(tmp_path, [device])

    [product] = data["categoryDetailList"][0]["productList"]
    assert product["id"] == import_id


def test_model_missing_from_cloud_import_gets_built_in_id(tmp_path: Path) -> None:
    _write_cloud_products(tmp_path, {"roborock.vacuum.a226": 199})
    device = dict(_DEVICE, model="roborock.vacuum.a307", product_id="4J89YHjAc2uUG9W0HLxKPP")

    data = _products_v5(tmp_path, [device])

    [product] = data["categoryDetailList"][0]["productList"]
    assert product["id"] == 263


def test_app_gets_a307_plugin_without_cloud_import(tmp_path: Path) -> None:
    import urllib.parse

    from https_server.routes.plugin.common import APPPLUGIN_LIST

    device = dict(_DEVICE, model="roborock.vacuum.a307", product_id="4J89YHjAc2uUG9W0HLxKPP")
    [product] = _products_v5(tmp_path, [device])["categoryDetailList"][0]["productList"]
    # The app requests its device plugin with the product id from /api/v5/product.
    body = {"apilevel": 10046, "productids": [product["id"]], "type": 2}
    route, payload = resolve_route(
        rules=default_endpoint_rules(),
        context=_make_context(tmp_path),
        clean_path="/api/v1/appplugin",
        query_params={},
        body_params={"__json": [json.dumps(body)]},
        method="POST",
    )

    assert product["id"] == 263
    assert route == "download_code"
    [record] = payload["data"]
    [a307_record] = [item for item in APPPLUGIN_LIST if item["productid"] == 263]
    assert record["productid"] == 263
    assert record["version"] == a307_record["version"]
    assert urllib.parse.parse_qs(urllib.parse.urlsplit(record["url"]).query)["src"] == [a307_record["url"]]
