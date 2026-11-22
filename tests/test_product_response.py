import json
from pathlib import Path

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


def _labels(data_point: dict) -> dict[int, str]:
    return {code: entry["desc"]["en"] for entry in data_point["value"] for code in entry["value"]}


def test_product_entry_enables_scene_tiles(tmp_path: Path) -> None:
    data = _products_v5(tmp_path, [_DEVICE])

    category_detail = data["categoryDetailList"][0]
    [product] = category_detail["productList"]
    category = category_detail["category"]

    # ProductEntity.sceneProduct() looks up exactly this tag; values as the cloud sends them.
    assert {"name": "scene_2.0", "requirePlugin": True, "pluginLevel": 3000, "forceShow": True} in product[
        "productTags"
    ]
    # Like the cloud: lower-case "cardspec" on the category, a JSON string
    # holding the spec in a "data" wrapper (decoded by the app as CardSpecV2Data).
    assert "cardSpec" not in category
    assert isinstance(category["cardspec"], str)
    wrapper = json.loads(category["cardspec"])
    assert set(wrapper) == {"data"}
    card_spec = wrapper["data"]
    assert set(card_spec) == {"state", "extra", "battery", "offline", "offpeak"}
    assert card_spec["state"]["dps"] == 121
    assert card_spec["battery"] == {"dps": 122}
    assert card_spec["extra"] == {"dps": 128}
    assert card_spec["offline"]["dps"] == 135
    assert card_spec["offpeak"] == {"dps": 133}
    for data_point in (card_spec["state"], card_spec["offline"]):
        for entry in data_point["value"]:
            assert set(entry) == {"desc", "value"}
            assert entry["desc"]["en"]
            assert all(isinstance(code, int) for code in entry["value"])


def test_vacuum_card_spec_matches_cloud_labels(tmp_path: Path) -> None:
    data = _products_v5(tmp_path, [_DEVICE])

    card_spec = json.loads(data["categoryDetailList"][0]["category"]["cardspec"])["data"]
    states = _labels(card_spec["state"])
    offline = _labels(card_spec["offline"])

    # Wording of the cloud's EU /api/v5/product answer (Nov 2026).
    assert states[6] == "Returning to Dock"
    assert states[15] == "Returning to Dock"
    assert states[9] == "Charging Error"
    assert states[26] == "Going to wash the mop"
    assert offline[1] == "Powered Off Manually"
    # Every state code of the cloud is mapped, plus the extra ones of the
    # template bundled with the app.
    cloud_codes = {2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16, 17, 18, 22, 23, 26, 28, 29, 32}
    extra_codes = {13, 33, 34, 36, 37, 38, 39, 40, 101, 102, 103, 104, 108}
    assert cloud_codes <= set(states)
    assert set(states) == cloud_codes | extra_codes
    assert {1, 34, 51, 103} <= set(offline)


def test_card_spec_only_on_known_categories(tmp_path: Path) -> None:
    other = dict(
        _DEVICE,
        duid="device-b",
        name="Other",
        model="roborock.other.b1",
        product_id="iot-product-b",
        category="other.category",
    )

    data = _products_v5(tmp_path, [_DEVICE, other])

    categories = {entry["category"]["code"]: entry["category"] for entry in data["categoryDetailList"]}
    assert set(categories) == {"robot.vacuum.cleaner", "other.category"}
    assert isinstance(categories["robot.vacuum.cleaner"]["cardspec"], str)
    assert "cardspec" not in categories["other.category"]
    assert "cardSpec" not in categories["other.category"]


def test_unknown_category_has_no_card_spec(tmp_path: Path) -> None:
    device = dict(_DEVICE, category="other.category")

    data = _products_v5(tmp_path, [device])

    category = data["categoryDetailList"][0]["category"]
    assert category["displayName"] == "other.category"
    assert "cardSpec" not in category
    assert "cardspec" not in category
