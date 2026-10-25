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


def test_product_entry_enables_scene_tiles(tmp_path: Path) -> None:
    data = _products_v5(tmp_path, [_DEVICE])

    category_detail = data["categoryDetailList"][0]
    [product] = category_detail["productList"]
    category = category_detail["category"]

    # ProductEntity.sceneProduct() looks up exactly this tag.
    assert {"name": "scene_2.0", "forceShow": True, "pluginLevel": 0, "requirePlugin": False} in product[
        "productTags"
    ]
    # CardSpecV2 holds the four data points directly, without a "data" wrapper.
    for key in ("cardspec", "cardSpec"):
        card_spec = category[key]
        assert set(card_spec) == {"state", "extra", "battery", "offline"}
        assert card_spec["state"]["dps"] == 121
        assert card_spec["battery"]["dps"] == 122
        assert card_spec["extra"]["dps"] == 128
        assert card_spec["offline"]["dps"] == 135
        for entry in card_spec["state"]["value"]:
            assert set(entry) == {"desc", "value"}
            assert entry["desc"]["en"]
            assert all(isinstance(code, int) for code in entry["value"])


def test_card_spec_is_not_shared_between_responses(tmp_path: Path) -> None:
    first = _products_v5(tmp_path, [_DEVICE])
    first["categoryDetailList"][0]["category"]["cardSpec"]["state"]["value"].clear()

    second = _products_v5(tmp_path, [_DEVICE])

    assert second["categoryDetailList"][0]["category"]["cardSpec"]["state"]["value"]


def test_unknown_category_has_no_card_spec(tmp_path: Path) -> None:
    device = dict(_DEVICE, category="other.category")

    data = _products_v5(tmp_path, [device])

    category = data["categoryDetailList"][0]["category"]
    assert category["displayName"] == "other.category"
    assert "cardSpec" not in category
    assert "cardspec" not in category
