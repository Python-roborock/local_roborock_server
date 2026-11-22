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
    # No cloud snapshot: the built-in fallback values.
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


def _write_cloud_product_snapshot(tmp_path: Path, category_details: list[dict]) -> None:
    snapshot = {"web_api_cache": {"plugin_catalogs": {"product": {"data": {"categoryDetailList": category_details}}}}}
    (tmp_path / "web_api_inventory_full_snapshot.json").write_text(json.dumps(snapshot), encoding="utf-8")


# Shape of the cloud's /api/v5/product answer: cardspec is a JSON string with
# the spec in {"data": ...}, the labels in many languages.
_CLOUD_VACUUM_SPEC = {
    "state": {
        "dps": 121,
        "desc": {"en": "State", "de": "Status", "fr": "État"},
        "value": [{"desc": {"en": "Charging", "de": "Wird geladen", "fr": "En charge"}, "value": [8]}],
    },
    "battery": {"dps": 122},
}
_CLOUD_VACUUM_CARD_SPEC = json.dumps({"data": _CLOUD_VACUUM_SPEC}, ensure_ascii=False)
_CLOUD_SCENE_TAG = {"name": "scene_2.0", "requirePlugin": False, "pluginLevel": 1234, "forceShow": True}
_CLOUD_OTHER_TAG = {"name": "other_tag", "requirePlugin": False, "pluginLevel": 0, "forceShow": False}


def test_cloud_snapshot_product_tags_and_card_spec_win(tmp_path: Path) -> None:
    _write_cloud_product_snapshot(
        tmp_path,
        [
            {
                "category": {"id": 7, "code": "robot.vacuum.cleaner", "cardspec": _CLOUD_VACUUM_CARD_SPEC},
                "productList": [
                    {"id": 101, "model": "roborock.vacuum.a15", "productTags": [_CLOUD_SCENE_TAG, _CLOUD_OTHER_TAG]}
                ],
            }
        ],
    )

    data = _products_v5(tmp_path, [_DEVICE])

    category_detail = data["categoryDetailList"][0]
    [product] = category_detail["productList"]
    # The cloud's tags are passed through unchanged, not the built-in values.
    assert product["productTags"] == [_CLOUD_SCENE_TAG, _CLOUD_OTHER_TAG]
    # The cloud's card spec string is passed through as is, all languages included.
    card_spec = category_detail["category"]["cardspec"]
    assert card_spec == _CLOUD_VACUUM_CARD_SPEC
    charging = json.loads(card_spec)["data"]["state"]["value"][0]["desc"]
    assert charging == {"en": "Charging", "de": "Wird geladen", "fr": "En charge"}


def test_cloud_snapshot_without_scene_tag_is_respected(tmp_path: Path) -> None:
    # The cloud lists the model but sends no scene_2.0 tag: none is added.
    _write_cloud_product_snapshot(
        tmp_path,
        [
            {
                "category": {"id": 7, "code": "robot.vacuum.cleaner", "cardspec": _CLOUD_VACUUM_CARD_SPEC},
                "productList": [{"id": 101, "model": "roborock.vacuum.a15", "productTags": []}],
            }
        ],
    )

    data = _products_v5(tmp_path, [_DEVICE])

    [product] = data["categoryDetailList"][0]["productList"]
    assert product["productTags"] == []


def test_model_missing_from_cloud_snapshot_uses_fallback(tmp_path: Path) -> None:
    # Snapshot without an entry for this model and with an empty category
    # cardspec (some bundles default it to ''): built-in values as fallback.
    _write_cloud_product_snapshot(
        tmp_path,
        [
            {
                "category": {"id": 7, "code": "robot.vacuum.cleaner", "cardspec": ""},
                "productList": [{"id": 199, "model": "roborock.vacuum.a226", "productTags": [_CLOUD_OTHER_TAG]}],
            }
        ],
    )

    data = _products_v5(tmp_path, [_DEVICE])

    category_detail = data["categoryDetailList"][0]
    [product] = category_detail["productList"]
    assert product["productTags"] == [
        {"name": "scene_2.0", "requirePlugin": True, "pluginLevel": 3000, "forceShow": True}
    ]
    card_spec = json.loads(category_detail["category"]["cardspec"])["data"]
    assert card_spec["state"]["dps"] == 121
    assert _labels(card_spec["state"])[8] == "Charging"


_MOWER = dict(
    _DEVICE,
    duid="device-m",
    name="Mower",
    model="roborock.mower.m1",
    product_id="iot-product-m",
    category="roborock.mower",
)


def test_non_vacuum_category_gets_no_fallback_scene_tag(tmp_path: Path) -> None:
    data = _products_v5(tmp_path, [_DEVICE, _MOWER])

    by_category = {entry["category"]["code"]: entry for entry in data["categoryDetailList"]}
    [vacuum] = by_category["robot.vacuum.cleaner"]["productList"]
    [mower] = by_category["roborock.mower"]["productList"]
    assert [tag["name"] for tag in vacuum["productTags"]] == ["scene_2.0"]
    assert mower["productTags"] == []
    assert "cardspec" not in by_category["roborock.mower"]["category"]


def test_non_vacuum_category_takes_scene_tag_and_card_spec_from_cloud(tmp_path: Path) -> None:
    mower_spec = json.dumps({"data": {"state": {"dps": 201, "desc": {"en": "State"}, "value": []}}})
    _write_cloud_product_snapshot(
        tmp_path,
        [
            {
                "category": {"id": 9, "code": "roborock.mower", "cardspec": mower_spec},
                "productList": [{"id": 301, "model": "roborock.mower.m1", "productTags": [_CLOUD_SCENE_TAG]}],
            }
        ],
    )

    data = _products_v5(tmp_path, [_MOWER])

    category_detail = data["categoryDetailList"][0]
    [mower] = category_detail["productList"]
    assert mower["productTags"] == [_CLOUD_SCENE_TAG]
    assert category_detail["category"]["cardspec"] == mower_spec
