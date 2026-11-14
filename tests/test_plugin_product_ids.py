"""The product ids sent to the cloud's /api/v1/appplugin catalog during cloud import."""

from __future__ import annotations

from types import SimpleNamespace

# Importing the backend bridge puts the bundled_backend dir on sys.path.
import roborock_local_server.backend  # noqa: F401
from import_web_inventory_from_cloud import (  # noqa: E402
    _numeric_product_ids_by_model,
    _plugin_product_ids,
)

A296_STRING_ID = "3PlD6TMLNY5LwI8kwxntCL"


def _home_data(products: list[tuple[object, str]], device_product_ids: list) -> SimpleNamespace:
    return SimpleNamespace(
        products=[SimpleNamespace(id=pid, model=model) for pid, model in products],
        devices=[SimpleNamespace(product_id=pid) for pid in device_product_ids],
        received_devices=[],
    )


def test_string_product_ids_map_to_the_numeric_id_of_their_model() -> None:
    # A Saros 20 Neo (a296) is listed with a string id only. The catalog answers a string with
    # code 1002 "parameter error", so it has to be sent as the model's numeric id.
    home_data = _home_data([(A296_STRING_ID, "roborock.vacuum.a296")], [A296_STRING_ID])
    assert _plugin_product_ids(home_data, {"roborock.vacuum.a296": 4242}) == [4242]


def test_unmapped_string_ids_are_left_out() -> None:
    home_data = _home_data([(A296_STRING_ID, "roborock.vacuum.a296")], [A296_STRING_ID])
    assert _plugin_product_ids(home_data) == []
    assert _plugin_product_ids(home_data, {"roborock.vacuum.other": 7}) == []


def test_numeric_ids_are_kept_and_sorted() -> None:
    home_data = _home_data([(110, "roborock.vacuum.a87"), ("abc", "roborock.vacuum.a226")], ["20", None, "", "0"])
    assert _plugin_product_ids(home_data, {"roborock.vacuum.a226": 199}) == [20, 110, 199]


def test_numeric_ids_are_read_from_the_product_answer_wherever_they_are_nested() -> None:
    # Shape of the cloud's GET /api/v5/product answer is undocumented; issue #221 shows
    # {"id": 199, "model": "roborock.vacuum.a226", "packagename": "com.roborock.tanos"} in it.
    answer = {
        "categoryDetailList": [
            {"productList": [{"id": 199, "model": "roborock.vacuum.a226", "packagename": "com.roborock.tanos"}]},
            {"productList": [{"id": "4242", "model": "roborock.vacuum.a296"}, {"id": "x", "model": "bad"}]},
        ]
    }
    assert _numeric_product_ids_by_model(answer) == {
        "roborock.vacuum.a226": 199,
        "roborock.vacuum.a296": 4242,
    }
    assert _numeric_product_ids_by_model(None) == {}
