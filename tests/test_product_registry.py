from __future__ import annotations

from roborock_local_server.bundled_backend.shared.constants import DEFAULT_PRODUCT_SCHEMA
from roborock_local_server.product_registry import BUILTIN_PRODUCT_REGISTRY, resolve_product_metadata


def test_builtin_catalog_contains_only_robot_vacuums() -> None:
    assert len(BUILTIN_PRODUCT_REGISTRY) > 40
    for model, entry in BUILTIN_PRODUCT_REGISTRY.items():
        assert model.startswith("roborock.vacuum."), model
        assert entry["category"] == "robot.vacuum.cleaner"
        assert entry["product_id"]
        assert entry["product_name"].startswith("Roborock ")
    # Washers (e.g. Zeo One) are not handled by this server.
    assert "roborock.vacuum.a102" not in BUILTIN_PRODUCT_REGISTRY


def test_resolve_known_model_uses_cloud_catalog_ids() -> None:
    meta = resolve_product_metadata("roborock.vacuum.a87")
    assert meta["product_name"] == "Roborock Qrevo MaxV"
    assert meta["product_id"] == "5gUei3OIJIXVD3eD85Balg"
    assert meta["schema"] == DEFAULT_PRODUCT_SCHEMA

    assert resolve_product_metadata("a15")["product_id"] == "1YYW18rpgyAJTISwb1NM91"
    assert resolve_product_metadata("roborock.vacuum.a87", custom_name="Upstairs")["product_name"] == "Upstairs"


def test_resolve_unknown_model_falls_back_to_generic_profile() -> None:
    meta = resolve_product_metadata("roborock.vacuum.zz99")
    assert meta["product_name"] == "Roborock ZZ99"
    assert meta["product_id"] == "zz99"
    assert meta["schema"] == DEFAULT_PRODUCT_SCHEMA
