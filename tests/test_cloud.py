from pathlib import Path

from roborock_local_server.backend import _merge_existing_inventory_mutations
from roborock_local_server.cloud import _to_jsonable


class _FakeSchema:
    def __init__(self, payload):
        self._payload = payload

    def as_dict(self):
        return self._payload


def test_to_jsonable_converts_nested_schema_objects() -> None:
    raw = {
        "root": _FakeSchema(
            {
                "child": _FakeSchema({"name": "vacuum"}),
                "items": [_FakeSchema({"id": 1}), Path("/tmp/test")],
            }
        )
    }

    converted = _to_jsonable(raw)

    assert converted == {
        "root": {
            "child": {"name": "vacuum"},
            "items": [{"id": 1}, str(Path("/tmp/test"))],
        }
    }


def test_cloud_inventory_merge_preserves_local_rooms_and_scenes() -> None:
    cloud_inventory = {
        "home": {"id": 123, "name": "Cloud Home", "rooms": [{"id": 1, "name": "Living"}]},
        "rooms": [{"id": 1, "name": "Living"}, {"id": 2, "name": "Kitchen"}],
        "devices": [{"duid": "cloud-device", "name": "Vacuum"}],
        "scenes": [{"id": 10, "name": "Cloud routine"}, {"id": 20, "name": "Cloud-only routine"}],
        "home_scenes": [{"id": 10, "name": "Cloud routine"}, {"id": 20, "name": "Cloud-only routine"}],
        "scene_order": [10, 20],
    }
    existing_inventory = {
        "home": {"id": 123, "name": "Old Home", "rooms": [{"id": 1, "name": "Living local"}]},
        "rooms": [{"id": 1, "name": "Living local"}, {"id": 9, "name": "Office"}],
        "devices": [{"duid": "old-device", "name": "Old Vacuum"}],
        "scenes": [{"id": 10, "name": "Renamed routine"}, {"id": 90, "name": "Local-only routine"}],
        "home_scenes": [{"id": 10, "name": "Renamed routine"}, {"id": 90, "name": "Local-only routine"}],
        "scene_order": [90, 10],
    }

    merged = _merge_existing_inventory_mutations(cloud_inventory, existing_inventory)

    assert merged["devices"] == [{"duid": "cloud-device", "name": "Vacuum"}]
    assert merged["rooms"] == [
        {"id": 1, "name": "Living local"},
        {"id": 2, "name": "Kitchen"},
        {"id": 9, "name": "Office"},
    ]
    assert merged["home"]["rooms"] == merged["rooms"]
    assert merged["scenes"] == [
        {"id": 10, "name": "Renamed routine"},
        {"id": 20, "name": "Cloud-only routine"},
        {"id": 90, "name": "Local-only routine"},
    ]
    assert merged["home_scenes"] == [
        {"id": 10, "name": "Renamed routine"},
        {"id": 20, "name": "Cloud-only routine"},
        {"id": 90, "name": "Local-only routine"},
    ]
    assert merged["scene_order"] == [90, 10, 20]
