"""Room bindings must use segment IDs from the same loaded map, never cloud IDs."""

import copy
import json
import unittest

from roborock_local_server.admin_schedule_settings import (
    RoomCatalogError, build_room_catalog, merge_settings, schedule_param,
    segment_ids, setting_choices, validate_rooms,
)


class ScheduleSettingsTests(unittest.TestCase):
    def setUp(self):
        self.inventory = {"home": {"rooms": [{"id": 90000000000000001, "name": "Kitchen"}, {"id": "cloud-b", "name": "Hall"}]}}
        self.maps = [{"map_info": [{"mapFlag": 1, "name": "Downstairs"}, {"mapFlag": 2, "name": "Upstairs"}]}]
        self.mapping = [[16, "90000000000000001"], [18, "cloud-b", 0], [21, "unknown"]]
        self.job = {"param": {"method": "server_scheduled_start", "id": 1, "params": [{
            "name": "native-timer", "map_index": 1, "segments": "16,18", "fan_power": 102,
            "water_box_mode": 202, "mop_mode": 300, "repeat": 1, "future": {"keep": True},
        }]}}

    def catalog(self, **kwargs):
        return build_room_catalog(**{
            "before": [{"map_status": 7}], "after": {"map_status": 7}, "maps": self.maps,
            "mapping": self.mapping, "inventory": self.inventory, **kwargs,
        })

    def test_names_join_cloud_room_ids_without_losing_integer_precision(self):
        catalog = self.catalog()
        self.assertEqual(catalog["map_index"], 1)
        self.assertEqual(catalog["rooms"], [
            {"id": 16, "room_id": "90000000000000001", "name": "Kitchen"},
            {"id": 18, "room_id": "cloud-b", "name": "Hall"},
            {"id": 21, "room_id": "unknown", "name": "Room 21"},
        ])
        self.assertEqual(catalog["revision"], self.catalog(mapping=list(reversed(self.mapping)))["revision"])

    def test_map_change_no_map_and_unsaved_map_are_rejected(self):
        for status in (11, 4, 252, 255, -1, None, True, "7"):
            with self.subTest(status=status), self.assertRaises(RoomCatalogError):
                self.catalog(after={"map_status": status})

    def test_ambiguous_and_malformed_room_lists_are_rejected(self):
        for mapping in (None, {}, [[16, "a"], [16, "b"]], [[False, "b"]], [[0, "b"]], [[300, "b"]], [[16]]):
            with self.subTest(mapping=mapping), self.assertRaises(RoomCatalogError):
                self.catalog(mapping=mapping)

    def test_room_rename_or_id_change_invalidates_revision(self):
        old = self.catalog()
        self.inventory["home"]["rooms"][0]["name"] = "Dining"
        new = self.catalog()
        self.assertNotEqual(old["revision"], new["revision"])
        with self.assertRaises(RoomCatalogError):
            validate_rooms(self.job["param"], new, old["revision"])

    def test_changed_map_or_missing_room_cannot_be_saved(self):
        catalog = self.catalog()
        for changes in ({"map_index": 2}, {"segments": "99"}):
            param, needs_rooms = merge_settings(self.job, changes)
            self.assertTrue(needs_rooms)
            with self.assertRaises(RoomCatalogError):
                validate_rooms(param, catalog, catalog["revision"])
        validate_rooms(self.job["param"], catalog, catalog["revision"])

    def test_full_map_does_not_need_room_bindings_but_requires_a_saved_map(self):
        catalog = self.catalog()
        param, _ = merge_settings(self.job, {"map_index": 2, "segments": "0"})
        validate_rooms(param, catalog, catalog["revision"])
        param["params"][0]["map_index"] = 9
        with self.assertRaises(RoomCatalogError):
            validate_rooms(param, catalog, catalog["revision"])

    def test_edit_preserves_native_identity_unknown_fields_and_original(self):
        before = copy.deepcopy(self.job)
        param, needs_rooms = merge_settings(self.job, {"segments": [18, 21], "fan_power": 103, "repeat": 2})
        self.assertTrue(needs_rooms)
        self.assertEqual(param["params"][0]["segments"], "18,21")
        self.assertEqual(param["params"][0]["name"], "native-timer")
        self.assertEqual(param["params"][0]["future"], {"keep": True})
        self.assertEqual(self.job, before)
        self.assertFalse(merge_settings(self.job, {"water_box_mode": 200})[1])

    def test_custom_values_are_preserved_without_offering_unrelated_model_modes(self):
        self.job["param"]["params"][0]["fan_power"] = 987
        options = setting_choices(self.job["param"]["params"][0])["fan_power"]
        self.assertEqual(options[-1], {"value": 987, "label": "Saved custom option (987)"})
        self.assertEqual(merge_settings(self.job, {"fan_power": 987})[0], self.job["param"])
        for changes in ({"fan_power": 108}, {"fan_power": "102"}, {"repeat": True}, {"repeat": 0}, {"repeat": 4}, {"name": "different"}, {}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                merge_settings(self.job, changes)

    def test_whole_home_and_room_selection_validation(self):
        self.assertEqual(segment_ids("0"), [])
        self.assertEqual(segment_ids("16; 18"), [16, 18])
        for value in ([], "", True, [0, 16], [16, 16], [False], [256], "16,nope"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                segment_ids(value)
        param, _ = merge_settings(self.job, {"segments": "0"})
        catalog = self.catalog()
        validate_rooms(param, catalog, catalog["revision"])

    def test_string_payloads_supported_but_legacy_multi_action_and_unknown_formats_read_only(self):
        original = copy.deepcopy(self.job["param"])
        self.job["param"] = json.dumps(original)
        self.assertEqual(schedule_param(self.job), original)
        original["params"][0].pop("name")
        self.assertIsNone(schedule_param({"param": original}))
        for param in (None, "invalid", {"method": "other", "params": [{}]}, {"method": "server_scheduled_start", "params": [{}, {}]}):
            self.assertIsNone(schedule_param({"param": param}))


if __name__ == "__main__":
    unittest.main()
