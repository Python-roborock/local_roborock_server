"""Native state converges across clients without treating a sent command as success."""

import asyncio
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import roborock_local_server.backend  # noqa: F401 (makes bundled shared modules importable)

from shared import native_schedule_sync as sync
from shared import schedule_store as store


def job(enabled=True, *, job_id=701, name="native-1", repeated=True):
    return {
        "id": job_id, "enabled": enabled, "repeated": repeated, "cron": "0 9 * * *",
        "timeZoneId": "America/Los_Angeles", "future": {"keep": [1, 2]},
        "param": {"method": "server_scheduled_start", "params": [{
            "name": name, "segments": "16,18", "map_index": 2, "future": {"keep": True},
        }]},
    }


class NativeStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "web_api_inventory.json"
        self.context = SimpleNamespace(http_jsonl=self.path.parent / "http.jsonl")
        self.seed([job()])

    def seed(self, jobs, claims=None):
        self.path.write_text(json.dumps({
            "schedules": {"robot": jobs, "other": [job()]},
            "schedule_occurrences": {"robot": claims or {}}, "keep": {"metadata": 1},
        }))

    def test_reconciles_both_directions_and_preserves_identity_settings_and_other_devices(self):
        for enabled in (False, True):
            before = json.loads(self.path.read_text())
            snapshot = store.list_jobs(self.context, "robot")
            self.assertEqual(store.reconcile_native_enabled(self.context, "robot", snapshot, {"native-1": enabled}), [701])
            before["schedules"]["robot"][0]["enabled"] = enabled
            self.assertEqual(json.loads(self.path.read_text()), before)

    def test_noop_does_not_write_inventory(self):
        with patch.object(store, "write_inventory", side_effect=AssertionError("unnecessary write")):
            self.assertEqual(store.reconcile_native_enabled(self.context, "robot", [job()], {"native-1": True}), [])

    def test_stale_read_cannot_overwrite_job_edited_while_reading_robot(self):
        snapshot = store.list_jobs(self.context, "robot")
        changed = job()
        changed["cron"] = "30 9 * * *"
        self.seed([changed])
        self.assertEqual(store.reconcile_native_enabled(self.context, "robot", snapshot, {"native-1": False}), [])
        self.assertEqual(store.list_jobs(self.context, "robot"), [changed])

    def test_deleted_job_is_not_recreated(self):
        snapshot = store.list_jobs(self.context, "robot")
        self.seed([])
        self.assertEqual(store.reconcile_native_enabled(self.context, "robot", snapshot, {"native-1": False}), [])
        self.assertEqual(store.list_jobs(self.context, "robot"), [])

    def test_duplicate_timer_or_job_ids_are_never_guessed(self):
        for jobs in ([job(), job(job_id=702)], [job(), job(name="native-2")]):
            self.seed(jobs)
            self.assertEqual(store.reconcile_native_enabled(self.context, "robot", jobs, {"native-1": False}), [])
            self.assertEqual(store.list_jobs(self.context, "robot"), jobs)

    def test_missing_and_malformed_timer_entries_do_not_disable_jobs(self):
        for timers in ([], [["native-1", "bad"]], [["native-1", "off"], ["native-1", "on"]], [["native-1"]]):
            states = sync.timer_states(timers)
            self.assertEqual(store.reconcile_native_enabled(self.context, "robot", [job()], states), [])

    def test_serialized_and_object_params_keep_their_original_form(self):
        for serialized in (False, True):
            original = job()
            if serialized:
                original["param"] = json.dumps(original["param"])
            else:
                original["param"]["params"] = original["param"]["params"][0]
            self.seed([original])
            self.assertEqual(store.reconcile_native_enabled(self.context, "robot", [original], {"native-1": False}), [701])
            self.assertEqual(store.list_jobs(self.context, "robot")[0]["param"], original["param"])

    def test_consumed_one_time_job_is_not_resurrected_by_periodic_read(self):
        original = job(False, repeated=False)
        self.seed([original], {"701": 12345})
        self.assertEqual(store.reconcile_native_enabled(self.context, "robot", [original], {"native-1": True}), [])
        self.assertEqual(store.reconcile_native_enabled(
            self.context, "robot", [original], {"native-1": True}, explicit_enable={"native-1": 12345},
        ), [701])
        self.assertEqual(json.loads(self.path.read_text())["schedule_occurrences"], {"robot": {"701": 12345}})

    def test_earlier_enable_intent_does_not_resurrect_a_newly_consumed_occurrence(self):
        original = job(False, repeated=False)
        self.seed([original], {"701": 23456})
        self.assertEqual(store.reconcile_native_enabled(
            self.context, "robot", [original], {"native-1": True}, explicit_enable={"native-1": 12345},
        ), [])

    def test_unlinked_server_only_jobs_are_unchanged(self):
        original = job()
        del original["param"]["params"][0]["name"]
        self.seed([original])
        self.assertEqual(store.reconcile_native_enabled(self.context, "robot", [original], {"701": False}), [])

    def test_persistence_failure_does_not_lose_inventory(self):
        before = self.path.read_bytes()
        with patch.object(store, "write_inventory", return_value=False):
            with self.assertRaises(OSError):
                store.reconcile_native_enabled(self.context, "robot", [job()], {"native-1": False})
        self.assertEqual(self.path.read_bytes(), before)


class NativeCoordinatorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "web_api_inventory.json"
        self.path.write_text(json.dumps({"schedules": {"robot": [job()]}}))
        self.context = SimpleNamespace(
            http_jsonl=self.path.parent / "http.jsonl",
            runtime_credentials=SimpleNamespace(resolve_device=lambda **kw: {"duid": "robot", "localkey": "test"}),
        )
        self.coordinator = sync.NativeScheduleSync(self.context)
        self.robot = SimpleNamespace(timers=[["native-1", "off"]], calls=[], after_read=None, write_error=None, apply=True)
        robot = self.robot

        class Client:
            def __init__(self, *args):
                pass

            async def connect(self):
                robot.calls.append("connect")

            async def send_command(self, command, params):
                robot.calls.append(str(command))
                if command == "get_server_timer":
                    result = copy.deepcopy(robot.timers)
                    if robot.after_read:
                        await robot.after_read()
                    return result
                if robot.apply:
                    robot.timers[0][1] = params[0][1]
                if robot.write_error:
                    raise robot.write_error
                return ["ok"]

            async def close(self):
                robot.calls.append("close")

        self.network = patch.dict("sys.modules", {"shared.routine_runner": SimpleNamespace(_RoutineMqttClient=Client)})
        self.network.start()
        self.addCleanup(self.network.stop)

    async def test_external_toggle_reconciliation_reads_only_and_closes_connection(self):
        self.assertEqual(await self.coordinator.refresh("robot"), [701])
        self.assertFalse(store.list_jobs(self.context, "robot")[0]["enabled"])
        self.assertEqual(self.robot.calls, ["connect", "get_server_timer", "close"])

    async def test_later_native_write_invalidates_an_in_flight_read(self):
        async def later():
            self.coordinator.changed("robot")
            self.robot.timers[0][1] = "on"
        self.robot.after_read = later
        self.assertEqual(await self.coordinator.refresh("robot"), [])
        self.assertTrue(store.list_jobs(self.context, "robot")[0]["enabled"])
        self.robot.after_read = None
        self.assertEqual(await self.coordinator.refresh("robot"), [])

    async def test_dashboard_or_http_edit_lock_prevents_background_race(self):
        async with self.coordinator.lock("robot"):
            pending = asyncio.create_task(self.coordinator.refresh("robot"))
            await asyncio.sleep(0)
            self.assertEqual(self.robot.calls, [])
            self.assertFalse(pending.done())
        self.assertEqual(await pending, [701])

    async def test_lost_write_ack_requires_a_fresh_matching_read(self):
        self.robot.write_error = TimeoutError()
        self.assertEqual(await sync.sync_timer(self.context, "robot", "native-1", True, check_current=lambda: None), "on")
        self.assertEqual(self.robot.calls.count("upd_server_timer"), 1)
        self.assertEqual(self.robot.calls.count("get_server_timer"), 2)

    async def test_unapplied_write_is_not_success(self):
        self.robot.apply = False
        with self.assertRaises(sync.TimerSyncError):
            await sync.sync_timer(self.context, "robot", "native-1", True, check_current=lambda: None)
        self.assertEqual(self.robot.calls.count("upd_server_timer"), 1)

    async def test_matching_timer_needs_no_second_write(self):
        self.assertEqual(await sync.sync_timer(self.context, "robot", "native-1", False, check_current=lambda: None), "off")
        self.assertNotIn("upd_server_timer", self.robot.calls)

    async def test_startup_and_periodic_reads_recover_changes_without_observed_requests(self):
        self.coordinator.INTERVAL = 0.02
        self.coordinator.DEBOUNCE = 0
        stop = asyncio.Event()
        task = asyncio.create_task(self.coordinator.run(stop))
        try:
            for enabled in (False, True):
                self.robot.timers[0][1] = "on" if enabled else "off"
                async with asyncio.timeout(1):
                    while store.list_jobs(self.context, "robot")[0]["enabled"] != enabled:
                        await asyncio.sleep(0.001)
        finally:
            stop.set()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self.assertNotIn("upd_server_timer", self.robot.calls)

    async def test_cancellation_closes_an_in_flight_read(self):
        waiting = asyncio.Event()
        async def pause():
            waiting.set()
            await asyncio.Event().wait()
        self.robot.after_read = pause
        task = asyncio.create_task(self.coordinator.refresh("robot"))
        await waiting.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.robot.calls[-1], "close")


if __name__ == "__main__":
    unittest.main()
