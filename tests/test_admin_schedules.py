"""Dashboard edits preserve native identity and verify room/map bindings."""

import copy
import asyncio
from datetime import datetime
import json
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor
from roborock_local_server import admin_schedules


@pytest.fixture
def timer_robot(monkeypatch):
    from shared import routine_runner

    robot = SimpleNamespace(
        timers=[["native-test-timer", "on", {"keep": "timer-settings"}]], calls=[],
        read_count=0, read_error=None, connect_error=None, write_error=None,
        apply_write=True, after_read=None, after_write=None,
    )

    class Client:
        def __init__(self, context, device, logger):
            assert device["duid"] == "test-vacuum"

        async def connect(self):
            robot.calls.append(("connect", None))
            if robot.connect_error:
                raise robot.connect_error

        async def send_command(self, command, params):
            method = str(command)
            robot.calls.append((method, copy.deepcopy(params)))
            await asyncio.sleep(0)
            if method == "get_server_timer":
                robot.read_count += 1
                if robot.after_read:
                    robot.after_read(robot.read_count)
                if robot.read_error:
                    raise robot.read_error
                return copy.deepcopy(robot.timers)
            assert method == "upd_server_timer"
            if robot.apply_write:
                for timer in robot.timers:
                    if timer[0] == params[0][0]:
                        timer[1] = params[0][1]
            if robot.after_write:
                robot.after_write()
            if robot.write_error:
                raise robot.write_error
            return ["ok"]

        async def close(self):
            robot.calls.append(("close", None))

    monkeypatch.setattr(routine_runner, "_RoutineMqttClient", Client)
    return robot


@pytest.fixture
def schedule_admin(tmp_path, timer_robot):
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    paths.inventory_path.parent.mkdir(parents=True, exist_ok=True)
    native_job = {
        "id": 701, "cron": "15 10 * * 1,3,5", "enabled": True, "repeated": True,
        "timeZoneId": "America/Los_Angeles", "type": "clean", "future_job_field": "preserve-me",
        "param": {"method": "server_scheduled_start", "id": 1, "params": [{
            "name": "native-test-timer", "segments": "16,18", "map_index": 0,
            "fan_power": 102, "mop_mode": 300, "mop_template_id": 4,
            "water_box_mode": 202, "clean_order_mode": 1, "repeat": 1,
            "future_setting": {"preserve": [1, 2, 3]}, "secret": "PRIVATE_SETTING",
        }]},
        "opaque": "PRIVATE_JOB_DATA",
    }
    inventory = {
        "devices": [{"duid": "test-vacuum", "name": "Test downstairs", "model": "roborock.vacuum.a15",
                     "localKey": "PRIVATE_DEVICE_KEY"}],
        "schedules": {"test-vacuum": [native_job]},
        "schedule_occurrences": {"test-vacuum": {"701": {"claimed_at": 12345}}},
    }
    paths.inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    client = TestClient(supervisor.app)
    yield client, supervisor, paths, native_job
    client.close()


def login(client):
    assert client.post("/admin/api/login", json={"password": "correct horse battery staple"}).status_code == 200


def row(client):
    response = client.get("/admin/api/schedules")
    assert response.status_code == 200
    device = next(device for device in response.json()["devices"] if device["duid"] == "test-vacuum")
    return device["schedules"][0]


def patch(client, **fields):
    return client.patch("/admin/api/schedules/test-vacuum/701", json=fields)


def test_schedule_routes_require_admin_session(schedule_admin):
    client, _, paths, _ = schedule_admin
    before = paths.inventory_path.read_bytes()
    assert client.get("/admin/api/schedules").status_code == 401
    assert client.get("/admin/api/schedules/test-vacuum/rooms").status_code == 401
    assert client.post("/admin/api/schedules/test-vacuum/rooms", json={"map_index": 1}).status_code == 401
    assert patch(client, revision="unknown", enabled=False).status_code == 401
    assert paths.inventory_path.read_bytes() == before


def test_friendly_cleaning_edits_preserve_other_native_options(schedule_admin, monkeypatch):
    client, _, paths, original = schedule_admin
    login(client)

    async def no_robot_query(*args):
        raise AssertionError("An unrelated edit must not require an online vacuum")

    monkeypatch.setattr(admin_schedules, "read_room_catalog", no_robot_query)
    assert row(client)["settings_editable"] is True
    response = patch(client, revision=row(client)["revision"], settings={"fan_power": 103, "water_box_mode": 201, "mop_mode": 301, "repeat": 2})
    assert response.status_code == 200
    saved = json.loads(paths.inventory_path.read_text())["schedules"]["test-vacuum"][0]
    expected = copy.deepcopy(original)
    expected["param"]["params"][0].update(fan_power=103, water_box_mode=201, mop_mode=301, repeat=2)
    assert saved == expected


def test_room_api_revalidates_loaded_map_and_revision_before_saving(schedule_admin, monkeypatch):
    client, _, paths, _ = schedule_admin
    login(client)
    catalog = {"revision": "map-0-rooms-v1", "map_index": 0, "maps": [{"id": 0, "name": "Downstairs"}],
               "rooms": [{"id": 16, "name": "Kitchen"}, {"id": 18, "name": "Hall"}]}
    calls = []

    async def read(supervisor, duid):
        calls.append(duid)
        return copy.deepcopy(catalog)

    monkeypatch.setattr(admin_schedules, "read_room_catalog", read)
    response = client.get("/admin/api/schedules/test-vacuum/rooms")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    revision = row(client)["revision"]
    before = paths.inventory_path.read_bytes()
    for room_revision, settings in [(None, {"segments": "16"}), ("old-map", {"segments": "16"}),
                                   (catalog["revision"], {"map_index": 1}), (catalog["revision"], {"segments": "99"})]:
        response = patch(client, revision=revision, room_revision=room_revision, settings=settings)
        assert response.status_code == 409
        assert response.json()["code"] == "room_catalog_changed"
        assert paths.inventory_path.read_bytes() == before
    response = patch(client, revision=revision, room_revision=catalog["revision"], settings={"segments": "18", "map_index": 0})
    assert response.status_code == 200
    assert response.json()["schedule"]["settings"]["segments"] == "18"
    assert calls == ["test-vacuum"] * 6


def test_read_room_catalog_uses_only_selected_robot_and_read_commands(schedule_admin, monkeypatch):
    import asyncio
    from shared import routine_runner
    from roborock_local_server.admin_schedule_settings import read_room_catalog, RoomCatalogError

    _, supervisor, _, _ = schedule_admin
    calls = []
    replies = [[{"map_status": 3}], {"map_info": [{"mapFlag": 0, "name": "Downstairs"}]}, [[16, "cloud-room"]], [{"map_status": 3}]]

    class Client:
        def __init__(self, context, device, logger):
            assert device["duid"] == "test-vacuum"

        async def connect(self):
            calls.append("connect")

        async def send_command(self, command, params):
            assert params == []
            calls.append(str(command))
            if not replies:
                raise TimeoutError("PRIVATE_CONNECTION_DETAIL")
            return replies.pop(0)

        async def close(self):
            calls.append("close")

    monkeypatch.setattr(routine_runner, "_RoutineMqttClient", Client)
    result = asyncio.run(read_room_catalog(supervisor, "test-vacuum"))
    assert result["rooms"][0]["id"] == 16
    assert calls == ["connect", "get_status", "get_multi_maps_list", "get_room_mapping", "get_status", "close"]
    with pytest.raises(RoomCatalogError, match="Could not read rooms") as error:
        asyncio.run(read_room_catalog(supervisor, "test-vacuum"))
    assert "PRIVATE_CONNECTION_DETAIL" not in str(error.value)
    assert calls[-1] == "close"
    with pytest.raises(KeyError):
        asyncio.run(read_room_catalog(supervisor, "other-vacuum"))


@pytest.mark.parametrize("state,in_cleaning,allowed", [(3, 0, True), (8, 0, True), (100, 0, True), (5, 0, False), (8, 2, False), (10, 1, False)])
def test_explicit_map_load_checks_idle_state_and_verifies_the_loaded_floor(schedule_admin, monkeypatch, state, in_cleaning, allowed):
    import asyncio
    from shared import routine_runner
    from roborock_local_server.admin_schedule_settings import read_room_catalog, RoomCatalogError

    _, supervisor, _, _ = schedule_admin
    calls = []

    class Client:
        def __init__(self, context, device, logger):
            self.loaded = False

        async def connect(self):
            pass

        async def send_command(self, command, params):
            calls.append((str(command), params))
            if str(command) == "get_status":
                return [{"state": state, "in_cleaning": in_cleaning, "map_status": 7 if self.loaded else 3}]
            if str(command) == "get_multi_maps_list":
                return {"map_info": [{"mapFlag": 0, "name": "Downstairs"}, {"mapFlag": 1, "name": "Upstairs"}]}
            if str(command) == "load_multi_map":
                assert params == [1]
                self.loaded = True
                return ["ok"]
            if str(command) == "get_room_mapping":
                assert self.loaded
                return [[25, "bedroom"]]
            raise AssertionError("Unexpected robot command")

        async def close(self):
            calls.append(("close", []))

    monkeypatch.setattr(routine_runner, "_RoutineMqttClient", Client)
    if allowed:
        result = asyncio.run(read_room_catalog(supervisor, "test-vacuum", load_map=1))
        assert result["map_index"] == 1
        assert result["rooms"][0]["id"] == 25
        assert ("load_multi_map", [1]) in calls
    else:
        with pytest.raises(RoomCatalogError, match="idle or docked"):
            asyncio.run(read_room_catalog(supervisor, "test-vacuum", load_map=1))
        assert not any(command == "load_multi_map" for command, _ in calls)
    assert calls[-1] == ("close", [])


def test_map_load_endpoint_validates_origin_and_shape(schedule_admin, monkeypatch):
    client, _, _, _ = schedule_admin
    login(client)
    calls = []

    async def load(supervisor, duid, *, load_map):
        calls.append((duid, load_map))
        return {"map_index": load_map, "maps": [], "rooms": [], "revision": "fresh"}

    monkeypatch.setattr(admin_schedules, "read_room_catalog", load)
    url = "/admin/api/schedules/test-vacuum/rooms"
    assert client.post(url, json={"map_index": 1}, headers={"Origin": "https://elsewhere.example"}).status_code == 403
    assert client.post(url, content="{}").status_code == 415
    for body in ({}, {"map_index": True}, {"map_index": -1}, {"map_index": 63}, {"map_index": 1, "start": True}):
        assert client.post(url, json=body).status_code == 400
    assert calls == []
    assert client.post(url, json={"map_index": 1}).status_code == 200
    assert calls == [("test-vacuum", 1)]


def test_lists_native_imports_and_next_run_without_exposing_inventory(schedule_admin):
    client, _, _, _ = schedule_admin
    login(client)
    response = client.get("/admin/api/schedules")
    assert response.headers["cache-control"] == "no-store"
    data = row(client)
    assert data["id"] == 701
    assert data["enabled"] is True
    assert data["native_timer_name"] == "native-test-timer"
    assert data["native_timer_state"] == "not_checked"
    assert data["editable"] is True
    assert datetime.fromisoformat(data["next_run_at"]).utcoffset().total_seconds() == 0
    assert data["settings"]["segments"] == "16,18"
    assert data["settings"]["map_index"] == 0
    for secret in ("PRIVATE_SETTING", "PRIVATE_JOB_DATA", "PRIVATE_DEVICE_KEY", "future_setting"):
        assert secret not in response.text


def test_edit_preserves_native_settings_unknown_fields_and_occurrence_claim(schedule_admin):
    client, _, paths, original = schedule_admin
    login(client)
    revision = row(client)["revision"]
    response = patch(client, revision=revision, cron="30 11 * * 0,6", timeZoneId="America/New_York")
    assert response.status_code == 200
    assert response.json()["schedule"]["revision"] != revision
    stored = json.loads(paths.inventory_path.read_text())
    changed = stored["schedules"]["test-vacuum"][0]
    expected = {**original, "cron": "30 11 * * 0,6", "timeZoneId": "America/New_York"}
    assert changed == expected
    assert stored["schedule_occurrences"]["test-vacuum"]["701"] == {"claimed_at": 12345}


def test_disabling_updates_and_verifies_only_the_linked_timer(schedule_admin, timer_robot):
    client, _, paths, original = schedule_admin
    login(client)
    response = patch(client, revision=row(client)["revision"], enabled=False)
    assert response.status_code == 200
    updated = response.json()["schedule"]
    assert updated["enabled"] is False
    assert updated["next_run_at"] is None
    assert updated["native_timer_state"] == "off"
    assert datetime.fromisoformat(updated["native_timer_checked_at"]).utcoffset().total_seconds() == 0
    assert timer_robot.calls == [
        ("connect", None), ("get_server_timer", []),
        ("upd_server_timer", [["native-test-timer", "off"]]), ("get_server_timer", []), ("close", None),
    ]
    assert timer_robot.timers == [["native-test-timer", "off", {"keep": "timer-settings"}]]
    stored = json.loads(paths.inventory_path.read_text())["schedules"]["test-vacuum"][0]
    assert stored["param"] == original["param"]
    assert stored["cron"] == original["cron"]


def test_enabling_repairs_a_server_enabled_job_whose_robot_timer_is_off(schedule_admin, timer_robot):
    client, _, paths, original = schedule_admin
    timer_robot.timers = [["native-test-timer", "off", {"keep": 1}], ["another-timer", "off"]]
    login(client)
    response = patch(client, revision=row(client)["revision"], enabled=True)
    assert response.status_code == 200
    assert response.json()["schedule"]["native_timer_state"] == "on"
    assert timer_robot.timers == [["native-test-timer", "on", {"keep": 1}], ["another-timer", "off"]]
    assert json.loads(paths.inventory_path.read_text())["schedules"]["test-vacuum"][0] == original
    assert ("upd_server_timer", [["native-test-timer", "on"]]) in timer_robot.calls
    # A later listing does not present the earlier verification as a fresh read.
    assert row(client)["native_timer_state"] == "not_checked"


def test_already_matching_timer_is_read_without_a_duplicate_write(schedule_admin, timer_robot):
    client, _, _, _ = schedule_admin
    login(client)
    response = patch(client, revision=row(client)["revision"], enabled=True)
    assert response.status_code == 200
    assert response.json()["schedule"]["native_timer_state"] == "on"
    assert timer_robot.calls == [("connect", None), ("get_server_timer", []), ("close", None)]


@pytest.mark.parametrize("timers,status", [
    ([], 409), ([["unrelated", "on"]], 409),
    ([["native-test-timer", "on"], ["native-test-timer", "off"]], 409),
    ([["native-test-timer", "unknown"]], 409), ([["native-test-timer"]], 409), ({"timers": []}, 503),
])
def test_unusable_native_timer_never_changes_job_or_creates_a_timer(schedule_admin, timer_robot, timers, status):
    client, _, paths, _ = schedule_admin
    timer_robot.timers = timers
    login(client)
    before = paths.inventory_path.read_bytes()
    response = patch(client, revision=row(client)["revision"], enabled=False)
    assert response.status_code == status
    assert paths.inventory_path.read_bytes() == before
    assert timer_robot.calls == [("connect", None), ("get_server_timer", []), ("close", None)]


@pytest.mark.parametrize("name", [None, "", " ", 123])
def test_invalid_native_reference_is_not_treated_as_a_legacy_schedule(schedule_admin, timer_robot, name):
    client, _, paths, _ = schedule_admin
    data = json.loads(paths.inventory_path.read_text())
    data["schedules"]["test-vacuum"][0]["param"]["params"][0]["name"] = name
    paths.inventory_path.write_text(json.dumps(data))
    login(client)
    before = paths.inventory_path.read_bytes()
    assert patch(client, revision=row(client)["revision"], enabled=False).status_code == 409
    assert paths.inventory_path.read_bytes() == before
    assert timer_robot.calls == []


def test_shared_native_reference_is_rejected_before_contacting_robot(schedule_admin, timer_robot):
    client, _, paths, original = schedule_admin
    data = json.loads(paths.inventory_path.read_text())
    data["schedules"]["test-vacuum"].append({**original, "id": 702})
    paths.inventory_path.write_text(json.dumps(data))
    login(client)
    before = paths.inventory_path.read_bytes()
    assert patch(client, revision=row(client)["revision"], enabled=False).status_code == 409
    assert paths.inventory_path.read_bytes() == before
    assert timer_robot.calls == []


def test_multiple_native_references_are_not_treated_as_legacy(schedule_admin, timer_robot):
    client, _, paths, _ = schedule_admin
    data = json.loads(paths.inventory_path.read_text())
    data["schedules"]["test-vacuum"][0]["param"]["params"] = [{"name": "native-test-timer"}, {"name": "another-timer"}]
    paths.inventory_path.write_text(json.dumps(data))
    login(client)
    before = paths.inventory_path.read_bytes()
    assert patch(client, revision=row(client)["revision"], enabled=False).status_code == 409
    assert paths.inventory_path.read_bytes() == before
    assert timer_robot.calls == []


@pytest.mark.parametrize("failure", ["connect_error", "read_error"])
def test_unreachable_robot_keeps_job_and_does_not_expose_connection_details(schedule_admin, timer_robot, failure):
    client, _, paths, _ = schedule_admin
    setattr(timer_robot, failure, TimeoutError("PRIVATE_CONNECTION_DETAIL"))
    login(client)
    before = paths.inventory_path.read_bytes()
    response = patch(client, revision=row(client)["revision"], enabled=False)
    assert response.status_code == 503
    assert "PRIVATE_CONNECTION_DETAIL" not in response.text
    assert paths.inventory_path.read_bytes() == before
    assert not any(command == "upd_server_timer" for command, _ in timer_robot.calls)
    assert timer_robot.calls[-1] == ("close", None)


@pytest.mark.parametrize("write_error", [None, RuntimeError("PRIVATE_REFUSAL")])
def test_acknowledgement_without_changed_timer_is_not_success(schedule_admin, timer_robot, write_error):
    client, _, paths, _ = schedule_admin
    timer_robot.apply_write = False
    timer_robot.write_error = write_error
    login(client)
    before = paths.inventory_path.read_bytes()
    response = patch(client, revision=row(client)["revision"], enabled=False)
    assert response.status_code == 503
    assert "PRIVATE_REFUSAL" not in response.text
    assert paths.inventory_path.read_bytes() == before
    assert timer_robot.read_count == 2


def test_lost_write_acknowledgement_can_be_confirmed_without_resending(schedule_admin, timer_robot):
    client, _, _, _ = schedule_admin
    timer_robot.write_error = TimeoutError("lost acknowledgement")
    login(client)
    response = patch(client, revision=row(client)["revision"], enabled=False)
    assert response.status_code == 200
    assert response.json()["schedule"]["native_timer_state"] == "off"
    assert sum(command == "upd_server_timer" for command, _ in timer_robot.calls) == 1
    assert timer_robot.read_count == 2


def test_failed_verification_reports_uncertainty_without_saving_job(schedule_admin, timer_robot):
    client, _, paths, _ = schedule_admin
    def fail_readback(count):
        if count == 2:
            timer_robot.read_error = TimeoutError("PRIVATE_CONNECTION_DETAIL")
    timer_robot.after_read = fail_readback
    login(client)
    before = paths.inventory_path.read_bytes()
    response = patch(client, revision=row(client)["revision"], enabled=False)
    assert response.status_code == 503
    assert "may have changed" in response.json()["error"]
    assert paths.inventory_path.read_bytes() == before
    assert timer_robot.timers[0][1] == "off"
    assert timer_robot.calls[-1] == ("close", None)


@pytest.mark.parametrize("when", ["before_write", "after_write"])
def test_app_edit_during_timer_operation_is_preserved(schedule_admin, timer_robot, when):
    client, _, paths, _ = schedule_admin
    def change_job(*args):
        data = json.loads(paths.inventory_path.read_text())
        data["schedules"]["test-vacuum"][0]["cron"] = "5 9 * * *"
        paths.inventory_path.write_text(json.dumps(data))
    if when == "before_write":
        timer_robot.after_read = change_job
    else:
        timer_robot.after_write = change_job
    login(client)
    response = patch(client, revision=row(client)["revision"], enabled=False)
    assert response.status_code == 409
    stored = json.loads(paths.inventory_path.read_text())["schedules"]["test-vacuum"][0]
    assert stored["cron"] == "5 9 * * *"
    assert stored["enabled"] is True
    writes = [call for call in timer_robot.calls if call[0] == "upd_server_timer"]
    assert len(writes) == (0 if when == "before_write" else 1)


def test_simultaneous_dashboard_toggles_do_not_interleave_robot_writes(schedule_admin, timer_robot):
    import httpx
    _, supervisor, _, _ = schedule_admin
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=supervisor.app), base_url="http://testserver") as client:
            assert (await client.post("/admin/api/login", json={"password": "correct horse battery staple"})).status_code == 200
            listing = (await client.get("/admin/api/schedules")).json()
            job = next(d for d in listing["devices"] if d["duid"] == "test-vacuum")["schedules"][0]
            results = await asyncio.gather(*[
                client.patch("/admin/api/schedules/test-vacuum/701", json={"revision": job["revision"], "enabled": False})
                for _ in range(2)
            ])
            assert sorted(r.status_code for r in results) == [200, 409]
    asyncio.run(exercise())
    assert sum(command == "upd_server_timer" for command, _ in timer_robot.calls) == 1


@pytest.mark.parametrize("method", ["app_start", "server_scheduled_start"])
def test_legacy_enablement_and_unrelated_edits_do_not_contact_native_timer(schedule_admin, timer_robot, method):
    client, _, paths, _ = schedule_admin
    login(client)
    assert patch(client, revision=row(client)["revision"], cron="5 9 * * *").status_code == 200
    assert timer_robot.calls == []
    data = json.loads(paths.inventory_path.read_text())
    del data["schedules"]["test-vacuum"][0]["param"]["params"][0]["name"]
    data["schedules"]["test-vacuum"][0]["param"]["method"] = method
    paths.inventory_path.write_text(json.dumps(data))
    response = patch(client, revision=row(client)["revision"], enabled=False)
    assert response.status_code == 200
    assert response.json()["schedule"]["native_timer_state"] is None
    assert timer_robot.calls == []


def test_stale_browser_revision_does_not_overwrite_another_client(schedule_admin):
    client, _, paths, _ = schedule_admin
    login(client)
    revision = row(client)["revision"]
    inventory = json.loads(paths.inventory_path.read_text())
    inventory["schedules"]["test-vacuum"][0]["cron"] = "45 14 * * *"
    paths.inventory_path.write_text(json.dumps(inventory))
    before = paths.inventory_path.read_bytes()
    assert patch(client, revision=revision, enabled=False).status_code == 409
    assert paths.inventory_path.read_bytes() == before


def test_change_between_validation_and_write_is_rejected(schedule_admin, monkeypatch):
    client, _, paths, _ = schedule_admin
    login(client)
    revision = row(client)["revision"]
    real_upsert = admin_schedules.upsert_job

    def racing_upsert(*args, **kwargs):
        inventory = json.loads(paths.inventory_path.read_text())
        inventory["schedules"]["test-vacuum"][0]["cron"] = "5 9 * * *"
        paths.inventory_path.write_text(json.dumps(inventory))
        return real_upsert(*args, **kwargs)

    monkeypatch.setattr(admin_schedules, "upsert_job", racing_upsert)
    assert patch(client, revision=revision, enabled=False).status_code == 409
    stored = json.loads(paths.inventory_path.read_text())["schedules"]["test-vacuum"][0]
    assert stored["cron"] == "5 9 * * *"
    assert stored["enabled"] is True


@pytest.mark.parametrize("fields", [
    {"enabled": "false"}, {"enabled": 0}, {"cron": "65 8 * * *"}, {"cron": []},
    {"timeZoneId": "Not/A_Zone"}, {"timeZoneId": ""}, {"timeZoneId": None},
    {"param": {"params": []}}, {"id": 800}, {"repeated": "false"},
])
def test_invalid_or_out_of_scope_edits_do_not_write(schedule_admin, fields):
    client, _, paths, _ = schedule_admin
    login(client)
    revision = row(client)["revision"]
    before = paths.inventory_path.read_bytes()
    assert patch(client, revision=revision, **fields).status_code == 400
    assert paths.inventory_path.read_bytes() == before


def test_once_and_recurring_schedules_can_be_edited_without_changing_native_identity(schedule_admin):
    client, _, paths, _ = schedule_admin
    inventory = json.loads(paths.inventory_path.read_text())
    inventory["schedules"]["test-vacuum"][0]["repeated"] = "false"
    paths.inventory_path.write_text(json.dumps(inventory))
    login(client)
    data = row(client)
    assert data["editable"] is True
    assert data["repeated"] is False
    assert patch(client, revision=data["revision"], enabled=False).status_code == 200
    response = patch(client, revision=row(client)["revision"], repeated=True, cron="30 10 * * 0,6")
    assert response.status_code == 200
    assert response.json()["schedule"]["repeated"] is True
    response = patch(client, revision=row(client)["revision"], repeated=False, cron="30 10 * * *")
    assert response.status_code == 200
    saved = json.loads(paths.inventory_path.read_text())["schedules"]["test-vacuum"][0]
    assert saved["repeated"] is False
    assert saved["param"] == inventory["schedules"]["test-vacuum"][0]["param"]


def test_missing_and_duplicate_jobs_are_not_created_or_arbitrarily_edited(schedule_admin):
    client, _, paths, original = schedule_admin
    login(client)
    assert client.patch("/admin/api/schedules/test-vacuum/999", json={
        "revision": "unknown", "enabled": False,
    }).status_code == 404
    inventory = json.loads(paths.inventory_path.read_text())
    inventory["schedules"]["test-vacuum"].append(copy.deepcopy(original))
    paths.inventory_path.write_text(json.dumps(inventory))
    assert patch(client, revision=admin_schedules._revision(original), enabled=False).status_code == 409


def test_write_failure_and_corrupt_inventory_are_not_acknowledged(schedule_admin, monkeypatch):
    client, _, paths, _ = schedule_admin
    login(client)
    revision = row(client)["revision"]

    def cannot_save(*args, **kwargs):
        raise OSError("PRIVATE_FILESYSTEM_DETAIL")

    monkeypatch.setattr(admin_schedules, "upsert_job", cannot_save)
    response = patch(client, revision=revision, enabled=False)
    assert response.status_code == 500
    assert response.json()["code"] == "schedule_save_failed_after_timer_sync"
    assert "robot timer was verified off" in response.json()["error"]
    assert "PRIVATE_FILESYSTEM_DETAIL" not in response.text
    paths.inventory_path.write_text("not valid JSON")
    assert client.get("/admin/api/schedules").status_code == 500
    assert patch(client, revision=revision, enabled=False).status_code == 500
    assert paths.inventory_path.read_text() == "not valid JSON"


def test_rejects_cross_origin_and_non_json_edits(schedule_admin):
    client, _, paths, _ = schedule_admin
    login(client)
    revision = row(client)["revision"]
    before = paths.inventory_path.read_bytes()
    response = client.patch("/admin/api/schedules/test-vacuum/701",
        json={"revision": revision, "enabled": False}, headers={"Origin": "https://elsewhere.example"})
    assert response.status_code == 403
    assert client.patch("/admin/api/schedules/test-vacuum/701", content="{}").status_code == 415
    assert client.patch("/admin/api/schedules/test-vacuum/701", content="[]",
                        headers={"Content-Type": "application/json"}).status_code == 400
    assert paths.inventory_path.read_bytes() == before
