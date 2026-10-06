import asyncio
from copy import deepcopy
from datetime import datetime
import json
import sqlite3

from fastapi.testclient import TestClient
import pytest

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.routine_schedules import RoutineScheduler, validate_schedule
from roborock_local_server.server import ReleaseSupervisor


def _definition(**changes):
    return {
        "scene_id": 7, "time": "08:30", "timezone": "Australia/Brisbane",
        "weekdays": [0, 1, 2, 3, 4], "enabled": True, **changes,
    }


def _scene():
    return {
        "id": 7, "device_id": "vacuum-1", "name": "Kitchen", "enabled": True,
        "param": json.dumps({"action": {"items": [{
            "id": 1, "type": "CMD", "finishDpIds": [],
            "param": {"method": "do_scenes_app_start", "params": [{"repeat": 1}]},
        }]}}),
    }


def _at(value):
    return datetime.fromisoformat(value)


@pytest.fixture
def scheduler(tmp_path):
    calls = []
    scene = _scene()

    def dispatch(value):
        calls.append(deepcopy(value))
        return {"status": "started"}

    return RoutineScheduler(
        tmp_path / "schedules.sqlite3", load_scene=lambda _: deepcopy(scene), dispatch=dispatch
    ), calls, scene


@pytest.mark.parametrize("changes", [
    {"time": "24:00"}, {"time": "8:30"}, {"time": "08:60"}, {"time": 830}, {"time": "0٨:30"},
    {"timezone": "Mars/Olympus"}, {"timezone": "../UTC"}, {"timezone": None},
    {"weekdays": []}, {"weekdays": [7]}, {"weekdays": [1, 1]}, {"weekdays": [True]},
    {"weekdays": "1"}, {"scene_id": True}, {"scene_id": 0}, {"scene_id": "7"},
    {"enabled": "false"}, {"unknown": 1},
])
def test_invalid_definitions(changes):
    with pytest.raises(ValueError):
        validate_schedule(_definition(**changes))


def test_timezone_weekdays_persistence_and_restart(scheduler):
    worker, calls, _ = scheduler
    worker.save(_definition())
    # Tuesday UTC is already Wednesday in Brisbane.
    worker.tick(_at("2026-10-06T22:29:59+00:00"))
    assert calls == []
    worker.tick(_at("2026-10-06T22:30:00+00:00"))
    worker.tick(_at("2026-10-06T22:30:40+00:00"))
    restarted = RoutineScheduler(worker.path, load_scene=worker._load_scene, dispatch=worker._dispatch)
    restarted.tick(_at("2026-10-06T22:30:50+00:00"))
    assert len(calls) == 1
    assert restarted.list()[0]["last_date"] == "2026-10-07"
    assert restarted.list()[0]["last_result"] == "started"
    restarted.tick(_at("2026-10-07T22:30:00+00:00"))
    assert len(calls) == 2
    restarted.tick(_at("2026-10-09T22:30:00+00:00"))  # Saturday
    assert len(calls) == 2


def test_no_catchup_or_clock_rollback_replay(scheduler):
    worker, calls, _ = scheduler
    worker.save(_definition())
    worker.tick(_at("2026-10-07T08:31:00+10:00"))
    assert calls == []
    worker.tick(_at("2026-10-08T08:30:00+10:00"))
    worker.tick(_at("2026-10-07T08:30:00+10:00"))
    assert len(calls) == 1


def test_disabled_edit_and_delete(scheduler):
    worker, calls, _ = scheduler
    schedule_id = worker.save(_definition(enabled=False))
    now = _at("2026-10-07T08:30:00+10:00")
    worker.tick(now)
    assert calls == []
    worker.save(_definition(), schedule_id=schedule_id)
    worker.tick(now)
    worker.save(_definition(enabled=False), schedule_id=schedule_id)
    worker.save(_definition(), schedule_id=schedule_id)
    worker.tick(now)
    assert len(calls) == 1
    assert worker.delete(schedule_id)
    assert not worker.delete(schedule_id)
    worker.tick(_at("2026-10-08T08:30:00+10:00"))
    assert len(calls) == 1
    assert worker.list() == []
    with pytest.raises(KeyError):
        worker.save(_definition(), schedule_id=schedule_id)


def test_dst_fold_dispatches_once_and_gap_is_skipped(scheduler):
    worker, calls, _ = scheduler
    worker.save(_definition(time="01:30", timezone="America/New_York", weekdays=[6]))
    worker.tick(_at("2026-11-01T05:30:00+00:00"))
    worker.tick(_at("2026-11-01T06:30:00+00:00"))
    assert len(calls) == 1
    worker.save(_definition(time="02:30", timezone="America/New_York", weekdays=[6]))
    worker.tick(_at("2026-03-08T06:59:00+00:00"))
    worker.tick(_at("2026-03-08T07:30:00+00:00"))
    assert len(calls) == 1
    worker.tick(_at("2026-03-15T06:30:00+00:00"))
    assert len(calls) == 2


def test_claim_survives_crash_and_is_visible_to_other_scheduler(scheduler):
    worker, calls, _ = scheduler
    worker.save(_definition())
    now = _at("2026-10-07T08:30:00+10:00")
    other = RoutineScheduler(worker.path, load_scene=worker._load_scene, dispatch=worker._dispatch)

    def crash_after_claim(scene):
        other.tick(now)
        raise KeyboardInterrupt("simulated process exit before dispatch")

    worker._dispatch = crash_after_claim
    with pytest.raises(KeyboardInterrupt):
        worker.tick(now)
    other.tick(now)
    assert calls == []
    assert other.list()[0]["last_result"] == "claimed"


def test_failed_claim_does_not_dispatch(scheduler, monkeypatch):
    worker, calls, _ = scheduler
    worker.save(_definition())
    connect = worker._connect
    attempts = 0

    def fail_write():
        nonlocal attempts
        attempts += 1
        if attempts > 1:
            raise sqlite3.OperationalError("read-only database")
        return connect()

    monkeypatch.setattr(worker, "_connect", fail_write)
    worker.tick(_at("2026-10-07T08:30:00+10:00"))
    assert calls == []


def test_scene_changes_require_resave_and_disabled_scenes_are_skipped(scheduler):
    worker, calls, scene = scheduler
    schedule_id = worker.save(_definition())
    scene["device_id"] = "replacement-vacuum"
    worker.tick(_at("2026-10-07T08:30:00+10:00"))
    assert calls == []
    assert worker.list()[0]["last_result"] == "scene_changed"
    worker.save(_definition(), schedule_id=schedule_id)
    worker.tick(_at("2026-10-08T08:30:00+10:00"))
    assert len(calls) == 1
    scene["enabled"] = False
    worker.tick(_at("2026-10-09T08:30:00+10:00"))
    assert len(calls) == 1
    assert worker.list()[0]["last_result"] == "scene_disabled"


def test_missing_scene_does_not_block_other_schedules(scheduler):
    worker, calls, scene = scheduler
    worker.save(_definition())
    worker.save(_definition(scene_id=8))

    def load(scene_id):
        if scene_id == 7:
            raise RuntimeError("Scene 7 not found")
        return deepcopy(scene)

    worker._load_scene = load
    worker.tick(_at("2026-10-07T08:30:00+10:00"))
    worker.tick(_at("2026-10-07T08:30:30+10:00"))
    assert len(calls) == 1
    assert {row["last_result"] for row in worker.list()} == {"started", "dispatch_failed"}


def test_scheduler_loop_lifecycle(scheduler, monkeypatch):
    worker, _, _ = scheduler

    async def exercise():
        ticks = []
        monkeypatch.setattr(worker, "tick", ticks.append)
        worker.start()
        task = worker._task
        worker.start()
        assert worker._task is task
        await asyncio.sleep(0)
        assert len(ticks) == 1 and ticks[0].tzinfo is not None
        await worker.stop()
        assert task.cancelled()
        assert worker._task is None
        await worker.stop()

    asyncio.run(exercise())


def test_admin_schedule_api_and_dispatch(tmp_path, monkeypatch):
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    paths.inventory_path.write_text(json.dumps({"scenes": [_scene()]}), encoding="utf-8")
    client = TestClient(supervisor.app)
    base = "/admin/api/routine-schedules"
    for method, url in [("get", base), ("post", base), ("put", base + "/missing"),
                        ("delete", base + "/missing"), ("get", "/admin/api/routines")]:
        assert getattr(client, method)(url).status_code == 401
    assert client.post("/admin/api/login", json={"password": "correct horse battery staple"}).status_code == 200
    routines = client.get("/admin/api/routines").json()["routines"]
    assert routines[0]["id"] == 7
    assert client.post(base, json=_definition(scene_id=999)).status_code == 400
    assert client.post(base, content="{bad json").status_code == 400
    assert client.post(base, json=[]).status_code == 400
    assert client.post(base, json=_definition(enabled="false")).status_code == 400
    response = client.post(base, json=_definition())
    assert response.status_code == 201
    schedule_id = response.json()["id"]

    calls = []

    class Runner:
        def start_scene(self, scene, *, scheduled=False):
            calls.append((scene["id"], scheduled))
            return {"status": "started"}

    monkeypatch.setattr(supervisor.context, "_routine_runner", Runner(), raising=False)
    supervisor.routine_scheduler.tick(_at("2026-10-07T08:30:00+10:00"))
    assert calls == [(7, True)]
    assert client.get(base).json()["schedules"][0]["last_result"] == "started"
    assert client.put(base + "/" + schedule_id, json=_definition(enabled=False)).status_code == 200
    assert client.get(base).json()["schedules"][0]["enabled"] is False
    assert client.put(base + "/missing", json=_definition()).status_code == 404
    assert client.delete(base + "/" + schedule_id).status_code == 200
    assert client.delete(base + "/" + schedule_id).status_code == 404
    assert client.get(base).json()["schedules"] == []


def test_schedule_api_absent_when_standalone_admin_disabled(tmp_path):
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    supervisor = ReleaseSupervisor(
        config=config, paths=resolve_paths(config_file, config), enable_standalone_admin=False
    )
    client = TestClient(supervisor.app)
    assert client.get("/admin/api/routine-schedules").status_code == 404
