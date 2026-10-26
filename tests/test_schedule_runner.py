import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import roborock_local_server.backend  # noqa: F401  (puts the bundled `shared` package on sys.path)
from shared import schedule_runner as sr
from shared.routine_runner import RoutineExecutionError

NEW_YORK = "America/New_York"


def _job(**overrides):
    job = {
        "id": 3549431,
        "cron": "00 11 ? * 1,3,5",
        "timeZoneId": NEW_YORK,
        "repeated": True,
        "enabled": True,
        "param": {
            "id": 1,
            "method": "server_scheduled_start",
            "params": [
                {
                    "repeat": 1,
                    "water_box_mode": 203,
                    "segments": "0",
                    "fan_power": 104,
                    "mop_mode": 300,
                    "clean_mop": 1,
                    "map_index": -1,
                }
            ],
        },
    }
    job.update(overrides)
    return job


def _utc(*args):
    return datetime(*args, tzinfo=timezone.utc)


def test_next_fire_matches_the_cloud_reported_fire_times():
    # Values taken from a real cloud snapshot: Monday 2026-09-28 for MWF 11:00 New York.
    spec = sr.parse_cron("00 11 ? * 1,3,5")
    zone = sr._zone(NEW_YORK, "")
    after = _utc(2026, 9, 28, 12, 0).astimezone(zone)
    assert sr.next_fire(spec, after).astimezone(timezone.utc) == _utc(2026, 9, 28, 15, 0)

    tue_thu = sr.parse_cron("00 11 ? * 2,4")
    assert sr.next_fire(tue_thu, after).astimezone(timezone.utc) == _utc(2026, 9, 29, 15, 0)


def test_next_fire_is_strictly_after_and_skips_to_next_matching_day():
    spec = sr.parse_cron("00 11 ? * 1,3,5")
    zone = sr._zone(NEW_YORK, "")
    on_the_minute = _utc(2026, 9, 28, 15, 0).astimezone(zone)
    assert sr.next_fire(spec, on_the_minute).astimezone(timezone.utc) == _utc(2026, 9, 30, 15, 0)


def test_weekend_cron_uses_sunday_zero():
    spec = sr.parse_cron("00 11 ? * 0,6")
    zone = sr._zone(NEW_YORK, "")
    monday = _utc(2026, 9, 28, 12, 0).astimezone(zone)
    assert sr.next_fire(spec, monday).astimezone(timezone.utc) == _utc(2026, 10, 3, 15, 0)


@pytest.mark.parametrize("expression", ["", "* * * *", "61 * * * *", "* 25 * * *", "a b c d e", "*/0 * * * *"])
def test_invalid_cron_is_rejected(expression):
    with pytest.raises(sr.CronError):
        sr.parse_cron(expression)


def test_whole_house_job_becomes_an_app_start_step_carrying_vac_and_mop_settings():
    steps = sr.steps_for_job(_job())
    assert len(steps) == 1
    step = steps[0]
    assert step.method == "schedule_app_start"
    assert step.params == [
        {"repeat": 1, "water_box_mode": 203, "segments": "0", "fan_power": 104, "mop_mode": 300, "clean_mop": 1, "map_index": -1}
    ]
    assert step.name == "Schedule 3549431"


def test_job_with_a_robot_side_timer_id_is_run_by_asking_the_robot_to_start_it():
    # The official app saves every schedule on the robot too and records its timer id as "name" in
    # the cloud job's settings; the cloud runs such a job with server_scheduled_start (confirmed
    # live: the robot records "Schedules" for it, for rooms and whole-home alike).
    job = _job()
    job["param"]["params"][0]["name"] = "1759965417864"
    step = sr.steps_for_job(job)[0]
    assert step.method == "schedule_server_start"
    assert step.params == [
        {
            "repeat": 1, "water_box_mode": 203, "segments": "0", "fan_power": 104, "mop_mode": 300,
            "clean_mop": 1, "map_index": -1, "name": "1759965417864",
        }
    ]


def test_room_job_with_a_robot_side_timer_id_carries_its_rooms_in_the_same_step():
    job = _job()
    job["param"]["params"][0].update({"name": "1759965417864", "segments": "16,17", "map_index": 0})
    step = sr.steps_for_job(job)[0]
    assert step.method == "schedule_server_start"
    assert step.params[0]["segments"] == "16,17"
    assert step.params[0]["map_index"] == 0


def test_segment_job_becomes_a_segment_clean_step():
    job = _job()
    job["param"]["params"][0]["segments"] = "16,17"
    step = sr.steps_for_job(job)[0]
    assert step.method == "do_scenes_segments"
    assert step.params["data"][0]["segs"] == [16, 17]
    assert step.params["data"][0]["fan_power"] == 104


def test_unsupported_method_is_refused():
    job = _job()
    job["param"]["method"] = "something_else"
    with pytest.raises(RoutineExecutionError):
        sr.steps_for_job(job)


class _FakeRunner:
    def __init__(self):
        self.started = []

    def start_job(self, **kwargs):
        self.started.append(kwargs)
        return {"accepted": True, "status": "started", "deviceId": kwargs["device_id"]}


def _runner_with_inventory(tmp_path, monkeypatch, jobs):
    inventory = {"schedules": {"duid-1": jobs}}
    (tmp_path / "web_api_inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
    ctx = SimpleNamespace(http_jsonl=tmp_path / "http.jsonl", loggers={})
    fake = _FakeRunner()
    monkeypatch.setattr(sr, "get_routine_runner", lambda _ctx: fake)
    return sr.ScheduleRunner(ctx), ctx, fake


def test_tick_fires_a_job_that_came_due_since_the_previous_tick(tmp_path, monkeypatch):
    runner, _ctx, fake = _runner_with_inventory(tmp_path, monkeypatch, [_job()])
    assert runner.tick(_utc(2026, 9, 28, 14, 59, 40)) == []  # first tick only sets the baseline
    results = runner.tick(_utc(2026, 9, 28, 15, 0, 5))
    assert [r["status"] for r in results] == ["started"]
    assert fake.started[0]["device_id"] == "duid-1"
    assert fake.started[0]["steps"][0].method == "schedule_app_start"


def test_tick_does_not_fire_twice_or_when_disabled(tmp_path, monkeypatch):
    runner, _ctx, fake = _runner_with_inventory(
        tmp_path, monkeypatch, [_job(), _job(id=2, enabled=False)]
    )
    runner.tick(_utc(2026, 9, 28, 14, 59, 40))
    runner.tick(_utc(2026, 9, 28, 15, 0, 5))
    runner.tick(_utc(2026, 9, 28, 15, 0, 25))
    runner.tick(_utc(2026, 9, 28, 15, 0, 45) + timedelta(minutes=5))
    assert len(fake.started) == 1


def test_one_shot_job_disables_itself_after_firing(tmp_path, monkeypatch):
    runner, _ctx, _fake = _runner_with_inventory(tmp_path, monkeypatch, [_job(repeated=False)])
    runner.tick(_utc(2026, 9, 28, 14, 59, 40))
    runner.tick(_utc(2026, 9, 28, 15, 0, 5))
    saved = json.loads((tmp_path / "web_api_inventory.json").read_text(encoding="utf-8"))
    assert saved["schedules"]["duid-1"][0]["enabled"] is False


@pytest.mark.parametrize("disabled_value", [False, 0, "false", "0"])
def test_string_typed_disabled_flag_is_respected(tmp_path, monkeypatch, disabled_value):
    # Imported inventory stores booleans loosely ("false", 0); "false" must not read as enabled.
    runner, _ctx, fake = _runner_with_inventory(tmp_path, monkeypatch, [_job(enabled=disabled_value)])
    runner.tick(_utc(2026, 9, 28, 14, 59, 40))
    runner.tick(_utc(2026, 9, 28, 15, 0, 5))
    assert fake.started == []


def test_next_fire_time_utc_is_none_when_disabled():
    now = _utc(2026, 9, 28, 12, 0)
    assert sr.next_fire_time_utc(_job(), now=now) == _utc(2026, 9, 28, 15, 0)
    assert sr.next_fire_time_utc(_job(enabled=False), now=now) is None


def test_native_settings_survive_dispatch_preparation_without_filtering_or_mutation():
    job = _job()
    entry = job["param"]["params"][0]
    entry.update(name="timer-42", clean_order_mode=0, mop_template_id=7, future_option={"x": [1, 2]})
    step = sr.steps_for_job(job)[0]
    assert step.params == [entry]
    step.params[0]["future_option"]["x"].append(3)
    assert entry["future_option"] == {"x": [1, 2]}


@pytest.mark.parametrize("timer_name", [None, "", "   ", 123])
def test_invalid_native_timer_name_cannot_turn_into_an_ordinary_start(timer_name):
    job = _job()
    job["param"]["params"][0]["name"] = timer_name
    with pytest.raises(RoutineExecutionError, match="timer name"):
        sr.steps_for_job(job)


def test_observed_weekday_next_fire_advances_to_monday_after_offline_occurrence():
    job = _job(cron="09 14 ? * 1,2,3,4,5", timeZoneId="America/Los_Angeles")
    assert sr.next_fire_time_utc(job, now=_utc(2026, 10, 23, 21, 7)) == _utc(2026, 10, 23, 21, 9)
    assert sr.next_fire_time_utc(job, now=_utc(2026, 10, 23, 21, 10)) == _utc(2026, 10, 26, 21, 9)


@pytest.mark.parametrize("cron,after,expected", [
    ("30 2 * * *", _utc(2026, 3, 8, 9, 59), _utc(2026, 3, 9, 9, 30)),
    ("30 1 * * *", _utc(2026, 11, 1, 8, 29), _utc(2026, 11, 1, 8, 30)),
    ("30 1 * * *", _utc(2026, 11, 1, 8, 30), _utc(2026, 11, 2, 9, 30)),
    ("30 1 * * *", _utc(2026, 11, 1, 9, 20), _utc(2026, 11, 2, 9, 30)),
    ("0 0 * * 0", _utc(2026, 10, 25, 6, 59), _utc(2026, 10, 25, 7, 0)),
    ("0 0 29 2 ?", _utc(2024, 3, 1), _utc(2028, 2, 29, 8, 0)),
])
def test_timezone_and_provisional_dst_policy(cron, after, expected):
    job = _job(cron=cron, timeZoneId="America/Los_Angeles")
    assert sr.next_fire_time_utc(job, now=after) == expected


def test_invalid_explicit_timezone_never_runs_in_a_fallback_zone(tmp_path, monkeypatch):
    job = _job(timeZoneId="Invalid/Zone")
    assert sr.next_fire_time_utc(job, default_timezone="UTC", now=_utc(2026, 9, 28, 14)) is None
    runner, _, fake = _runner_with_inventory(tmp_path, monkeypatch, [job])
    runner.tick(_utc(2026, 9, 28, 14, 59, 40))
    runner.tick(_utc(2026, 9, 28, 15, 0, 5))
    assert fake.started == []


def test_missed_occurrence_is_skipped_and_future_schedule_stays_enabled(tmp_path, monkeypatch):
    runner, ctx, fake = _runner_with_inventory(tmp_path, monkeypatch, [_job()])
    runner.tick(_utc(2026, 9, 28, 14, 59, 40))
    assert runner.tick(_utc(2026, 9, 28, 15, 2)) == []
    restarted = sr.ScheduleRunner(ctx)
    assert restarted.tick(_utc(2026, 9, 28, 15, 3)) == []
    assert fake.started == []
    runner.tick(_utc(2026, 9, 30, 14, 59, 40))
    runner.tick(_utc(2026, 9, 30, 15, 0, 5))
    assert len(fake.started) == 1
    assert sr.load_inventory(ctx)["schedules"]["duid-1"][0]["enabled"] is True


def test_persisted_claim_prevents_replay_after_restart_and_clock_rollback(tmp_path, monkeypatch):
    runner, ctx, fake = _runner_with_inventory(tmp_path, monkeypatch, [_job()])
    runner.tick(_utc(2026, 9, 28, 14, 59, 40))
    runner.tick(_utc(2026, 9, 28, 15, 0, 5))
    runner.tick(_utc(2026, 9, 28, 14, 59, 40))
    runner.tick(_utc(2026, 9, 28, 15, 0, 10))
    restarted = sr.ScheduleRunner(ctx)
    restarted.tick(_utc(2026, 9, 28, 14, 59, 40))
    restarted.tick(_utc(2026, 9, 28, 15, 0, 5))
    assert len(fake.started) == 1


def test_failed_persistence_prevents_robot_dispatch(tmp_path, monkeypatch):
    from shared import schedule_store
    runner, _, fake = _runner_with_inventory(tmp_path, monkeypatch, [_job()])
    monkeypatch.setattr(schedule_store, "write_inventory", lambda *args: False)
    runner.tick(_utc(2026, 9, 28, 14, 59, 40))
    result = runner.tick(_utc(2026, 9, 28, 15, 0, 5))
    assert result[0]["accepted"] is False
    assert fake.started == []


def test_job_edit_between_tick_and_claim_cancels_stale_occurrence(tmp_path, monkeypatch):
    from shared import schedule_store
    runner, ctx, fake = _runner_with_inventory(tmp_path, monkeypatch, [_job()])
    original_steps = sr.steps_for_job
    def edit_then_prepare(job):
        schedule_store.set_enabled(ctx, "duid-1", job["id"], False)
        return original_steps(job)
    monkeypatch.setattr(sr, "steps_for_job", edit_then_prepare)
    runner.tick(_utc(2026, 9, 28, 14, 59, 40))
    runner.tick(_utc(2026, 9, 28, 15, 0, 5))
    assert fake.started == []


def test_malformed_import_does_not_block_other_jobs(tmp_path, monkeypatch):
    runner, _, fake = _runner_with_inventory(tmp_path, monkeypatch, [_job(id=None), _job()])
    runner.tick(_utc(2026, 9, 28, 14, 59, 40))
    runner.tick(_utc(2026, 9, 28, 15, 0, 5))
    assert len(fake.started) == 1
