import asyncio
import json
import logging
from types import SimpleNamespace

import pytest

import roborock_local_server.backend  # noqa: F401  (puts the bundled `shared` package on sys.path)
from roborock.protocol import create_mqtt_decoder, create_mqtt_encoder
from roborock.protocols.v1_protocol import decode_rpc_response
from roborock.roborock_message import RoborockMessage, RoborockMessageProtocol
from roborock_local_server.bundled_backend.mqtt_broker_server.topic_bridge import (
    CloudTopicKey,
    DeviceTopicKey,
    MqttTopicBridge,
)
from shared import schedule_store, timer_rpc

DUID = "duid-test-1"
LOCALKEY = "testkey000000000"


def _cloud_job(job_id, cron, *, enabled=True, **extra):
    job = {
        "id": job_id,
        "cron": cron,
        "timeZoneId": "America/New_York",
        "repeated": True,
        "enabled": enabled,
        "param": {
            "id": 1,
            "method": "server_scheduled_start",
            "params": [{"repeat": 1, "water_box_mode": 203, "segments": "0", "fan_power": 104, "mop_mode": 300}],
        },
    }
    job.update(extra)
    return job


@pytest.fixture
def ctx(tmp_path):
    inventory = {
        "schedules": {
            DUID: [
                _cloud_job(3549431, "00 11 ? * 1,3,5"),
                _cloud_job(3549434, "00 11 ? * 0,6", enabled=False),
                _cloud_job(3878757, "03 13 15 12 ?", repeated=False),
            ]
        }
    }
    (tmp_path / "web_api_inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
    creds = SimpleNamespace(resolve_device=lambda duid="": {"localkey": LOCALKEY} if duid == DUID else None)
    return SimpleNamespace(
        http_jsonl=tmp_path / "http.jsonl", loggers={}, timezone="America/New_York",
        runtime_credentials=creds, localkey="",
    )


def test_get_timer_lists_cloud_schedules_in_the_shape_localrock_parses(ctx):
    result = timer_rpc.handle_timer_request(ctx, DUID, "get_timer", None)
    # The one-off (Dec 15) keeps its day and month, the form the robot and the official app use.
    settings = {"repeat": 1, "water_box_mode": 203, "segments": "0", "fan_power": 104, "mop_mode": 300}
    assert result == [
        ["3549431", "on", ["00 11 * * 1,3,5", ["start_clean", settings]]],
        ["3549434", "off", ["00 11 * * 0,6", ["start_clean", settings]]],
        ["3878757", "on", ["03 13 15 12 *", ["start_clean", settings]]],
    ]


@pytest.mark.parametrize("serialized", [False, True])
def test_native_jobs_are_not_fabricated_as_legacy_timers(ctx, serialized):
    for job in schedule_store.list_jobs(ctx, DUID):
        param = job["param"]
        param["params"][0]["name"] = "native-" + str(job["id"])
        schedule_store.upsert_job(ctx, DUID, job_id=job["id"], cron=job["cron"],
                                  enabled=job["enabled"], param=param)
    if serialized:
        path = ctx.http_jsonl.parent / "web_api_inventory.json"
        inventory = json.loads(path.read_text())
        for job in inventory["schedules"][DUID]:
            job["param"] = json.dumps(job["param"])
        path.write_text(json.dumps(inventory))
    assert timer_rpc.handle_timer_request(ctx, DUID, "get_timer", []) == []
    assert len(schedule_store.list_jobs(ctx, DUID)) == 3


@pytest.mark.parametrize(
    ("cron", "expected"),
    [
        ("15 23 18 10 ?", "15 23 18 10 *"),
        ("15 23 18 10 *", "15 23 18 10 *"),
        ("00 11 ? * 1,3,5", "00 11 * * 1,3,5"),
        ("0 8 * * 0,1,2,3,4,5,6", "0 8 * * 0,1,2,3,4,5,6"),
        # Only one of day and month pinned has no one-time form.
        ("0 8 15 * *", None),
        ("0 8 * 10 *", None),
        ("not a cron", None),
    ],
)
def test_device_cron_keeps_a_one_time_schedules_date(cron, expected):
    assert timer_rpc.device_cron(cron) == expected


def test_set_timer_creates_a_job_and_get_timer_returns_it(ctx):
    params = [["1790000000", ["on", ["30 7 * * 1,2", ["start_clean", {}]]]]]
    assert timer_rpc.handle_timer_request(ctx, DUID, "set_timer", params) == ["ok"]

    job = next(j for j in schedule_store.list_jobs(ctx, DUID) if str(j["id"]) == "1790000000")
    assert job["cron"] == "30 7 * * 1,2"
    assert job["enabled"] is True
    assert job["timeZoneId"] == "America/New_York"
    assert job["param"]["method"] == "server_scheduled_start"

    listed = timer_rpc.handle_timer_request(ctx, DUID, "get_timer", None)
    default_settings = {"repeat": 1, "segments": "0"}
    assert ["1790000000", "on", ["30 7 * * 1,2", ["start_clean", default_settings]]] in listed


def test_editing_a_cloud_schedule_keeps_its_vac_and_mop_settings(ctx):
    params = [["3549431", ["on", ["15 9 * * 1,3,5", ["start_clean", {}]]]]]
    timer_rpc.handle_timer_request(ctx, DUID, "set_timer", params)

    job = next(j for j in schedule_store.list_jobs(ctx, DUID) if j["id"] == 3549431)
    assert job["cron"] == "15 9 * * 1,3,5"
    entry = job["param"]["params"][0]
    assert (entry["fan_power"], entry["water_box_mode"], entry["mop_mode"]) == (104, 203, 300)


def test_upd_timer_toggles_and_del_timer_removes_a_cloud_schedule(ctx):
    assert timer_rpc.handle_timer_request(ctx, DUID, "upd_timer", [["3549431", "off"]]) == ["ok"]
    job = next(j for j in schedule_store.list_jobs(ctx, DUID) if j["id"] == 3549431)
    assert job["enabled"] is False

    assert timer_rpc.handle_timer_request(ctx, DUID, "del_timer", ["3549431"]) == ["ok"]
    assert all(j["id"] != 3549431 for j in schedule_store.list_jobs(ctx, DUID))


def test_set_timer_rejects_an_unparseable_cron(ctx):
    with pytest.raises(timer_rpc.TimerRequestError):
        timer_rpc.handle_timer_request(ctx, DUID, "set_timer", [["1", ["on", ["not a cron", []]]]])


def _encode_request(method, params, request_id=4242):
    payload = json.dumps(
        {"t": 1790000000, "dps": {"101": json.dumps({"id": request_id, "method": method, "params": params})}}
    ).encode()
    message = RoborockMessage(protocol=RoborockMessageProtocol.RPC_REQUEST, payload=payload)
    return create_mqtt_encoder(LOCALKEY)(message)


def _decode_reply(reply):
    (message,) = create_mqtt_decoder(LOCALKEY)(reply)
    return decode_rpc_response(message)


def test_interceptor_answers_upd_timer_with_an_encrypted_rpc_response(ctx):
    reply = timer_rpc.TimerRpcInterceptor(ctx)(DUID, _encode_request("upd_timer", [["3549431", "off"]]))
    assert reply is not None
    response = _decode_reply(reply)
    assert response.request_id == 4242
    assert response.data == ["ok"]


def test_interceptor_forwards_everything_that_is_not_a_timer_request(ctx):
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    assert interceptor(DUID, _encode_request("get_status", [])) is None
    assert interceptor(DUID, b"not a roborock frame") is None
    assert interceptor("unknown-duid", _encode_request("get_timer", [])) is None


@pytest.mark.parametrize(
    "method", ["get_server_timer", "set_server_timer", "upd_server_timer", "del_server_timer"]
)
def test_interceptor_leaves_server_timer_to_the_robot(ctx, method):
    # A robot that speaks server_timer stores those entries itself and the official app reads
    # them back from it; answering this locally hides the robot's real schedules from every
    # client and has caused real data loss. This must always forward, never answer here.
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    assert interceptor(DUID, _encode_request(method, [])) is None


def test_native_write_observation_preserves_wire_payload_and_waits_for_confirmation(ctx):
    from shared.native_schedule_sync import NativeScheduleSync
    from roborock_local_server.bundled_backend.mqtt_broker_server.topic_bridge import DeviceTopicKey

    coordinator = NativeScheduleSync(ctx)
    bridge = MqttTopicBridge(
        host="127.0.0.1", port=1883, logger=logging.getLogger("native-sync-test"),
        request_interceptor=timer_rpc.TimerRpcInterceptor(ctx),
        request_observer=coordinator.observe_request,
    )
    device = DeviceTopicKey(did="robot-did", mqtt_usr="robot-user")
    bridge._remember_device_seen(device)
    before = schedule_store.list_jobs(ctx, DUID)
    sent = []

    class Client:
        async def publish(self, topic, payload, **kwargs):
            sent.append((topic, payload))

    async def exercise():
        for session, enabled in (("homebridge", False), ("oem", True), ("localrock", False)):
            cloud = CloudTopicKey(rriot_u=session, mqtt_username=session, duid=DUID)
            payload = _encode_request("upd_server_timer", [["native-timer", "on" if enabled else "off"]])
            message = SimpleNamespace(payload=payload, qos=0, retain=False)
            await bridge._handle_cloud_message(Client(), message, cloud, cloud.topic_in)
            assert sent[-1] == (device.topic_out, payload)
            assert schedule_store.list_jobs(ctx, DUID) == before
        assert coordinator._generation[DUID] == 3

    asyncio.run(exercise())


def test_retained_native_write_is_not_observed_as_a_new_change(ctx):
    from shared.native_schedule_sync import NativeScheduleSync
    from roborock_local_server.bundled_backend.mqtt_broker_server.topic_bridge import DeviceTopicKey
    coordinator = NativeScheduleSync(ctx)
    bridge = MqttTopicBridge(host="127.0.0.1", port=1883, logger=logging.getLogger("native-sync-test"),
                             request_observer=coordinator.observe_request)
    bridge._remember_device_seen(DeviceTopicKey(did="robot-did", mqtt_usr="robot-user"))
    cloud = CloudTopicKey(rriot_u="app", mqtt_username="app", duid=DUID)
    class Client:
        async def publish(self, *args, **kwargs):
            pass
    message = SimpleNamespace(payload=_encode_request("upd_server_timer", [["native-timer", "on"]]), qos=0, retain=True)
    asyncio.run(bridge._handle_cloud_message(Client(), message, cloud, cloud.topic_in))
    assert not coordinator._dirty


def test_bridge_answers_timer_requests_locally_and_does_not_forward_them(ctx):
    class Client:
        def __init__(self):
            self.published = []

        async def publish(self, topic, payload, *, qos=0, retain=False):
            self.published.append((topic, payload))

    bridge = MqttTopicBridge(
        host="127.0.0.1",
        port=1883,
        logger=logging.getLogger("test.timer_bridge"),
        request_interceptor=timer_rpc.TimerRpcInterceptor(ctx),
    )
    cloud = CloudTopicKey(rriot_u="u", mqtt_username="m", duid=DUID)
    message = SimpleNamespace(payload=_encode_request("upd_timer", [["3549431", "off"]]), qos=0, retain=False)
    client = Client()

    asyncio.run(bridge._handle_cloud_message(client, message, cloud, cloud.topic_in))

    assert [topic for topic, _ in client.published] == [cloud.topic_out]
    assert _decode_reply(client.published[0][1]).request_id == 4242


def _job(ctx, job_id):
    return next(j for j in schedule_store.list_jobs(ctx, DUID) if str(j["id"]) == str(job_id))


def test_set_timer_carries_vac_and_mop_settings_in_the_action_object(ctx):
    action = ["start_clean", {"fan_power": 102, "water_box_mode": 200, "repeat": 2}]
    params = [["1790000001", ["on", ["0 9 * * 2,4", action]]]]
    assert timer_rpc.handle_timer_request(ctx, DUID, "set_timer", params) == ["ok"]

    entry = _job(ctx, 1790000001)["param"]["params"][0]
    assert (entry["fan_power"], entry["water_box_mode"], entry["repeat"]) == (102, 200, 2)

    listed = timer_rpc.handle_timer_request(ctx, DUID, "get_timer", None)
    row = next(item for item in listed if item[0] == "1790000001")
    assert row[2][1][1]["water_box_mode"] == 200


def test_changing_one_setting_leaves_the_others_alone(ctx):
    action = ["start_clean", {"water_box_mode": 200}]  # vac only on this cloud schedule
    timer_rpc.handle_timer_request(ctx, DUID, "set_timer", [["3549431", ["on", ["00 11 * * 1,3,5", action]]]])

    entry = _job(ctx, 3549431)["param"]["params"][0]
    assert entry["water_box_mode"] == 200
    assert (entry["fan_power"], entry["mop_mode"]) == (104, 300)


def test_an_empty_action_object_does_not_reset_existing_settings(ctx):
    # What older LocalRock builds send: ["start_clean", {}].
    action = ["start_clean", {}]
    timer_rpc.handle_timer_request(ctx, DUID, "set_timer", [["3549431", ["on", ["30 8 * * 1,3,5", action]]]])

    job = _job(ctx, 3549431)
    assert job["cron"] == "30 8 * * 1,3,5"
    assert job["param"]["params"][0]["water_box_mode"] == 203


def test_null_clears_a_setting_and_segments_are_normalised(ctx):
    action = ["start_clean", {"mop_mode": None, "segments": [16, 17]}]
    timer_rpc.handle_timer_request(ctx, DUID, "set_timer", [["3549431", ["on", ["00 11 * * 1,3,5", action]]]])

    entry = _job(ctx, 3549431)["param"]["params"][0]
    assert "mop_mode" not in entry
    assert entry["segments"] == "16,17"


def test_vac_only_schedule_fires_without_a_mop_template(ctx):
    from shared import schedule_runner

    action = ["start_clean", {"water_box_mode": 200, "fan_power": 102}]
    timer_rpc.handle_timer_request(ctx, DUID, "set_timer", [["1790000002", ["on", ["0 9 * * *", action]]]])

    (step,) = schedule_runner.steps_for_job(_job(ctx, 1790000002))
    assert step.params[0]["water_box_mode"] == 200
    assert step.params[0]["fan_power"] == 102


def test_non_numeric_setting_is_rejected_and_nothing_is_saved(ctx):
    before = schedule_store.list_jobs(ctx, DUID)
    action = ["start_clean", {"fan_power": "loud"}]
    with pytest.raises(timer_rpc.TimerRequestError):
        timer_rpc.handle_timer_request(ctx, DUID, "set_timer", [["9", ["on", ["0 9 * * *", action]]]])
    assert schedule_store.list_jobs(ctx, DUID) == before


# What the official app sends (tanos setTimerOnRobot): no status element, the action carries the settings.
OFFICIAL_SET_TIMER = [
    ["1765735413736", ["30 7 * * 1,2", ["start_clean", {"segments": "", "fan_power": 102, "water_box_mode": 202, "repeat": 1}]]]
]
OFFICIAL_PATROL_TIMER = [["1765735413800", ["0 9 * * *", ["app_start_patrol", {"repeat": 1, "source": 3}]]]]


def _encode_robot_reply(request_id, result):
    body = json.dumps({"id": request_id, "result": result})
    payload = json.dumps({"t": 1790000000, "dps": {"102": body}}).encode()
    return create_mqtt_encoder(LOCALKEY)(RoborockMessage(protocol=RoborockMessageProtocol.RPC_RESPONSE, payload=payload))


def test_official_app_set_timer_layout_is_stored_enabled_with_its_settings(ctx):
    assert timer_rpc.handle_timer_request(ctx, DUID, "set_timer", OFFICIAL_SET_TIMER) == ["ok"]

    job = _job(ctx, "1765735413736")
    assert job["cron"] == "30 7 * * 1,2"
    assert job["enabled"] is True
    entry = job["param"]["params"][0]
    assert (entry["fan_power"], entry["water_box_mode"], entry["repeat"], entry["segments"]) == (102, 202, 1, "0")


def test_interceptor_answers_the_official_set_timer_layout_with_ok(ctx):
    reply = timer_rpc.TimerRpcInterceptor(ctx)(DUID, _encode_request("set_timer", OFFICIAL_SET_TIMER))
    response = _decode_reply(reply)
    assert response.api_error is None
    assert response.data == ["ok"]


def test_set_timer_layouts_with_a_status_still_work(ctx):
    timer_rpc.handle_timer_request(ctx, DUID, "set_timer", [["a1", ["off", ["0 9 * * *", ["start_clean", {}]]]]])
    timer_rpc.handle_timer_request(ctx, DUID, "set_timer", [["a2", "off", ["0 9 * * *", ["start_clean", {}]]]])
    assert _job(ctx, "a1")["enabled"] is False
    assert _job(ctx, "a2")["enabled"] is False


def test_patrol_timers_go_to_the_robot_instead_of_being_stored_as_cleans(ctx):
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    assert interceptor(DUID, _encode_request("set_timer", OFFICIAL_PATROL_TIMER)) is None
    assert all(str(j["id"]) != "1765735413800" for j in schedule_store.list_jobs(ctx, DUID))


def test_upd_and_del_of_a_timer_the_store_does_not_own_go_to_the_robot(ctx):
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    assert interceptor(DUID, _encode_request("upd_timer", [["robot-own", "off"]])) is None
    assert interceptor(DUID, _encode_request("del_timer", ["robot-own"])) is None
    assert interceptor(DUID, _encode_request("del_timer", ["3549431"])) is not None


def test_get_timer_is_forwarded_and_the_robots_own_timers_are_kept_in_the_reply(ctx):
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    assert interceptor(DUID, _encode_request("get_timer", [], request_id=77)) is None

    own = ["robot-own", "on", ["0 6 * * *", ["start_clean", {"repeat": 1}]]]
    merged = _decode_reply(interceptor.merge_response(DUID, _encode_robot_reply(77, [own])))
    assert [entry[0] for entry in merged.data] == ["robot-own", "3549431", "3549434", "3878757"]
    # The robot's reply to some other request is left alone.
    assert interceptor.merge_response(DUID, _encode_robot_reply(78, [own])) is None


def test_get_timer_reply_without_a_list_still_lists_the_stores_timers(ctx):
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    interceptor(DUID, _encode_request("get_timer", [], request_id=5))
    merged = _decode_reply(interceptor.merge_response(DUID, _encode_robot_reply(5, None)))
    assert [entry[0] for entry in merged.data] == ["3549431", "3549434", "3878757"]


def test_get_timer_with_nothing_in_the_store_is_plain_forwarding(tmp_path):
    (tmp_path / "web_api_inventory.json").write_text("{}", encoding="utf-8")
    empty = SimpleNamespace(
        http_jsonl=tmp_path / "http.jsonl", loggers={}, timezone="America/New_York",
        runtime_credentials=SimpleNamespace(resolve_device=lambda duid="": {"localkey": LOCALKEY}), localkey="",
    )
    interceptor = timer_rpc.TimerRpcInterceptor(empty)
    assert interceptor(DUID, _encode_request("get_timer", [], request_id=9)) is None
    assert interceptor.merge_response(DUID, _encode_robot_reply(9, [])) is None


def test_a_failed_save_is_reported_and_not_forwarded_to_the_robot(ctx, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(timer_rpc, "upsert_job", fail)
    reply = timer_rpc.TimerRpcInterceptor(ctx)(DUID, _encode_request("set_timer", OFFICIAL_SET_TIMER))
    assert reply is not None
    assert _decode_reply(reply).api_error is not None


def test_bridge_merges_the_robots_get_timer_reply_for_the_client(ctx):
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    bridge = MqttTopicBridge(
        host="127.0.0.1", port=1883, logger=logging.getLogger("test.timer_merge"),
        request_interceptor=interceptor, response_rewriter=interceptor.merge_response,
    )
    device = DeviceTopicKey(did="robot-did", mqtt_usr="robot-user")
    bridge._remember_device_seen(device)
    cloud = CloudTopicKey(rriot_u="u", mqtt_username="m", duid=DUID)
    sent = []

    class Client:
        async def publish(self, topic, payload, **kwargs):
            sent.append((topic, payload))

    async def exercise():
        request = SimpleNamespace(payload=_encode_request("get_timer", [], request_id=31), qos=0, retain=False)
        await bridge._handle_cloud_message(Client(), request, cloud, cloud.topic_in)
        assert sent[-1][0] == device.topic_out
        reply = SimpleNamespace(payload=_encode_robot_reply(31, []), qos=0, retain=False)
        await bridge._handle_device_message(Client(), reply, device, device.topic_in)

    asyncio.run(exercise())
    topic, payload = sent[-1]
    assert topic == cloud.topic_out
    assert [entry[0] for entry in _decode_reply(payload).data] == ["3549431", "3549434", "3878757"]


def test_get_timer_shows_day_names_as_numbers(ctx):
    timer_rpc.handle_timer_request(ctx, DUID, "set_timer", [["named", ["on", ["0 8 * * MON-FRI", ["start_clean", {}]]]]])
    listed = timer_rpc.handle_timer_request(ctx, DUID, "get_timer", None)
    assert next(entry for entry in listed if entry[0] == "named")[2][0] == "0 8 * * 1-5"


def _bridge_with_fallback(ctx, interceptor):
    return MqttTopicBridge(
        host="127.0.0.1", port=1883, logger=logging.getLogger("test.timer_fallback"),
        request_interceptor=interceptor, response_rewriter=interceptor.merge_response,
        request_fallback=interceptor.request_fallback,
    )


def test_get_timer_is_answered_by_the_store_when_the_robot_stays_silent(ctx, monkeypatch):
    monkeypatch.setattr(timer_rpc, "FALLBACK_SECONDS", 0.02)
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    bridge = _bridge_with_fallback(ctx, interceptor)
    bridge._remember_device_seen(DeviceTopicKey(did="robot-did", mqtt_usr="robot-user"))
    cloud = CloudTopicKey(rriot_u="u", mqtt_username="m", duid=DUID)
    sent = []

    class Client:
        async def publish(self, topic, payload, **kwargs):
            sent.append((topic, payload))

    async def exercise():
        request = SimpleNamespace(payload=_encode_request("get_timer", [], request_id=61), qos=0, retain=False)
        await bridge._handle_cloud_message(Client(), request, cloud, cloud.topic_in)
        await asyncio.sleep(0.1)

    asyncio.run(exercise())
    assert [topic for topic, _ in sent][-1] == cloud.topic_out
    reply = _decode_reply(sent[-1][1])
    assert reply.request_id == 61
    assert [entry[0] for entry in reply.data] == ["3549431", "3549434", "3878757"]


def test_no_fallback_reply_is_sent_once_the_robot_has_answered(ctx, monkeypatch):
    monkeypatch.setattr(timer_rpc, "FALLBACK_SECONDS", 0.05)
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    bridge = _bridge_with_fallback(ctx, interceptor)
    device = DeviceTopicKey(did="robot-did", mqtt_usr="robot-user")
    bridge._remember_device_seen(device)
    cloud = CloudTopicKey(rriot_u="u", mqtt_username="m", duid=DUID)
    sent = []

    class Client:
        async def publish(self, topic, payload, **kwargs):
            sent.append(topic)

    async def exercise():
        request = SimpleNamespace(payload=_encode_request("get_timer", [], request_id=62), qos=0, retain=False)
        await bridge._handle_cloud_message(Client(), request, cloud, cloud.topic_in)
        reply = SimpleNamespace(payload=_encode_robot_reply(62, []), qos=0, retain=False)
        await bridge._handle_device_message(Client(), reply, device, device.topic_in)
        await asyncio.sleep(0.15)

    asyncio.run(exercise())
    assert sent.count(cloud.topic_out) == 1


def _robot_error_frame(request_id):
    body = json.dumps({"id": request_id, "error": {"code": -10005, "message": "unsupported"}})
    payload = json.dumps({"t": 1790000000, "dps": {"102": body}}).encode()
    return create_mqtt_encoder(LOCALKEY)(RoborockMessage(protocol=RoborockMessageProtocol.RPC_RESPONSE, payload=payload))


def test_a_robot_error_reply_to_get_timer_still_shows_the_stores_timers(ctx):
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    interceptor(DUID, _encode_request("get_timer", [], request_id=63))
    reply = _decode_reply(interceptor.merge_response(DUID, _robot_error_frame(63)))
    assert reply.api_error is None
    assert [entry[0] for entry in reply.data] == ["3549431", "3549434", "3878757"]


def test_a_robot_error_reply_with_nothing_in_the_store_is_passed_through(ctx):
    for job in schedule_store.list_jobs(ctx, DUID):
        schedule_store.delete_job(ctx, DUID, str(job["id"]))
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    interceptor(DUID, _encode_request("get_timer", [], request_id=64))
    assert interceptor.merge_response(DUID, _robot_error_frame(64)) is None


def test_a_pending_get_timer_is_cleared_once_the_robot_has_answered(ctx):
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    interceptor(DUID, _encode_request("get_timer", [], request_id=65))
    assert interceptor.merge_response(DUID, _encode_robot_reply(65, [])) is not None
    assert interceptor._pending == {}
    assert interceptor.merge_response(DUID, _encode_robot_reply(65, [])) is None


ROBOT_TIMER = ["legacy-1", "on", ["0 9 * * *", ["start_clean", {}]]]


def _edit_legacy_timer(job_id="legacy-1"):
    return [[job_id, ["30 7 * * 1,2", ["start_clean", {"fan_power": 102}]]]]


def test_editing_a_timer_the_robot_listed_goes_to_the_robot(ctx):
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    interceptor(DUID, _encode_request("get_timer", [], request_id=66))
    interceptor.merge_response(DUID, _encode_robot_reply(66, [ROBOT_TIMER]))

    assert interceptor(DUID, _encode_request("set_timer", _edit_legacy_timer())) is None
    assert all(str(j["id"]) != "legacy-1" for j in schedule_store.list_jobs(ctx, DUID))


def test_a_new_timer_is_still_stored_after_the_robot_listed_others(ctx):
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    interceptor(DUID, _encode_request("get_timer", [], request_id=67))
    interceptor.merge_response(DUID, _encode_robot_reply(67, [ROBOT_TIMER]))

    assert interceptor(DUID, _encode_request("set_timer", _edit_legacy_timer("brand-new"))) is not None
    assert any(str(j["id"]) == "brand-new" for j in schedule_store.list_jobs(ctx, DUID))


def test_a_timer_the_store_owns_is_edited_in_the_store_even_if_the_robot_lists_it(ctx):
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    interceptor(DUID, _encode_request("get_timer", [], request_id=68))
    interceptor.merge_response(DUID, _encode_robot_reply(68, [["3549431", "on", ["0 9 * * *", ["start_clean", {}]]]]))

    assert interceptor(DUID, _encode_request("set_timer", _edit_legacy_timer("3549431"))) is not None


def test_the_robots_timer_list_is_forgotten_when_its_next_reply_drops_a_timer(ctx):
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    interceptor(DUID, _encode_request("get_timer", [], request_id=69))
    interceptor.merge_response(DUID, _encode_robot_reply(69, [ROBOT_TIMER]))
    interceptor(DUID, _encode_request("get_timer", [], request_id=70))
    interceptor.merge_response(DUID, _encode_robot_reply(70, []))

    assert interceptor(DUID, _encode_request("set_timer", _edit_legacy_timer())) is not None


def test_positional_start_clean_action_carries_fan_power_and_segments(ctx):
    params = [["pos-1", ["0 9 * * *", ["start_clean", 104, "16,17"]]]]
    assert timer_rpc.handle_timer_request(ctx, DUID, "set_timer", params) == ["ok"]
    entry = _job(ctx, "pos-1")["param"]["params"][0]
    assert (entry["fan_power"], entry["segments"]) == (104, "16,17")


def test_positional_start_clean_without_segments_keeps_the_default_rooms(ctx):
    timer_rpc.handle_timer_request(ctx, DUID, "set_timer", [["pos-2", ["0 9 * * *", ["start_clean", 102]]]])
    entry = _job(ctx, "pos-2")["param"]["params"][0]
    assert (entry["fan_power"], entry["segments"]) == (102, "0")


@pytest.mark.parametrize("action", [["start_clean", 102, "0", 0], ["start_clean", [1]], ["start_clean", None]])
def test_positional_start_clean_the_store_cannot_place_goes_to_the_robot(ctx, action):
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    assert interceptor(DUID, _encode_request("set_timer", [["pos-3", ["0 9 * * *", action]]])) is None
    assert all(str(j["id"]) != "pos-3" for j in schedule_store.list_jobs(ctx, DUID))


def test_one_job_with_an_unreadable_cron_does_not_hide_the_other_timers(ctx):
    schedule_store.upsert_job(ctx, DUID, job_id="bad", cron="0 0 * * ABC", enabled=True)
    assert timer_rpc.device_cron("0 0 * * ABC") is None
    listed = timer_rpc.handle_timer_request(ctx, DUID, "get_timer", None)
    assert [entry[0] for entry in listed] == ["3549431", "3549434", "3878757"]


def test_get_timer_writes_sunday_as_zero(ctx):
    assert timer_rpc.device_cron("0 8 * * 5-7") == "0 8 * * 0,5,6"
    assert timer_rpc.device_cron("0 8 * * FRI-SUN") == "0 8 * * 0,5,6"
    assert timer_rpc.device_cron("0 8 * * 1,7") == "0 8 * * 0,1"
