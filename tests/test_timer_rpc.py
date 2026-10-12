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
    MqttTopicBridge,
)
from shared import schedule_store, timer_rpc

DUID = "2e2txkqKqxVifcIdyOT1lY"
LOCALKEY = "AoYY9mpxTOIUZtg4"


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
    assert result == [
        ["3549431", "on", ["00 11 * * 1,3,5", ["start_clean", {}]]],
        ["3549434", "off", ["00 11 * * 0,6", ["start_clean", {}]]],
        ["3878757", "on", ["03 13 15 12 *", ["start_clean", {}]]],
    ]


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
    assert ["1790000000", "on", ["30 7 * * 1,2", ["start_clean", {}]]] in listed


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


def test_interceptor_answers_get_timer_with_an_encrypted_rpc_response(ctx):
    reply = timer_rpc.TimerRpcInterceptor(ctx)(DUID, _encode_request("get_timer", []))
    assert reply is not None
    response = _decode_reply(reply)
    assert response.request_id == 4242
    assert [entry[0] for entry in response.data] == ["3549431", "3549434", "3878757"]


def test_interceptor_forwards_everything_that_is_not_a_timer_request(ctx):
    interceptor = timer_rpc.TimerRpcInterceptor(ctx)
    assert interceptor(DUID, _encode_request("get_status", [])) is None
    assert interceptor(DUID, b"not a roborock frame") is None
    assert interceptor("unknown-duid", _encode_request("get_timer", [])) is None


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
    message = SimpleNamespace(payload=_encode_request("get_timer", []), qos=0, retain=False)
    client = Client()

    asyncio.run(bridge._handle_cloud_message(client, message, cloud, cloud.topic_in))

    assert [topic for topic, _ in client.published] == [cloud.topic_out]
    assert _decode_reply(client.published[0][1]).request_id == 4242
