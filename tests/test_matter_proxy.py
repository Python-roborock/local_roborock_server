import asyncio
import json
import logging

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import Response

from conftest import write_release_config
from roborock_local_server import matter_proxy
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor

PATH = "/iot.roborock.com/fwapi/matter/key"


def test_only_the_matter_key_get_matches() -> None:
    assert matter_proxy.matches("/iot.roborock.com/fwapi/matter/key", "GET")
    assert matter_proxy.matches("/fwapi/matter/key", "get")
    assert not matter_proxy.matches("/iot.roborock.com/fwapi/matter/key", "POST")
    assert not matter_proxy.matches("/iot.roborock.com/fwapi/createca", "GET")
    assert not matter_proxy.matches("/fwapi/matter/keys", "GET")


def test_the_upstream_is_the_regional_cloud_host() -> None:
    assert matter_proxy.upstream_url("us", "did=1") == "https://usiot.roborock.com/fwapi/matter/key?did=1"
    assert matter_proxy.upstream_url("eu", "") == "https://euiot.roborock.com/fwapi/matter/key"
    assert matter_proxy.upstream_url("cn", "") == "https://cniot.roborock.com/fwapi/matter/key"
    assert matter_proxy.upstream_url("ru", "") == "https://ruiot.roborock.com/fwapi/matter/key"


@pytest.mark.parametrize("region", ["../x", "de", "", "usiot.evil.example/", "u s"])
def test_an_unknown_region_is_refused(region) -> None:
    with pytest.raises(ValueError):
        matter_proxy.upstream_url(region, "")


def test_it_is_off_unless_enabled(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("ROBOROCK_SERVER_MATTER_KEY_PROXY", raising=False)
    config_file = write_release_config(tmp_path)
    assert load_config(config_file).matter.key_proxy is False
    monkeypatch.setenv("ROBOROCK_SERVER_MATTER_KEY_PROXY", "true")
    assert load_config(config_file).matter.key_proxy is True


def _request(query: str = "", headers: dict[str, str] | None = None) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": PATH,
            "query_string": query.encode(),
            "headers": raw,
            "client": ("10.0.0.7", 5000),
        }
    )


async def _forward_to(handler, monkeypatch, region="us", query="", headers=None, timeout=None):
    app = web.Application()
    app.router.add_get("/fwapi/matter/key", handler)
    async with TestServer(app) as server:
        monkeypatch.setattr(matter_proxy, "UPSTREAM_BASE", str(server.make_url("")).rstrip("/"))
        if timeout is not None:
            monkeypatch.setattr(matter_proxy, "TIMEOUT_SECONDS", timeout)
        return await matter_proxy.forward(_request(query, headers), region)


def test_forward_filters_headers_and_relays_the_answer(monkeypatch) -> None:
    seen = {}

    async def handler(request):
        seen["headers"], seen["query"] = {k.lower(): v for k, v in request.headers.items()}, request.query_string
        return web.Response(body=b"KEYBYTES", status=200, content_type="application/x-test")

    sent = {"Authorization": "tok", "Cookie": "a=b", "X-Forwarded-For": "1.2.3.4", "Via": "x", "X-Custom": "keep"}
    response = asyncio.run(
        _forward_to(handler, monkeypatch, query="did=D1&signature=abc%3D", headers=sent)
    )

    assert response.status_code == 200 and response.body == b"KEYBYTES"
    assert response.media_type == "application/x-test"
    assert seen["query"] == "did=D1&signature=abc%3D"
    assert seen["headers"]["authorization"] == "tok" and seen["headers"]["x-custom"] == "keep"
    assert not {name.lower() for name in seen["headers"]} & {"cookie", "x-forwarded-for", "via"}


def test_an_upstream_error_status_is_relayed(monkeypatch) -> None:
    async def handler(request):
        return web.Response(body=b"nope", status=403)

    response = asyncio.run(_forward_to(handler, monkeypatch))
    assert response.status_code == 403 and response.body == b"nope"


def test_an_unreachable_upstream_is_a_502(monkeypatch) -> None:
    monkeypatch.setattr(matter_proxy, "UPSTREAM_BASE", "http://127.0.0.1:1")
    response = asyncio.run(matter_proxy.forward(_request(), "us"))
    assert response.status_code == 502 and response.body == b""


def test_a_slow_upstream_times_out_as_a_502(monkeypatch) -> None:
    async def handler(request):
        await asyncio.sleep(2)
        return web.Response(body=b"late")

    response = asyncio.run(_forward_to(handler, monkeypatch, timeout=0.2))
    assert response.status_code == 502


def test_an_unsupported_region_is_a_502_without_a_request(monkeypatch) -> None:
    monkeypatch.setattr(matter_proxy, "UPSTREAM_BASE", "http://127.0.0.1:1")
    assert asyncio.run(matter_proxy.forward(_request(), "de")).status_code == 502


def test_hop_proxy_and_cookie_headers_are_dropped() -> None:
    kept = matter_proxy.forwardable_headers(
        {
            "Host": "h",
            "X-Forwarded-Proto": "https",
            "Forwarded": "x",
            "Cookie": "c",
            "Proxy-Authorization": "p",
            "Authorization": "a",
            "User-Agent": "robot",
        }
    )
    assert kept == {"Authorization": "a", "User-Agent": "robot"}


def test_the_query_must_be_plain_and_small() -> None:
    assert matter_proxy.query_is_acceptable("did=1&signature=x%3D")
    assert matter_proxy.query_is_acceptable("")
    assert not matter_proxy.query_is_acceptable("a b=1")
    assert not matter_proxy.query_is_acceptable("&".join(f"k{i}=1" for i in range(17)))
    assert not matter_proxy.query_is_acceptable("x" * 2000)


def test_a_client_supplied_host_key_counts_like_any_other() -> None:
    assert matter_proxy.query_is_acceptable("__host=evil&did=1")
    assert not matter_proxy.query_is_acceptable("&".join(["__host=1"] + [f"k{i}=1" for i in range(16)]))


def test_the_raw_query_reaches_the_upstream_unchanged(monkeypatch) -> None:
    seen = {}

    async def handler(request):
        seen["raw"] = request.rel_url.raw_query_string
        return web.Response(body=b"ok")

    query = "did=a%zz&sig=%41%7e+x%2Fy"
    response = asyncio.run(_forward_to(handler, monkeypatch, query=query))
    assert response.status_code == 200 and seen["raw"] == query


def test_an_unusable_header_is_logged_at_debug() -> None:
    messages: list[str] = []
    handler = logging.Handler(level=logging.DEBUG)
    handler.emit = lambda record: messages.append(record.getMessage())  # type: ignore[method-assign]
    logger = matter_proxy.logger
    previous = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        assert matter_proxy.forwardable_headers({"Authorization": "x" * 5000}) == {}
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)
    assert any("Authorization" in message for message in messages)


def test_the_rate_limit_is_per_client() -> None:
    limiter = matter_proxy.RateLimiter(limit=3, window=60)
    assert [limiter.allow("a") for _ in range(4)] == [True, True, True, False]
    assert limiter.allow("b")


def test_a_request_must_name_or_come_from_a_known_robot() -> None:
    robots = [{"duid": "D1", "did": "d1", "ips": ["10.0.0.7"], "last_ip": "10.0.0.7"}]
    assert matter_proxy.known_device(robots, {"did": ["d1"]}, "9.9.9.9") == "D1"
    assert matter_proxy.known_device(robots, {"duid": ["D1"]}, "9.9.9.9") == "D1"
    assert matter_proxy.known_device(robots, {"did": ["other"]}, "10.0.0.7") is None
    assert matter_proxy.known_device(robots, {}, "10.0.0.7") == "D1"
    assert matter_proxy.known_device(robots, {}, "9.9.9.9") is None
    assert matter_proxy.known_device([], {}, "10.0.0.7") is None
    assert matter_proxy.known_device(robots, {"device_id": ["d1"]}, "9.9.9.9") is None


def _supervisor(tmp_path, monkeypatch, enabled: bool) -> ReleaseSupervisor:
    monkeypatch.setenv("ROBOROCK_SERVER_MATTER_KEY_PROXY", "true" if enabled else "false")
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    return ReleaseSupervisor(config=config, paths=resolve_paths(config_file, config))


def test_the_route_forwards_for_a_known_robot_and_keeps_values_out_of_the_log(tmp_path, monkeypatch) -> None:
    supervisor = _supervisor(tmp_path, monkeypatch, True)
    calls = []

    async def handler(request):
        calls.append(request.query_string)
        return web.Response(body=b"KEYBYTES")

    def drive():
        client = TestClient(supervisor.app)
        unknown = client.get(PATH + "?did=ghost", headers={"Authorization": "SECRETVALUE"})
        supervisor.runtime_state.upsert_vacuum("D1", did="d1", name="Robot")
        known = client.get(PATH + "?did=d1&signature=QUERYSECRET", headers={"Authorization": "SECRETVALUE"})
        return unknown, known

    async def run():
        app = web.Application()
        app.router.add_get("/fwapi/matter/key", handler)
        async with TestServer(app) as upstream:
            monkeypatch.setattr(matter_proxy, "UPSTREAM_BASE", str(upstream.make_url("")).rstrip("/"))
            return await asyncio.to_thread(drive)

    unknown, known = asyncio.run(run())

    assert unknown.status_code == 403
    assert known.status_code == 200 and known.content == b"KEYBYTES"
    assert calls == ["did=d1&signature=QUERYSECRET"]
    log_text = supervisor.context.http_jsonl.read_text(encoding="utf-8")
    assert "SECRETVALUE" not in log_text and "QUERYSECRET" not in log_text
    entries = [json.loads(line) for line in log_text.splitlines() if "matter_key_proxy" in line]
    assert len(entries) == 2
    assert entries[1]["headers"]["authorization"] == "<redacted>"
    assert entries[1]["raw_path"] == PATH and "signature" in entries[1]["query"]


def test_when_disabled_nothing_is_forwarded(tmp_path, monkeypatch) -> None:
    supervisor = _supervisor(tmp_path, monkeypatch, False)
    called = []

    async def fail_forward(request, region):
        called.append(region)

    monkeypatch.setattr(matter_proxy, "forward", fail_forward)
    supervisor.runtime_state.upsert_vacuum("D1", did="d1", name="Robot")
    response = TestClient(supervisor.app).get(PATH + "?did=d1&signature=QUERYSECRET", headers={"Authorization": "SECRETVALUE"})

    assert called == []
    assert response.content != b"KEYBYTES"
    assert "matter_key_proxy" not in supervisor.context.http_jsonl.read_text(encoding="utf-8")
    log_text = supervisor.context.http_jsonl.read_text(encoding="utf-8")
    assert PATH in log_text and "QUERYSECRET" not in log_text and "SECRETVALUE" not in log_text


def test_the_route_answers_429_after_too_many_requests(tmp_path, monkeypatch) -> None:
    supervisor = _supervisor(tmp_path, monkeypatch, True)
    client = TestClient(supervisor.app)
    codes = [client.get(PATH + "?did=ghost").status_code for _ in range(12)]
    assert codes[:10] == [403] * 10 and codes[10:] == [429, 429]


def test_the_route_records_an_event_without_creating_a_robot_for_a_refused_id(tmp_path, monkeypatch) -> None:
    supervisor = _supervisor(tmp_path, monkeypatch, True)
    TestClient(supervisor.app).get(PATH + "?did=ghost&signature=QUERYSECRET")
    events = [e for e in supervisor.runtime_state.recent_events() if e.get("route") == "matter_key_proxy"]
    assert len(events) == 1 and events[0]["raw_path"] == PATH and events[0]["did"] is None
    assert supervisor.runtime_state.vacuum_snapshot() == []


def _ghost_ids(supervisor) -> list[str]:
    return [str(v.get("duid") or v.get("did")) for v in supervisor.runtime_state.vacuum_snapshot()]


def test_an_extra_id_key_cannot_create_a_robot_beside_a_known_duid(tmp_path, monkeypatch) -> None:
    supervisor = _supervisor(tmp_path, monkeypatch, True)
    supervisor.runtime_state.upsert_vacuum("D1", did="d1", name="Robot")

    async def fake_forward(request, region):
        return Response(content=b"K")

    monkeypatch.setattr(matter_proxy, "forward", fake_forward)
    TestClient(supervisor.app).get(PATH + "?duid=D1&d=ghost")
    events = [e for e in supervisor.runtime_state.recent_events() if e.get("route") == "matter_key_proxy"]
    assert len(events) == 1 and events[0]["did"] == "D1"
    assert "ghost" not in _ghost_ids(supervisor)


def test_an_extra_id_key_cannot_create_a_robot_through_the_address_fallback(tmp_path, monkeypatch) -> None:
    supervisor = _supervisor(tmp_path, monkeypatch, True)
    supervisor.runtime_state.upsert_vacuum("D1", did="d1", name="Robot")
    supervisor.runtime_state.record_http_event(
        event_time="2026-01-01T00:00:00+00:00", route_name="region", clean_path="/region", raw_path="/region",
        method="GET", host="h", remote="10.0.0.7:1", did="D1",
    )

    async def fake_forward(request, region):
        return Response(content=b"K")

    monkeypatch.setattr(matter_proxy, "forward", fake_forward)
    TestClient(supervisor.app, client=("10.0.0.7", 5000)).get(PATH + "?d=ghost")
    assert "ghost" not in _ghost_ids(supervisor)
    assert [e["did"] for e in supervisor.runtime_state.recent_events() if e.get("route") == "matter_key_proxy"] == ["D1"]


def test_the_in_memory_event_has_no_signed_query_with_the_proxy_off(tmp_path, monkeypatch) -> None:
    supervisor = _supervisor(tmp_path, monkeypatch, False)
    TestClient(supervisor.app).get(PATH + "?did=d1&signature=QUERYSECRET")
    events = [e for e in supervisor.runtime_state.recent_events() if e.get("path") == PATH]
    assert events and all("QUERYSECRET" not in json.dumps(e) for e in supervisor.runtime_state.recent_events())
