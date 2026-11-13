import asyncio
import hashlib
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server import ota_dry_run
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.ota_dry_run import OtaDryRun
from roborock_local_server.server import ReleaseSupervisor

DOCKED = [{"state": 8, "battery": 100, "in_cleaning": 0, "error_code": 0}]


class FakeRobot:
    """Plays the robot: answers the reads, and 'downloads' the file when asked to."""

    def __init__(self, dry_run: OtaDryRun, states, status=None, fetch=True):
        self.dry_run, self.states, self.status = dry_run, list(states), status or DOCKED
        self.fetch, self.asked, self.fetched = fetch, [], None

    async def send_command(self, method, params):
        self.asked.append((method, params))
        if method == "get_status":
            return self.status
        if method == "get_ota_state":
            state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            return {"ota_state": state, "ts": 1}
        if method == "get_ota_progress":
            return {"ota_progress": 0}
        if method == "miIO.ota":
            if self.fetch:
                path = "/" + params["app_url"].split("/", 3)[3]
                self.fetched = self.dry_run.file_response(path, "GET", {"user-agent": "robot/1"}, "10.0.0.5")
            return ["ok"]
        raise AssertionError(method)


async def _body(response):
    """The bytes of a streamed response."""
    return b"".join([chunk async for chunk in response.body_iterator])


def _fast(monkeypatch):
    monkeypatch.setattr(ota_dry_run, "POLL_SECONDS", 0)
    monkeypatch.setattr(ota_dry_run, "WATCH_SECONDS", 2)


def test_the_robot_is_asked_to_download_without_installing_and_the_file_is_served(monkeypatch) -> None:
    _fast(monkeypatch)
    dry_run = OtaDryRun()
    robot = FakeRobot(dry_run, ["idle", "idle", "downloading", "failed", "failed", "failed"])

    result = asyncio.run(dry_run.run(robot, "https://srv:555"))

    ota_call = next(params for method, params in robot.asked if method == "miIO.ota")
    assert (ota_call["mode"], ota_call["install"], ota_call["proc"]) == ("normal", "0", "dnld")
    assert ota_call["app_url"].startswith("https://srv:555/ota_test/")
    assert result["ran"] is True and result["file_fetched"] is True
    assert result["hits"][0]["headers"] == {"user-agent": "robot/1"}
    assert [step["state"] for step in result["trace"]][:3] == ["idle", "downloading", "failed"]
    assert result["final_state"] == "failed"
    assert "<token>" in result["params"]["app_url"] and ota_call["app_url"] not in str(result)
    served = robot.fetched
    assert served.status_code == 200 and hashlib.md5(asyncio.run(_body(served))).hexdigest() == ota_call["file_md5"]  # noqa: S324


def test_the_url_stops_working_after_the_run(monkeypatch) -> None:
    _fast(monkeypatch)
    dry_run = OtaDryRun()
    robot = FakeRobot(dry_run, ["idle"])
    asyncio.run(dry_run.run(robot, "https://srv:555"))

    token_path = "/" + next(p for m, p in robot.asked if m == "miIO.ota")["app_url"].split("/", 3)[3]
    assert dry_run.file_response(token_path, "GET", {}, "x").status_code == 404
    assert dry_run.file_response("/ota_test/not-a-real-token-at-all.bin", "GET", {}, "x").status_code == 404
    assert dry_run.file_response("/something/else", "GET", {}, "x") is None


def test_a_robot_that_is_not_docked_idle_and_healthy_is_left_alone(monkeypatch) -> None:
    _fast(monkeypatch)
    for status in ([{"state": 5, "battery": 90, "in_cleaning": 1, "error_code": 0}],
                   [{"state": 8, "battery": 10, "in_cleaning": 0, "error_code": 0}],
                   [{"state": 8, "battery": 90, "in_cleaning": 0, "error_code": 12}]):
        dry_run = OtaDryRun()
        robot = FakeRobot(dry_run, ["idle"], status=status)
        result = asyncio.run(dry_run.run(robot, "https://srv:555"))
        assert result["ran"] is False
        assert all(method != "miIO.ota" for method, _ in robot.asked)


def test_a_robot_already_updating_is_left_alone(monkeypatch) -> None:
    _fast(monkeypatch)
    dry_run = OtaDryRun()
    robot = FakeRobot(dry_run, ["downloading"])
    result = asyncio.run(dry_run.run(robot, "https://srv:555"))
    assert result["ran"] is False and "downloading" in result["reason"]
    assert all(method != "miIO.ota" for method, _ in robot.asked)


def test_range_and_head_requests_are_answered(monkeypatch) -> None:
    _fast(monkeypatch)
    dry_run = OtaDryRun()
    robot = FakeRobot(dry_run, ["idle"], fetch=False)

    async def go():
        # Keep the URL alive for the requests by starting a run and reading the token mid-way.
        original = robot.send_command

        async def spy(method, params):
            if method == "miIO.ota":
                path = "/" + params["app_url"].split("/", 3)[3]
                robot.part = dry_run.file_response(path, "GET", {"range": "bytes=0-9"}, "x")
                robot.head = dry_run.file_response(path, "HEAD", {}, "x")
            return await original(method, params)

        robot.send_command = spy
        return await dry_run.run(robot, "https://srv:555")

    asyncio.run(go())
    assert robot.part.status_code == 206 and dict((k.lower(), v) for k, v in robot.part.raw_headers)[b"content-length"] == b"10"
    assert dict((k.lower(), v) for k, v in robot.part.raw_headers)[b"content-range"].startswith(b"bytes 0-9/")
    assert robot.head.status_code == 200 and robot.head.body == b""
    assert robot.head.headers["content-length"] == str(ota_dry_run.FILE_BYTES)


def test_a_robot_still_showing_a_failed_attempt_can_start_a_new_one(monkeypatch) -> None:
    _fast(monkeypatch)
    dry_run = OtaDryRun()
    # It starts as "failed", then really downloads, then settles: the watch must not stop at the first reading.
    robot = FakeRobot(dry_run, ["failed", "failed", "downloading", "downloading", "idle", "idle", "idle"])

    result = asyncio.run(dry_run.run(robot, "https://srv:555"))

    assert result["ran"] is True
    assert "downloading" in [step["state"] for step in result["trace"]]
    assert result["final_state"] == "idle"


def test_a_robot_that_is_updating_is_still_left_alone(monkeypatch) -> None:
    _fast(monkeypatch)
    for state in ("downloading", "installing"):
        robot = FakeRobot(OtaDryRun(), [state])
        result = asyncio.run(OtaDryRun().run(robot, "https://srv:555"))
        assert result["ran"] is False and "in progress" in result["reason"]


def test_the_file_route_records_how_much_the_robot_took() -> None:
    dry_run = OtaDryRun()
    active = dry_run._active = ota_dry_run._Active("t" * 24, b"x" * (3 * ota_dry_run.CHUNK_BYTES), "md5", 9e12)
    path = "/ota_test/" + "t" * 24 + ".bin"

    async def take_all():
        response = dry_run.file_response(path, "GET", {}, "robot")
        return await _body(response)

    assert len(asyncio.run(take_all())) == 3 * ota_dry_run.CHUNK_BYTES
    assert active.hits[0]["completed"] is True
    assert (active.hits[0]["bytes_sent"], active.hits[0]["of_bytes"]) == (3 * ota_dry_run.CHUNK_BYTES, 3 * ota_dry_run.CHUNK_BYTES)

    async def take_some():
        response = dry_run.file_response(path, "GET", {}, "robot")
        iterator = response.body_iterator
        await iterator.__anext__()
        await iterator.__anext__()
        await iterator.aclose()

    asyncio.run(take_some())
    assert active.hits[1]["completed"] is False
    assert active.hits[1]["bytes_sent"] == ota_dry_run.CHUNK_BYTES and active.hits[1]["of_bytes"] == 3 * ota_dry_run.CHUNK_BYTES
