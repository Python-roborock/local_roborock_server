import asyncio

import pytest
from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server import ota_dry_run
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.ota_dry_run import OtaDryRun
from roborock_local_server.server import ReleaseSupervisor
from test_ota_package_dry_run import MD5, PACKAGE, URL, FakeCloud, _no_network  # noqa: F401

PACKAGE_INFO = {"url": URL, "md5": MD5, "data": PACKAGE, "filename": f"pearl-s_1526_fullos.{MD5}.signed.pkg", "headers": {}}


class Robot:
    """A robot whose OTA state follows a script; None means it did not answer (rebooting)."""

    def __init__(self, states, battery=100):
        self.states, self.battery, self.asked = list(states), battery, []

    status_extra: dict = {}

    async def send_command(self, method, params):
        self.asked.append((method, params))
        if method == "get_status":
            return [{"state": 8, "battery": self.battery, "in_cleaning": 0, "error_code": 0, **self.status_extra}]
        if method == "get_ota_state":
            state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            if state is None:
                raise TimeoutError("no answer")
            return {"ota_state": state}
        if method == "get_ota_progress":
            return {"ota_progress": 0}
        if method == "miIO.ota":
            return ["ok"]
        raise AssertionError(method)


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    monkeypatch.setattr(ota_dry_run, "POLL_SECONDS", 0)
    monkeypatch.setattr(ota_dry_run, "INSTALL_WATCH_SECONDS", 2)
    monkeypatch.setattr(ota_dry_run, "WAIT_INSTALL_STUCK_SECONDS", 0.3)


def _ota_call(robot):
    return next(params for method, params in robot.asked if method == "miIO.ota")


def test_an_install_asks_for_download_and_install() -> None:
    robot = Robot(["idle", "downloading", "installing", "idle"])
    result = asyncio.run(OtaDryRun().run(robot, "https://srv:555", dict(PACKAGE_INFO), None, install=True))

    sent = _ota_call(robot)
    assert (sent["install"], sent["proc"], sent["file_md5"], sent["mode"]) == ("1", "dnld install", MD5, "normal")
    assert sent["app_url"].endswith(f"/pearl-s_1526_fullos.{MD5}.signed.pkg")
    assert result["install"] is True


def test_a_dry_run_still_only_downloads() -> None:
    robot = Robot(["idle", "downloading", "wait_install"])
    result = asyncio.run(OtaDryRun().run(robot, "https://srv:555", dict(PACKAGE_INFO)))

    sent = _ota_call(robot)
    assert (sent["install"], sent["proc"]) == ("0", "dnld")
    assert result["install"] is False


def test_an_install_needs_a_well_charged_robot_but_a_dry_run_does_not() -> None:
    result = asyncio.run(OtaDryRun().run(Robot(["idle"], battery=70), "https://srv:555", dict(PACKAGE_INFO), None, install=True))
    assert result["ran"] is False and "battery" in result["reason"]

    result = asyncio.run(OtaDryRun().run(Robot(["idle", "wait_install"], battery=70), "https://srv:555", dict(PACKAGE_INFO)))
    assert result["ran"] is True


def test_the_watch_goes_through_wait_install_and_a_reboot() -> None:
    robot = Robot(["idle", "downloading", "wait_install", "installing", "installing", None, None, "idle"])
    result = asyncio.run(OtaDryRun().run(robot, "https://srv:555", dict(PACKAGE_INFO), None, install=True))

    states = [step["state"] for step in result["trace"]]
    assert "installing" in states and None in states
    assert states.index("installing") > states.index("wait_install")
    assert result["saw_offline"] is True
    assert result["final_state"] == "idle"
    assert result["stuck_in_wait_install"] is False


def test_a_robot_that_stays_in_wait_install_is_reported_as_not_installing() -> None:
    robot = Robot(["idle", "downloading", "wait_install"])
    result = asyncio.run(OtaDryRun().run(robot, "https://srv:555", dict(PACKAGE_INFO), None, install=True))

    assert result["stuck_in_wait_install"] is True
    assert result["final_state"] == "wait_install"
    assert result["saw_offline"] is False


def test_a_robot_asleep_on_its_dock_counts_as_docked() -> None:
    sleeping = Robot(["idle", "downloading", "installing", "idle"])
    sleeping.status_extra = {"state": 2, "charge_status": 1}
    result = asyncio.run(OtaDryRun().run(sleeping, "https://srv:555", dict(PACKAGE_INFO), None, install=True))
    assert result["ran"] is True

    off_dock = Robot(["idle"])
    off_dock.status_extra = {"state": 2, "charge_status": 0}
    result = asyncio.run(OtaDryRun().run(off_dock, "https://srv:555", dict(PACKAGE_INFO), None, install=True))
    assert result["ran"] is False and "docked" in result["reason"]
