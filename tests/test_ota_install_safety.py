import asyncio
import json

import pytest
from test_firmware_catalog import MODEL, OLD_MD5, OLD_URL, robot  # noqa: F401  (the fixture)
from test_firmware_catalog import _supervisor as catalog_supervisor
from test_ota_install import PACKAGE_INFO, Robot
from test_ota_package_dry_run import MD5, PACKAGE, URL, FakeCloud
from test_ota_upgrade_button import UpdatableCloud
from test_ota_upgrade_button import _supervisor as button_supervisor

import roborock_local_server.ota_install as ota_install
from roborock_local_server import ota_dry_run
from roborock_local_server.ota_dry_run import OtaDryRun

REPORT = '{"mqttOtaData":{"mqttOtaFirmwareVersion":{"version":"%s"}}}'


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    monkeypatch.setattr(ota_dry_run, "POLL_SECONDS", 0)
    monkeypatch.setattr(ota_dry_run, "INSTALL_WATCH_SECONDS", 2)
    monkeypatch.setattr(ota_install, "REPORT_WAIT_SECONDS", 0.2)
    monkeypatch.setattr(ota_install, "REPORT_POLL_SECONDS", 0.02)


def _client_for(robot):
    class FakeClient:
        def __init__(self, *args):
            pass

        async def connect(self):
            pass

        async def send_command(self, method, params):
            return await robot.send_command(method, params)

        async def close(self):
            pass

    return FakeClient


def _prepare(tmp_path, monkeypatch, states, *, fetch=True, report="02.16.00"):
    """An installer whose robot follows [states]; it fetches the package and reports [report] once sent the install."""
    supervisor = button_supervisor(tmp_path, monkeypatch, enable=True)
    robot = Robot(states)
    if fetch:
        robot.fetch_from = supervisor.ota_dry_run
    if report:
        robot.on_ota = lambda: supervisor.context.snapshot_store.record_firmware_version("robot", REPORT % report)
    monkeypatch.setattr(ota_install, "_RoutineMqttClient", _client_for(robot))

    async def to_file(url, target):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(PACKAGE)
        return MD5, {}

    monkeypatch.setattr(ota_dry_run, "_download_to_file", to_file)
    return supervisor, robot


def _run_install(supervisor):
    async def go():
        assert (await supervisor.ota_installer.start("robot"))["started"] is True
        await asyncio.gather(*supervisor.ota_installer._running.values())

    asyncio.run(go())
    return supervisor.ota_installer.live_status("robot")


def test_two_presses_start_one_install_and_the_second_does_not_fail_the_first(tmp_path, monkeypatch) -> None:
    supervisor = button_supervisor(tmp_path, monkeypatch, enable=True)
    installer = supervisor.ota_installer
    gate, installed = asyncio.Event(), []

    class SlowCloud(UpdatableCloud):
        async def firmware_update_info(self, duid, *, lang="en"):
            await gate.wait()
            return await super().firmware_update_info(duid, lang=lang)

    async def resolve(*args, **kwargs):
        return {"data": b"x", "url": "http://x/p", "md5": MD5}

    async def install(*args, **kwargs):
        installed.append(args[2])

    monkeypatch.setattr(supervisor, "cloud_manager", SlowCloud(current="02.16.00"))
    monkeypatch.setattr(ota_install, "resolve_package", resolve)
    monkeypatch.setattr(installer, "_install", install)

    async def go():
        first = asyncio.create_task(installer.start("robot"))
        await asyncio.sleep(0)
        second = await installer.start("robot")  # while the first still waits on the cloud
        assert second == {"started": False, "reason": ota_install.BUSY_REASON}
        assert installer.live_status("robot") is None  # the refused press did not touch the status
        gate.set()
        assert (await first)["started"] is True
        await asyncio.gather(*installer._running.values())

    asyncio.run(go())
    assert installed == ["02.16.00"]
    assert installer.live_status("robot")["status"] == "START"


def test_the_start_marker_is_released_when_a_start_is_refused(tmp_path, monkeypatch) -> None:
    supervisor = button_supervisor(tmp_path, monkeypatch, enable=True)
    installer = supervisor.ota_installer
    assert asyncio.run(installer.start("nobody"))["started"] is False
    assert installer._claim == "" and not installer._busy()


def test_each_robot_has_its_own_file_slot() -> None:
    dry_run = OtaDryRun()
    for duid, token in (("a", "a" * 24), ("b", "b" * 24)):
        dry_run._slots[duid] = ota_dry_run._Active(token, PACKAGE, MD5, 9e12, filename="f.signed.pkg")

    def status(token):
        return dry_run.file_response(f"/ota_test/{token}/f.signed.pkg", "GET", {}, "x").status_code

    assert (status("a" * 24), status("b" * 24)) == (200, 200)
    del dry_run._slots["a"]
    assert (status("a" * 24), status("b" * 24)) == (404, 200)


def test_a_run_removes_only_its_own_slot() -> None:
    dry_run = OtaDryRun()
    other = ota_dry_run._Active("o" * 24, PACKAGE, MD5, 9e12, filename="f.signed.pkg")
    dry_run._slots["other"] = other
    asyncio.run(dry_run.run(Robot(["idle", "downloading", "idle"]), "https://srv:555", dict(PACKAGE_INFO), None, True, duid="mine"))
    assert dry_run._slots == {"other": other}


def test_a_package_in_use_survives_another_robots_clean_up(tmp_path, monkeypatch) -> None:
    cache = tmp_path / "ota_packages"
    cache.mkdir()
    in_use, stale = f"{'a' * 32}.pkg", f"{'b' * 32}.pkg"
    (cache / in_use).write_bytes(b"x")
    (cache / stale).write_bytes(b"y")
    ota_dry_run.pin_package(in_use)
    ota_dry_run.clean_package_cache(cache)
    assert [p.name for p in cache.iterdir()] == [in_use]
    ota_dry_run.release_package(in_use)
    ota_dry_run.clean_package_cache(cache)
    assert list(cache.iterdir()) == []


def test_resolve_pins_the_package_until_it_is_released(tmp_path, monkeypatch) -> None:
    async def to_file(url, target):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(PACKAGE)
        return MD5, {}

    monkeypatch.setattr(ota_dry_run, "_download_to_file", to_file)
    cache = tmp_path / "ota_packages"
    package = asyncio.run(ota_dry_run.resolve_package(FakeCloud(), "duid", "02.15.26", serve=True, cache_dir=cache))
    ota_dry_run.clean_package_cache(cache)
    assert package["data"].exists()
    ota_dry_run.release_package(package["data"].name)
    ota_dry_run.clean_package_cache(cache)
    assert not package["data"].exists()


def test_a_brief_disconnect_is_not_a_success(tmp_path, monkeypatch) -> None:
    # The reviewer's sequence: idle, idle, offline, idle, with nothing downloaded and no new version.
    supervisor, robot = _prepare(tmp_path, monkeypatch, ["idle", "idle", None, "idle"], fetch=False, report="")
    live = _run_install(supervisor)
    assert live["status"] == "FAILED" and "downloaded the whole package" in live["errMsg"]
    assert supervisor.ota_installer.results["robot"]["file_fetched"] is False


def test_a_partly_fetched_package_is_not_a_success(tmp_path, monkeypatch) -> None:
    supervisor, robot = _prepare(tmp_path, monkeypatch, ["idle", "downloading", "installing", None, "idle"], fetch=False)

    async def half(app_url):
        headers = {"range": f"bytes=0-{len(PACKAGE) // 2}"}
        response = supervisor.ota_dry_run.file_response("/ota_test" + app_url.split("/ota_test", 1)[1], "GET", headers, "robot")
        async for _ in response.body_iterator:
            pass

    robot._fetch = half
    robot.fetch_from = object()
    live = _run_install(supervisor)
    assert live["status"] == "FAILED" and "whole package" in live["errMsg"]


def test_a_robot_that_reports_the_old_version_afterwards_is_not_a_success(tmp_path, monkeypatch) -> None:
    supervisor, _ = _prepare(tmp_path, monkeypatch, ["idle", "downloading", "installing", None, "idle"], report="02.15.26")
    live = _run_install(supervisor)
    assert live["status"] == "FAILED" and "02.15.26" in live["errMsg"] and "02.16.00" in live["errMsg"]


def test_a_robot_that_reports_nothing_afterwards_is_not_a_success(tmp_path, monkeypatch) -> None:
    supervisor, _ = _prepare(tmp_path, monkeypatch, ["idle", "downloading", "installing", None, "idle"], report="")
    live = _run_install(supervisor)
    assert live["status"] == "FAILED" and "nothing" in live["errMsg"]


def test_a_complete_install_that_reports_the_target_is_a_success(tmp_path, monkeypatch) -> None:
    supervisor, _ = _prepare(tmp_path, monkeypatch, ["idle", "downloading", "installing", None, "idle"])
    assert _run_install(supervisor)["status"] == "IDLE"
    assert supervisor.ota_installer.results["robot"]["package_fully_fetched"] is True


@pytest.mark.parametrize("host", sorted(ota_dry_run.PACKAGE_HOSTS))
def test_every_known_package_host_is_accepted(host) -> None:
    assert ota_dry_run.package_md5(f"https://{host}/rriotpkg/a245/x_1_fullos.{MD5}.signed.pkg") == MD5


@pytest.mark.parametrize("url", [
    f"https://evil.example.com/x.{MD5}.signed.pkg",
    f"https://cdn.awsusor0.fds.api.mi-img.com.evil.com/x.{MD5}.signed.pkg",
    f"https://user@evil.com/x.{MD5}.signed.pkg",
    f"https://notroborock.com/x.{MD5}.signed.pkg",
    f"http://cdn.awsusor0.fds.api.mi-img.com/x.{MD5}.signed.pkg",
])
def test_a_package_address_on_another_host_is_refused(url) -> None:
    assert ota_dry_run.package_md5(url) == ""


def test_the_hardware_folder_of_a_package_address() -> None:
    assert ota_dry_run.package_family(URL) == "a101"
    assert ota_dry_run.package_family(f"https://files.roborock.com/x.{MD5}.signed.pkg") == ""


def test_the_hardware_of_the_real_package_address_shapes() -> None:
    folder = f"https://cdn.awsusor0.fds.api.mi-img.com/rriotpkg/a245/rpkg_beryl_lite_3348_fullos.{MD5}.signed.pkg"
    regional = f"https://rrpkg-us.roborock.com/a245/rpkg_beryl_lite_3552_fullos.{MD5}.signed.pkg"
    for url in (folder, regional):
        assert ota_dry_run.package_family(url) == "a245" and ota_dry_run.package_name_prefix(url) == "rpkg_beryl_lite"
    assert ota_dry_run.package_name_prefix(URL) == "pearl-s"
    assert ota_dry_run.package_name_prefix(f"https://files.roborock.com/x.{MD5}.signed.pkg") == ""


@pytest.mark.parametrize(("own", "target", "reason"), [
    (f"https://cdn.awsusor0.fds.api.mi-img.com/rpkg_a245_3552_fullos.{OLD_MD5}.signed.pkg", OLD_URL, "hardware cannot be checked"),
    (f"https://cdn.awsusor0.fds.api.mi-img.com/rriotpkg/a245/rpkg_beryl_lite_3552_fullos.{OLD_MD5}.signed.pkg",
     f"https://cdn.awsusor0.fds.api.mi-img.com/rpkg_beryl_lite_3348_fullos.{OLD_MD5}.signed.pkg", "hardware cannot be checked"),
    (f"https://cdn.awsusor0.fds.api.mi-img.com/rriotpkg/a245/rpkg_other_3552_fullos.{OLD_MD5}.signed.pkg", OLD_URL, "different hardware"),
    (f"https://cdn.awsusor0.fds.api.mi-img.com/rriotpkg/a101/rpkg_beryl_lite_3552_fullos.{OLD_MD5}.signed.pkg", OLD_URL, "different hardware"),
])
def test_a_package_whose_hardware_is_missing_or_different_is_refused(tmp_path, monkeypatch, robot, own, target, reason) -> None:
    supervisor, _ = catalog_supervisor(tmp_path, monkeypatch, reported="02.35.52", extra="allow_downgrade = true\n")
    supervisor.ota_installer.catalog.add(MODEL, "02.33.48", source="robot_reported", url=OLD_URL, md5=OLD_MD5)
    supervisor.cloud_manager.urls = {"02.33.48": target, "02.35.52": own}
    started = asyncio.run(supervisor.ota_installer.start_version("robot", "02.33.48", True, "02.33.48"))
    assert started["started"] is False and reason in started["reason"]
    assert supervisor.ota_installer._running == {} and robot.downloads == []


def test_a_robot_connection_that_cannot_be_built_still_unpins_the_package(tmp_path, monkeypatch) -> None:
    supervisor, _ = _prepare(tmp_path, monkeypatch, ["idle"])

    def broken(*args):
        raise OSError("no certificates")

    monkeypatch.setattr(ota_install, "_RoutineMqttClient", broken)
    live = _run_install(supervisor)
    assert live["status"] == "FAILED" and "no certificates" in live["errMsg"]
    assert ota_dry_run._PINNED == {}


def test_only_robots_in_the_inventory_are_owned(tmp_path, monkeypatch) -> None:
    supervisor = button_supervisor(tmp_path, monkeypatch, enable=True)
    assert supervisor.ota_installer.owns("robot") and not supervisor.ota_installer.owns("someone-elses")


def test_a_downgrade_is_refused_when_the_hardware_of_the_current_package_is_unknown(tmp_path, monkeypatch, robot) -> None:
    supervisor, _ = catalog_supervisor(tmp_path, monkeypatch, reported="02.35.52", extra="allow_downgrade = true\n")
    catalog = supervisor.ota_installer.catalog
    catalog.add(MODEL, "02.33.48", source="robot_reported", url=OLD_URL, md5=OLD_MD5)
    catalog.add(MODEL, "02.35.52", source="cloud_offer")  # no package address for the running version anywhere
    supervisor.cloud_manager.urls = {"02.33.48": OLD_URL}
    started = asyncio.run(supervisor.ota_installer.start_version("robot", "02.33.48", True, "02.33.48"))
    assert started["started"] is False and "hardware cannot be checked" in started["reason"]
    assert supervisor.ota_installer._running == {} and robot.downloads == []


@pytest.mark.parametrize("url", [
    f"https://files.roborock.com:8443/x.{MD5}.signed.pkg",
    f"https://user:pw@files.roborock.com/x.{MD5}.signed.pkg",
    f"https://files.roborock.com/x.pkg?name=x.{MD5}.signed.pkg",
    f"https://files.roborock.com/x.pkg#x.{MD5}.signed.pkg",
])
def test_ports_userinfo_and_a_checksum_outside_the_path_are_refused(url) -> None:
    assert ota_dry_run.package_md5(url) == ""
    assert ota_dry_run.package_md5(f"https://files.roborock.com:443/x.{MD5}.signed.pkg") == MD5


class _Reply:
    def __init__(self, status, location=""):
        self.status, self.headers, self.released = status, ({"Location": location} if location else {}), False

    def release(self):
        self.released = True


class _Session:
    def __init__(self, replies):
        self.replies, self.asked = list(replies), []

    async def request(self, method, url, allow_redirects=True):
        assert allow_redirects is False
        self.asked.append(url)
        return self.replies.pop(0)


def test_a_redirect_to_an_allowed_host_is_followed() -> None:
    good = f"https://cdn.awsusor0.fds.api.mi-img.com/x.{MD5}.signed.pkg"
    session = _Session([_Reply(302, good), _Reply(200)])
    reply = asyncio.run(ota_dry_run._open(session, "GET", f"https://files.roborock.com/x.{MD5}.signed.pkg"))
    assert reply.status == 200 and session.asked[-1] == good


@pytest.mark.parametrize("location", [
    "https://evil.example.com/x.pkg", "http://files.roborock.com/x.pkg", "https://files.roborock.com:81/x.pkg", "https://u@files.roborock.com/x.pkg",
])
def test_a_redirect_off_the_package_hosts_is_refused(location) -> None:
    session = _Session([_Reply(302, location), _Reply(200)])
    with pytest.raises(ota_dry_run.PackageRefused, match="not allowed"):
        asyncio.run(ota_dry_run._open(session, "GET", f"https://files.roborock.com/x.{MD5}.signed.pkg"))
    assert len(session.asked) == 1


def test_a_redirect_loop_is_refused() -> None:
    loop = f"https://files.roborock.com/x.{MD5}.signed.pkg"
    session = _Session([_Reply(302, loop) for _ in range(10)])
    with pytest.raises(ota_dry_run.PackageRefused, match="too many"):
        asyncio.run(ota_dry_run._open(session, "GET", loop))


def test_a_failure_outside_the_watched_part_still_ends_as_failed(tmp_path, monkeypatch) -> None:
    supervisor, robot = _prepare(tmp_path, monkeypatch, ["idle", "downloading", "installing", None, "idle"])

    def broken(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(supervisor.ota_installer, "_write_record", broken)
    live = _run_install(supervisor)
    assert live["status"] == "FAILED" and "disk full" in live["errMsg"]
    assert not supervisor.ota_installer._busy()


def test_a_close_that_raises_does_not_hide_the_result_and_releases_the_package(tmp_path, monkeypatch) -> None:
    supervisor, robot = _prepare(tmp_path, monkeypatch, ["idle", "downloading", "installing", None, "idle"])

    class ClosingBadly(_client_for(robot)):
        async def close(self):
            raise ConnectionError("already gone")

    monkeypatch.setattr(ota_install, "_RoutineMqttClient", ClosingBadly)
    assert _run_install(supervisor)["status"] == "IDLE"
    assert ota_dry_run._PINNED == {}


def test_versions_written_differently_compare_as_the_same(tmp_path, monkeypatch) -> None:
    from roborock_local_server import firmware_versions

    assert firmware_versions.same("2.35.52", "02.35.52") and not firmware_versions.same("2.35.52", "02.35.53")
    assert firmware_versions.same("beta", "beta") and not firmware_versions.same("beta", "02.35.52")
    supervisor, _ = _prepare(tmp_path, monkeypatch, ["idle", "downloading", "installing", None, "idle"], report="2.16.00")
    assert _run_install(supervisor)["status"] == "IDLE"  # the robot spells the target version without the leading zero


def test_the_same_version_written_differently_is_not_a_downgrade_or_another_version(tmp_path, monkeypatch) -> None:
    supervisor, _ = catalog_supervisor(tmp_path, monkeypatch, reported="2.35.52", extra="allow_downgrade = true\n")
    installer = supervisor.ota_installer
    assert installer._is_downgrade("02.35.52", "2.35.52") is False
    assert "already runs" in asyncio.run(installer.start_version("robot", "02.35.52"))["reason"]


def test_the_version_list_marks_the_running_version_whatever_its_spelling(tmp_path, monkeypatch) -> None:
    supervisor, _ = catalog_supervisor(tmp_path, monkeypatch, reported="2.35.52", extra="allow_downgrade = true\n")
    installer = supervisor.ota_installer
    installer.catalog.add(MODEL, "02.35.52", source="cloud_offer", url=OLD_URL, md5=OLD_MD5)
    rows = {row["version"]: row for row in installer.version_info("robot")["availableVersions"]}
    assert rows["02.35.52"]["current"] is True and rows["02.35.52"]["installable"] is False


def test_an_unparseable_version_needs_confirmation(tmp_path, monkeypatch) -> None:
    supervisor, _ = catalog_supervisor(tmp_path, monkeypatch, reported="custom-build", extra="allow_downgrade = true\n")
    installer = supervisor.ota_installer
    installer.catalog.add(MODEL, "02.33.48", source="robot_reported", url=OLD_URL, md5=OLD_MD5)
    assert installer._is_downgrade("beta-1", "02.35.52") is True and installer._is_downgrade("02.33.48", "custom-build") is True
    refused = asyncio.run(installer.start_version("robot", "02.33.48"))
    assert refused["started"] is False and refused["needs_confirmation"] is True


def test_two_version_installs_race_and_only_one_starts(tmp_path, monkeypatch, robot) -> None:
    supervisor, store = catalog_supervisor(tmp_path, monkeypatch, reported="02.35.52", extra="allow_downgrade = true\n")
    catalog = supervisor.ota_installer.catalog
    catalog.add(MODEL, "02.33.48", source="robot_reported", url=OLD_URL, md5=OLD_MD5)
    catalog.add(MODEL, "02.35.52", source="install", url=OLD_URL.replace(OLD_MD5, "a" * 32), md5="a" * 32)
    supervisor.cloud_manager.urls = {"02.33.48": OLD_URL, "02.35.52": OLD_URL.replace(OLD_MD5, "a" * 32)}
    gate = asyncio.Event()
    plain = supervisor.cloud_manager.iot_get

    async def slow(path, params=None):
        await gate.wait()
        return await plain(path, params)

    supervisor.cloud_manager.iot_get = slow
    robot.fetch_from = supervisor.ota_dry_run
    robot.states = ["idle", "downloading", "installing", None, "idle"]
    robot.on_install = lambda params: setattr(store, "version", "02.33.48")

    async def go():
        first = asyncio.create_task(supervisor.ota_installer.start_version("robot", "02.33.48", True, "02.33.48"))
        await asyncio.sleep(0)
        second = await supervisor.ota_installer.start_version("robot", "02.33.48", True, "02.33.48")
        gate.set()
        started = await first
        await asyncio.gather(*supervisor.ota_installer._running.values())
        return started, second

    started, second = asyncio.run(go())
    assert started["started"] is True
    assert second == {"started": False, "reason": ota_install.BUSY_REASON}
    assert supervisor.ota_installer.live_status("robot")["status"] == "IDLE"
