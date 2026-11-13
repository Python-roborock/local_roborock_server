import asyncio
import hashlib

import pytest
from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server import ota_dry_run
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.ota_dry_run import OtaDryRun, PackageRefused, resolve_package
from roborock_local_server.server import ReleaseSupervisor

PACKAGE = b"not really a firmware, but it has bytes" * 100
MD5 = hashlib.md5(PACKAGE).hexdigest()  # noqa: S324
URL = f"https://cdn.example.com/rriotpkg/a101/pearl-s_1526_fullos.{MD5}.signed.pkg"
DOCKED = [{"state": 8, "battery": 100, "in_cleaning": 0, "error_code": 0}]


class FakeCloud:
    def __init__(self, current="02.15.26", url=URL):
        self.current, self.url, self.asked = current, url, []

    async def firmware_update_info(self, duid, *, lang="en"):
        return {"currentVersion": self.current, "version": self.current, "updatable": False}

    async def iot_get(self, path, params=None):
        self.asked.append((path, params))
        return {"url": self.url}


CDN_HEADERS = {
    "Server": "Byte-nginx", "Content-Type": "application/octet-stream", "Content-Length": "999", "Content-Md5": MD5,
    "Etag": f'"{MD5}"', "X-Xiaomi-Meta-Content-Length": str(len(PACKAGE)), "Last-Modified": "Sat, 26 Jul 2025 09:03:30 GMT",
    "Connection": "keep-alive", "Date": "now", "Accept-Ranges": "bytes",
}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    async def fake_download(url):
        return PACKAGE, dict(CDN_HEADERS)

    monkeypatch.setattr(ota_dry_run, "_download", fake_download)
    monkeypatch.setattr(ota_dry_run, "POLL_SECONDS", 0)
    monkeypatch.setattr(ota_dry_run, "PACKAGE_WATCH_SECONDS", 2)


async def _body(response):
    return b"".join([chunk async for chunk in response.body_iterator])


def test_only_the_current_version_can_be_used() -> None:
    cloud = FakeCloud(current="02.15.26")
    for asked in ("02.99.99", "", "02.15.27"):
        with pytest.raises(PackageRefused, match="current version"):
            asyncio.run(resolve_package(cloud, "duid", asked, serve=True))
    assert cloud.asked == []


def test_an_unexpected_package_address_is_refused() -> None:
    for url in ("http://cdn.example.com/x.%s.signed.pkg" % MD5, "https://cdn.example.com/no-checksum.pkg", None):
        with pytest.raises(PackageRefused, match="not in the expected form"):
            asyncio.run(resolve_package(FakeCloud(url=url), "duid", "02.15.26", serve=True))


def test_a_download_that_does_not_match_its_checksum_is_refused(monkeypatch) -> None:
    async def corrupted(url):
        return PACKAGE + b"!", dict(CDN_HEADERS)

    monkeypatch.setattr(ota_dry_run, "_download", corrupted)
    with pytest.raises(PackageRefused, match="does not match"):
        asyncio.run(resolve_package(FakeCloud(), "duid", "02.15.26", serve=True))


def test_the_address_comes_from_the_cloud_route_with_the_version() -> None:
    cloud = FakeCloud()
    package = asyncio.run(resolve_package(cloud, "duid", "02.15.26", serve=True))

    assert cloud.asked == [("/user/devices/duid/fw", {"version": "02.15.26"})]
    assert (package["url"], package["md5"], package["data"]) == (URL, MD5, PACKAGE)
    assert package["filename"] == f"pearl-s_1526_fullos.{MD5}.signed.pkg"
    assert package["headers"] == {
        "Server": "Byte-nginx", "Content-Type": "application/octet-stream", "Content-Md5": MD5, "Etag": f'"{MD5}"',
        "X-Xiaomi-Meta-Content-Length": str(len(PACKAGE)), "Last-Modified": "Sat, 26 Jul 2025 09:03:30 GMT",
    }


def test_direct_mode_does_not_download_anything(monkeypatch) -> None:
    async def forbidden(url):
        raise AssertionError("must not download")

    monkeypatch.setattr(ota_dry_run, "_download", forbidden)
    package = asyncio.run(resolve_package(FakeCloud(), "duid", "02.15.26", serve=False))
    assert package == {"url": URL, "md5": MD5, "data": None}


class FakeRobot:
    def __init__(self, dry_run, states):
        self.dry_run, self.states, self.asked, self.fetched = dry_run, list(states), [], None

    async def send_command(self, method, params):
        self.asked.append((method, params))
        if method == "get_status":
            return DOCKED
        if method == "get_ota_state":
            return {"ota_state": self.states.pop(0) if len(self.states) > 1 else self.states[0]}
        if method == "get_ota_progress":
            return {"ota_progress": 0}
        if method == "miIO.ota" and params["app_url"].startswith("https://srv"):
            self.fetched = self.dry_run.file_response("/" + params["app_url"].split("/", 3)[3], "GET", {}, "robot")
        return ["ok"]


def test_a_served_package_is_sent_download_only_from_this_server() -> None:
    dry_run = OtaDryRun()
    robot = FakeRobot(dry_run, ["idle", "downloading", "idle"])
    package = {"url": URL, "md5": MD5, "data": PACKAGE}

    result = asyncio.run(dry_run.run(robot, "https://srv:555", package))

    sent = next(params for method, params in robot.asked if method == "miIO.ota")
    assert (sent["install"], sent["proc"], sent["file_md5"]) == ("0", "dnld", MD5)
    assert sent["app_url"].startswith("https://srv:555/ota_test/")
    assert result["package"] is True and result["file_fetched"] is True
    assert asyncio.run(_body(robot.fetched)) == PACKAGE


def test_a_direct_package_gives_the_robot_the_cdn_address_and_serves_nothing() -> None:
    dry_run = OtaDryRun()
    robot = FakeRobot(dry_run, ["idle"])

    result = asyncio.run(dry_run.run(robot, "https://srv:555", {"url": URL, "md5": MD5, "data": None}))

    sent = next(params for method, params in robot.asked if method == "miIO.ota")
    assert (sent["app_url"], sent["install"], sent["proc"]) == (URL, "0", "dnld")
    assert result["file_fetched"] is False


def test_the_package_is_served_under_its_real_file_name_with_the_cdn_headers() -> None:
    dry_run = OtaDryRun()
    robot = FakeRobot(dry_run, ["idle", "downloading", "idle"])
    package = asyncio.run(resolve_package(FakeCloud(), "duid", "02.15.26", serve=True))

    asyncio.run(dry_run.run(robot, "https://srv:555", package))

    sent = next(params for method, params in robot.asked if method == "miIO.ota")
    assert sent["app_url"].endswith(f"/pearl-s_1526_fullos.{MD5}.signed.pkg")
    sent = {name.decode().lower(): value.decode() for name, value in robot.fetched.raw_headers}
    assert sent["etag"] == f'"{MD5}"' and sent["content-md5"] == MD5
    assert sent["x-xiaomi-meta-content-length"] == str(len(PACKAGE))
    assert sent["content-length"] == str(len(PACKAGE))  # this server's own, not the CDN's


def test_only_the_real_file_name_is_served() -> None:
    dry_run = OtaDryRun()
    active = dry_run._active = ota_dry_run._Active("t" * 24, PACKAGE, MD5, 9e12, filename="right.signed.pkg")
    assert dry_run.file_response("/ota_test/" + "t" * 24 + "/right.signed.pkg", "GET", {}, "x").status_code == 200
    assert dry_run.file_response("/ota_test/" + "t" * 24 + "/wrong.signed.pkg", "GET", {}, "x").status_code == 404
    assert len(active.hits) == 1


def test_a_robot_holding_a_staged_package_can_start_another_attempt() -> None:
    dry_run = OtaDryRun()
    robot = FakeRobot(dry_run, ["wait_install", "downloading", "wait_install", "wait_install", "wait_install"])
    package = {"url": URL, "md5": MD5, "data": None}

    result = asyncio.run(dry_run.run(robot, "https://srv:555", package))

    assert result["ran"] is True
    assert result["final_state"] == "wait_install"


def _wire_names(response):
    return [name.decode() for name, _ in response.raw_headers]


def test_the_title_case_variant_sends_header_names_as_written() -> None:
    dry_run = OtaDryRun()
    dry_run._active = ota_dry_run._Active(
        "t" * 24, PACKAGE, MD5, 9e12, filename="f.signed.pkg", headers={"Etag": f'"{MD5}"'}, variant={"title_case": True},
    )
    response = dry_run.file_response("/ota_test/" + "t" * 24 + "/f.signed.pkg", "GET", {}, "x")

    assert _wire_names(response) == ["Content-Type", "Content-Length", "Accept-Ranges", "Etag"]
    assert dict(response.raw_headers)[b"Content-Length"] == str(len(PACKAGE)).encode()


def test_names_are_capitalised_by_default_and_close_is_optional() -> None:
    dry_run = OtaDryRun()
    path = "/ota_test/" + "t" * 24 + "/f.signed.pkg"
    dry_run._active = ota_dry_run._Active("t" * 24, PACKAGE, MD5, 9e12, filename="f.signed.pkg")
    assert "Content-Length" in _wire_names(dry_run.file_response(path, "GET", {}, "x"))  # capitalised by default

    dry_run._active = ota_dry_run._Active("t" * 24, PACKAGE, MD5, 9e12, filename="f.signed.pkg", variant={"title_case": False})
    assert all(name == name.lower() for name in _wire_names(dry_run.file_response(path, "GET", {}, "x")))

    dry_run._active = ota_dry_run._Active("t" * 24, PACKAGE, MD5, 9e12, filename="f.signed.pkg", variant={"title_case": True, "connection_close": True})
    assert "Connection" in _wire_names(dry_run.file_response(path, "GET", {}, "x"))
    dry_run._active = ota_dry_run._Active("t" * 24, PACKAGE, MD5, 9e12, filename="f.signed.pkg", variant={"connection_close": True})
    assert b"close" in dict(dry_run.file_response(path, "GET", {}, "x").raw_headers).values()


def test_the_variant_is_recorded_in_the_result() -> None:
    dry_run = OtaDryRun()
    robot = FakeRobot(dry_run, ["idle", "downloading", "idle"])
    package = {"url": URL, "md5": MD5, "data": PACKAGE, "filename": "x.signed.pkg", "headers": {}}

    result = asyncio.run(dry_run.run(robot, "https://srv:555", package, {"title_case": True}))

    assert result["variant"] == {"title_case": True}
