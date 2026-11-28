import asyncio
import hashlib

from fastapi.testclient import TestClient
from test_firmware_catalog import MODEL, _supervisor

from roborock_local_server import firmware_scan
from roborock_local_server.firmware_catalog import FirmwareCatalog
from roborock_local_server.firmware_scan import FirmwareScan


def url(version):
    return f"https://cdn.awsusor0.fds.api.mi-img.com/rpkg_{version}.{hashlib.md5(version.encode()).hexdigest()}.signed.pkg"


class FakeCloud:
    def __init__(self, versions, fail_at=None, on_call=None):
        self.urls = {v: url(v) for v in versions}
        self.asked = []
        self.fail_at, self.on_call = fail_at, on_call

    async def iot_get(self, path, params=None):
        self.asked.append(params["version"])
        if self.on_call:
            self.on_call(len(self.asked))
        if self.fail_at == len(self.asked):
            raise RuntimeError("cloud down")
        return {"url": self.urls.get(params["version"])}


async def noop(_seconds):
    pass


def run(scan, cloud, catalog, current, max_empty):
    async def go():
        scan.start(cloud, catalog, "robot", MODEL, current, max_empty)
        await scan.wait()
        return scan.state()

    return asyncio.run(go())


def setup(monkeypatch, tmp_path, versions, headers=("", None), **kwargs):
    async def fake_headers(_url):
        return headers

    monkeypatch.setattr(firmware_scan, "package_headers", fake_headers)
    return FirmwareScan(sleep=noop), FakeCloud(versions, **kwargs), FirmwareCatalog(tmp_path / "catalog.json")


def test_finds_versions_across_a_gap_and_a_major_boundary_then_stops(tmp_path, monkeypatch) -> None:
    found = ["02.05.10", "02.05.03", "02.03.40", "01.99.07"]
    scan, cloud, catalog = setup(monkeypatch, tmp_path, found)
    state = run(scan, cloud, catalog, "02.05.12", 4)
    assert state["found"] == found and state["stoppedReason"] == "empty_minors" and state["running"] is False
    assert [e["version"] for e in catalog.versions(MODEL)] == found
    entry = catalog.entry(MODEL, "02.03.40")
    assert entry["sources"] == ["probe"] and entry["url"] == url("02.03.40") and entry["md5"]
    # 02.05 builds 11..0, then minors 04, 03, 02, 01, 00 and 01.99 at 100 each, then four empty minors
    assert len(cloud.asked) == 12 + 100 * 6 + 400
    assert "02.05.12" not in cloud.asked and "02.05.11" in cloud.asked and cloud.asked[-1] == "01.95.00"


def test_known_versions_count_as_hits_and_are_not_asked_again(tmp_path, monkeypatch) -> None:
    scan, cloud, catalog = setup(monkeypatch, tmp_path, [])
    catalog.add(MODEL, "02.05.03", source="install", url=url("02.05.03"), md5="a" * 32)
    catalog.add(MODEL, "02.04.50", source="install", url=url("02.04.50"), md5="b" * 32)
    state = run(scan, cloud, catalog, "02.05.12", 2)
    assert state["found"] == [] and state["stoppedReason"] == "empty_minors" and state["minorsDone"] == 4
    assert "02.05.03" not in cloud.asked and "02.04.50" not in cloud.asked
    assert len(cloud.asked) == (12 - 1) + (100 - 1) + 200


def test_released_and_size_come_from_the_package_headers(tmp_path, monkeypatch) -> None:
    scan, cloud, catalog = setup(monkeypatch, tmp_path, ["02.05.03"], headers=("2025-07-25T06:27:35Z", 777))
    run(scan, cloud, catalog, "02.05.04", 1)
    entry = catalog.entry(MODEL, "02.05.03")
    assert entry["released"] == "2025-07-25T06:27:35Z" and entry["size"] == 777


def test_headers_are_skipped_when_the_entry_has_both(tmp_path, monkeypatch) -> None:
    scan, cloud, catalog = setup(monkeypatch, tmp_path, ["02.05.03"])
    catalog.add(MODEL, "02.05.03", source="install", size=5, released="2025-01-01T00:00:00Z")
    called = []

    async def spy(_url):
        called.append(1)
        return "", None

    monkeypatch.setattr(firmware_scan, "package_headers", spy)
    state = run(scan, cloud, catalog, "02.05.04", 1)
    assert state["found"] == ["02.05.03"] and called == []


def test_a_cloud_error_stops_the_scan_and_records_where(tmp_path, monkeypatch) -> None:
    scan, cloud, catalog = setup(monkeypatch, tmp_path, ["02.05.10"], fail_at=5)
    state = run(scan, cloud, catalog, "02.05.12", 8)
    assert state["stoppedReason"] == "error" and "cloud down" in state["error"] and state["stoppedAt"] == "02.05.07"
    assert state["found"] == ["02.05.10"] and state["running"] is False and len(cloud.asked) == 5


def test_cancel_stops_the_scan(tmp_path, monkeypatch) -> None:
    scan, cloud, catalog = setup(monkeypatch, tmp_path, [])
    cloud.on_call = lambda n: scan.cancel() if n == 3 else None
    state = run(scan, cloud, catalog, "02.05.12", 8)
    assert state["stoppedReason"] == "cancelled" and len(cloud.asked) == 3
    assert scan.cancel() is False


def test_the_scan_stops_at_the_floor(tmp_path, monkeypatch) -> None:
    scan, cloud, catalog = setup(monkeypatch, tmp_path, ["00.00.01"])
    state = run(scan, cloud, catalog, "00.01.02", 30)
    assert state["stoppedReason"] == "floor" and state["found"] == ["00.00.01"] and "00.00.00" not in cloud.asked


def admin(tmp_path, monkeypatch, reported="02.05.12"):
    supervisor, _ = _supervisor(tmp_path, monkeypatch, reported=reported)
    return supervisor, TestClient(supervisor.app)


def login(client):
    client.post("/admin/api/login", json={"password": "correct horse battery staple"})


def test_scan_routes_require_admin(tmp_path, monkeypatch) -> None:
    _, client = admin(tmp_path, monkeypatch)
    assert client.post("/admin/api/firmware/robot/scan-versions", json={}).status_code == 401
    assert client.get("/admin/api/firmware/scan").status_code == 401
    assert client.post("/admin/api/firmware/scan/cancel").status_code == 401


def test_scan_start_validates_and_refuses(tmp_path, monkeypatch) -> None:
    supervisor, client = admin(tmp_path, monkeypatch)
    login(client)
    for bad in (0, 31, "8", True, 2.5):
        assert client.post("/admin/api/firmware/robot/scan-versions", json={"max_empty_minors": bad}).status_code == 400
    assert client.post("/admin/api/firmware/nobody/scan-versions", json={}).status_code == 404
    supervisor.ota_installer.scan._state = {"running": True}
    refused = client.post("/admin/api/firmware/robot/scan-versions", json={})
    assert refused.status_code == 409 and client.get("/admin/api/firmware/scan").json()["scan"]["running"] is True
    assert client.post("/admin/api/firmware/scan/cancel").json()["cancelled"] is True


def test_scan_start_needs_a_known_version(tmp_path, monkeypatch) -> None:
    supervisor, client = admin(tmp_path, monkeypatch, reported="")

    async def no_info(duid, *, lang="en"):
        return {}

    monkeypatch.setattr(supervisor.cloud_manager, "firmware_update_info", no_info)
    login(client)
    assert client.post("/admin/api/firmware/robot/scan-versions", json={}).status_code == 400


def test_the_installer_starts_a_scan_from_the_reported_version(tmp_path, monkeypatch) -> None:
    supervisor, _ = _supervisor(tmp_path, monkeypatch, reported="02.35.52")
    installer = supervisor.ota_installer
    installer.scan = FirmwareScan(sleep=noop)

    async def no_headers(_url):
        return "", None

    monkeypatch.setattr(firmware_scan, "package_headers", no_headers)

    async def go():
        status, body = await installer.start_scan("robot", 3)
        await installer.scan.wait()
        return status, body

    status, body = asyncio.run(go())
    assert status == 200 and body["scan"]["startVersion"] == "02.35.52" and body["scan"]["running"] is True
    state = installer.scan.state()
    assert "02.33.48" in state["found"] and state["running"] is False
