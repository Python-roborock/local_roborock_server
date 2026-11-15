import asyncio

from fastapi.testclient import TestClient
from test_firmware_catalog import (
    MODEL,
    NEW_MD5,
    NEW_URL,
    OLD_MD5,
    OLD_URL,
    _install,
    _supervisor,
)
from test_firmware_catalog import robot as robot  # noqa: PLC0414  (the fixture)

from roborock_local_server import ota_dry_run

ON = "allow_downgrade = true\n"


def _remember(supervisor):
    catalog = supervisor.ota_installer.catalog
    catalog.add(MODEL, "02.33.48", source="robot_reported", url=OLD_URL, md5=OLD_MD5)
    catalog.add(MODEL, "02.35.52", source="install", url=NEW_URL, md5=NEW_MD5)
    catalog.remember_install("robot", MODEL, "02.33.48", "02.35.52")


def test_the_config_defaults_are_off(tmp_path, monkeypatch) -> None:
    supervisor, _ = _supervisor(tmp_path, monkeypatch)
    assert supervisor.config.ota.allow_downgrade is False and supervisor.config.ota.keep_previous_package is False


def test_another_version_is_refused_unless_opted_in(tmp_path, monkeypatch) -> None:
    supervisor, _ = _supervisor(tmp_path, monkeypatch, reported="02.35.52")
    _remember(supervisor)
    started = asyncio.run(supervisor.ota_installer.start_version("robot"))
    assert started["started"] is False and "allow_downgrade" in started["reason"]
    route, body = asyncio.run(supervisor._firmware_ota_response("/ota/device/robot/upgrade/version", "POST", {}))
    assert route == "ota_upgrade_version_refused" and body["code"] == 409
    assert supervisor.ota_installer._running == {}


def test_install_enable_is_needed_too(tmp_path, monkeypatch) -> None:
    supervisor, _ = _supervisor(tmp_path, monkeypatch, reported="02.35.52", extra=ON)
    monkeypatch.setenv("ROBOROCK_SERVER_OTA_ENABLE_INSTALL", "false")
    from roborock_local_server.config import load_config

    monkeypatch.setattr(supervisor, "config", load_config(supervisor.paths.config_file))
    assert supervisor.ota_installer.other_versions_allowed is False


def test_the_previous_version_is_reinstalled_from_the_remembered_package(tmp_path, monkeypatch, robot) -> None:
    supervisor, store = _supervisor(tmp_path, monkeypatch, reported="02.35.52", extra=ON)
    _remember(supervisor)
    supervisor.cloud_manager.urls = {}  # the cloud is not asked for the address again

    started = _install(supervisor, store, robot, lambda: supervisor.ota_installer.start_version("robot"), "02.33.48")

    assert started == {"started": True, "version": "02.33.48"}
    assert robot.downloads == [OLD_URL]
    sent = next(params for method, params in robot.asked if method == "miIO.ota")
    assert sent["file_md5"] == OLD_MD5 and sent["install"] == "1"
    assert robot.asked[0][0] == "get_status"  # the same docked and battery checks as an update
    assert supervisor.ota_installer.live_status("robot")["status"] == "IDLE"
    # Going back makes the newer one the previous version.
    assert supervisor.ota_installer.catalog.robot("robot")["previous_version"] == "02.35.52"


def test_any_catalog_version_can_be_picked_from_the_app_route(tmp_path, monkeypatch, robot) -> None:
    supervisor, store = _supervisor(tmp_path, monkeypatch, reported="02.35.52", extra=ON)
    _remember(supervisor)

    async def start():
        route, body = await supervisor._firmware_ota_response(
            "/ota/device/robot/upgrade/version", "POST", {"version": ["02.33.48"]},
        )
        assert route == "ota_upgrade_version_started"
        return body["data"]

    assert _install(supervisor, store, robot, start, "02.33.48")["version"] == "02.33.48"


def test_unknown_current_and_missing_versions_are_refused(tmp_path, monkeypatch) -> None:
    supervisor, _ = _supervisor(tmp_path, monkeypatch, reported="02.35.52", extra=ON)
    installer = supervisor.ota_installer
    assert "No previous version" in asyncio.run(installer.start_version("robot"))["reason"]
    _remember(supervisor)
    assert "already runs" in asyncio.run(installer.start_version("robot", "02.35.52"))["reason"]
    assert "not in the firmware catalog" in asyncio.run(installer.start_version("robot", "01.00.00"))["reason"]
    installer.catalog.add(MODEL, "02.20.00", source="cloud_offer")
    assert "no package" in asyncio.run(installer.start_version("robot", "02.20.00"))["reason"]
    supervisor.context.snapshot_store.version = ""
    assert "not known" in asyncio.run(installer.start_version("robot", "02.33.48"))["reason"]


def test_a_stale_address_is_replaced_only_by_the_same_package(tmp_path, monkeypatch, robot) -> None:
    supervisor, store = _supervisor(tmp_path, monkeypatch, reported="02.35.52", extra=ON)
    _remember(supervisor)
    fresh = OLD_URL.replace("cdn.example.com", "cdn2.example.com")
    plain = ota_dry_run._download_to_file

    async def stale_first(url, target):
        if url == OLD_URL:
            raise ota_dry_run.PackageUnavailable("The package server answered HTTP 403")
        return await plain(url.replace("cdn2.example.com", "cdn.example.com"), target)

    monkeypatch.setattr(ota_dry_run, "_download_to_file", stale_first)
    supervisor.cloud_manager.urls = {"02.33.48": fresh}
    assert _install(supervisor, store, robot, lambda: supervisor.ota_installer.start_version("robot"), "02.33.48")["started"]

    supervisor.cloud_manager.urls = {"02.35.52": NEW_URL.replace(NEW_MD5, "f" * 32)}
    monkeypatch.setattr(ota_dry_run, "_download_to_file", _always_403)
    refused = asyncio.run(supervisor.ota_installer.start_version("robot", "02.35.52"))
    assert refused["started"] is False and "no matching one" in refused["reason"]


async def _always_403(url, target):
    raise ota_dry_run.PackageUnavailable("The package server answered HTTP 403")


def test_the_firmware_check_lists_the_models_versions_for_localrock(tmp_path, monkeypatch) -> None:
    supervisor, _ = _supervisor(tmp_path, monkeypatch, reported="02.35.52", extra=ON)
    _remember(supervisor)
    supervisor.ota_installer.catalog.add(MODEL, "02.20.00", source="cloud_offer")

    async def updatev2(path, params=None):
        return {"currentVersion": "02.33.48", "version": "02.35.52", "updatable": True}

    supervisor.cloud_manager.iot_get = updatev2
    _, body = asyncio.run(supervisor._firmware_ota_response("/ota/firmware/robot/updatev2", "GET", {}))
    result = body["result"]
    assert result["currentVersion"] == "02.35.52" and result["updatable"] is False
    assert result["previousVersion"] == "02.33.48" and result["downgradeAllowed"] is True
    assert [(v["version"], v["current"], v["installable"]) for v in result["availableVersions"]] == [
        ("02.35.52", True, False), ("02.33.48", False, True), ("02.20.00", False, False),
    ]


def test_the_firmware_check_says_when_other_versions_are_off(tmp_path, monkeypatch) -> None:
    supervisor, _ = _supervisor(tmp_path, monkeypatch, reported="02.35.52")
    _remember(supervisor)
    info = supervisor.ota_installer.version_info("robot")
    assert info["downgradeAllowed"] is False and not any(v["installable"] for v in info["availableVersions"])
    supervisor.context.snapshot_store.version = "02.33.48"  # back on the previous version: nothing to show
    assert "previousVersion" not in supervisor.ota_installer.version_info("robot")


def test_the_admin_reads_and_triggers_another_version(tmp_path, monkeypatch) -> None:
    supervisor, _ = _supervisor(tmp_path, monkeypatch, reported="02.35.52")
    _remember(supervisor)
    client = TestClient(supervisor.app)
    assert client.get("/admin/api/firmware/robot/versions").status_code == 401
    client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    read = client.get("/admin/api/firmware/robot/versions").json()
    assert read["model"] == MODEL and read["previousVersion"] == "02.33.48" and read["lastInstall"]["installed_version"] == "02.35.52"
    refused = client.post("/admin/api/firmware/robot/install-version", json={"version": "02.33.48"})
    assert refused.status_code == 409 and "allow_downgrade" in refused.json()["reason"]

