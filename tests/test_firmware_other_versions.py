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
CONFIRM = ("02.33.48", True, "02.33.48")


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

    started = _install(supervisor, store, robot, lambda: supervisor.ota_installer.start_version("robot", *CONFIRM), "02.33.48")

    assert started == {"started": True, "version": "02.33.48"}
    assert ("/user/devices/robot/fw", {"version": "02.33.48"}) in supervisor.cloud_manager.asked  # asked for THIS robot
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
            "/ota/device/robot/upgrade/version", "POST", {}, {"version": "02.33.48", "confirm_downgrade": True},
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
    assert "no package" in asyncio.run(installer.start_version("robot", "02.20.00", True, "02.20.00"))["reason"]
    supervisor.context.snapshot_store.version = ""
    assert "not known" in asyncio.run(installer.start_version("robot", "02.33.48"))["reason"]


def test_the_cloud_is_asked_for_this_robots_package_and_must_agree_with_the_catalog(tmp_path, monkeypatch, robot) -> None:
    supervisor, store = _supervisor(tmp_path, monkeypatch, reported="02.35.52", extra=ON)
    _remember(supervisor)
    # The catalog's package was learned from another robot; this robot's cloud answer is a different file.
    supervisor.cloud_manager.urls = {"02.33.48": OLD_URL.replace(OLD_MD5, "f" * 32), "02.35.52": NEW_URL}
    started = asyncio.run(supervisor.ota_installer.start_version("robot", *CONFIRM))
    assert started["started"] is False and "differs from the catalog" in started["reason"]
    assert supervisor.ota_installer._running == {} and supervisor.ota_installer.live_status("robot") is None
    assert robot.downloads == []


def test_the_package_must_be_for_the_hardware_the_robot_runs(tmp_path, monkeypatch, robot) -> None:
    supervisor, store = _supervisor(tmp_path, monkeypatch, reported="02.35.52", extra=ON)
    _remember(supervisor)
    own = NEW_URL
    other = OLD_URL.replace("/a245/", "/a101/")
    supervisor.cloud_manager.urls = {"02.33.48": other, "02.35.52": own}
    started = asyncio.run(supervisor.ota_installer.start_version("robot", *CONFIRM))
    assert started["started"] is False and "different hardware" in started["reason"]


def test_a_version_the_cloud_will_not_give_this_robot_is_refused(tmp_path, monkeypatch) -> None:
    supervisor, _ = _supervisor(tmp_path, monkeypatch, reported="02.35.52", extra=ON)
    _remember(supervisor)  # the catalog knows a package, the cloud has none for this robot
    supervisor.cloud_manager.urls = {"02.35.52": NEW_URL}
    started = asyncio.run(supervisor.ota_installer.start_version("robot", *CONFIRM))
    assert started["started"] is False and "no package" in started["reason"]


def test_an_older_version_needs_the_request_to_confirm_it_by_name(tmp_path, monkeypatch, robot) -> None:
    supervisor, store = _supervisor(tmp_path, monkeypatch, reported="02.35.52", extra=ON)
    _remember(supervisor)
    installer = supervisor.ota_installer
    for args in (("02.33.48",), ("02.33.48", True), ("02.33.48", True, "02.30.00"), ("02.33.48", False, "02.33.48")):
        refused = asyncio.run(installer.start_version("robot", *args))
        assert refused["started"] is False and refused["needs_confirmation"] is True and "confirm_downgrade" in refused["reason"]
    assert installer._running == {} and robot.downloads == []

    async def post(body):
        return await supervisor._firmware_ota_response("/ota/device/robot/upgrade/version", "POST", {"version": ["02.33.48"]}, body)

    route, answer = asyncio.run(post({}))  # a version in the query alone is not a confirmation
    assert route == "ota_upgrade_version_refused" and answer["data"]["needs_confirmation"] is True
    route, answer = asyncio.run(post({"confirm_downgrade": True}))
    assert route == "ota_upgrade_version_refused" and answer["data"]["needs_confirmation"] is True
    assert _install(supervisor, store, robot, lambda: installer.start_version("robot", *CONFIRM), "02.33.48")["started"]


def test_a_newer_catalog_version_needs_no_confirmation(tmp_path, monkeypatch, robot) -> None:
    supervisor, store = _supervisor(tmp_path, monkeypatch, reported="02.33.48", extra=ON)
    _remember(supervisor)
    assert _install(supervisor, store, robot, lambda: supervisor.ota_installer.start_version("robot", "02.35.52"), "02.35.52")["started"]


def test_installing_on_a_robot_that_is_not_in_the_inventory_is_a_404(tmp_path, monkeypatch) -> None:
    supervisor, _ = _supervisor(tmp_path, monkeypatch, reported="02.35.52", extra=ON)
    for path in ("/ota/device/stranger/upgrade", "/ota/device/stranger/upgrade/version"):
        route, body = asyncio.run(supervisor._firmware_ota_response(path, "POST", {}, {"version": "02.33.48", "confirm_downgrade": True}))
        assert body["code"] == 404 and body["data"]["started"] is False
    assert supervisor.ota_installer._running == {}


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


def _fake_headers(monkeypatch, result):
    async def fake(url):
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr("roborock_local_server.standalone_admin.package_headers", fake)


def test_the_admin_learns_only_versions_the_cloud_gives_an_address_for(tmp_path, monkeypatch) -> None:
    _fake_headers(monkeypatch, ("", None))
    supervisor, _ = _supervisor(tmp_path, monkeypatch, reported="02.35.52")
    client = TestClient(supervisor.app)
    assert client.post("/admin/api/firmware/robot/learn-versions", json={"versions": ["02.33.48"]}).status_code == 401
    client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    done = client.post("/admin/api/firmware/robot/learn-versions", json={"versions": ["02.33.48", "02.01.01", "bad"]}).json()
    assert done["learned"] == ["02.33.48"] and done["checked"] == 3
    entry = supervisor.ota_installer.catalog.entry(MODEL, "02.33.48")
    assert entry["md5"] == OLD_MD5 and entry["sources"] == ["probe"]
    assert supervisor.ota_installer.catalog.entry(MODEL, "02.01.01") is None
    assert client.post("/admin/api/firmware/robot/learn-versions", json={"versions": []}).status_code == 400


def _learn(client, versions):
    client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    return client.post("/admin/api/firmware/robot/learn-versions", json={"versions": versions})


def test_learn_versions_stores_released_and_size_from_the_package_headers(tmp_path, monkeypatch) -> None:
    _fake_headers(monkeypatch, ("2025-07-25T06:27:35Z", 123456))
    supervisor, _ = _supervisor(tmp_path, monkeypatch, reported="02.35.52")
    assert _learn(TestClient(supervisor.app), ["02.33.48"]).json()["learned"] == ["02.33.48"]
    entry = supervisor.ota_installer.catalog.entry(MODEL, "02.33.48")
    assert entry["released"] == "2025-07-25T06:27:35Z" and entry["size"] == 123456
    info = supervisor.ota_installer.version_info("robot")
    assert [v["released"] for v in info["availableVersions"]] == ["2025-07-25T06:27:35Z"]


def test_a_failing_header_lookup_leaves_released_empty(tmp_path, monkeypatch) -> None:
    _fake_headers(monkeypatch, ("", None))
    supervisor, _ = _supervisor(tmp_path, monkeypatch, reported="02.35.52")
    assert _learn(TestClient(supervisor.app), ["02.33.48"]).json()["learned"] == ["02.33.48"]
    assert "released" not in supervisor.ota_installer.catalog.entry(MODEL, "02.33.48")
    assert supervisor.ota_installer.version_info("robot")["availableVersions"][0]["released"] is None


def test_learn_versions_backfills_an_existing_entry(tmp_path, monkeypatch) -> None:
    _fake_headers(monkeypatch, ("2025-07-25T06:27:35Z", 99))
    supervisor, _ = _supervisor(tmp_path, monkeypatch, reported="02.35.52")
    catalog = supervisor.ota_installer.catalog
    catalog.add(MODEL, "02.33.48", source="install", url=OLD_URL, md5=OLD_MD5, size=5)
    _learn(TestClient(supervisor.app), ["02.33.48"])
    entry = catalog.entry(MODEL, "02.33.48")
    assert entry["released"] == "2025-07-25T06:27:35Z" and entry["size"] == 5

