import asyncio

from fastapi.testclient import TestClient

import roborock_local_server.ota_install as ota_install
from conftest import write_release_config
from roborock_local_server import ota_dry_run
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor
from test_ota_install import Robot
from test_ota_package_dry_run import MD5, PACKAGE, FakeCloud, _no_network  # noqa: F401


class UpdatableCloud(FakeCloud):
    async def firmware_update_info(self, duid, *, lang="en"):
        return {"currentVersion": "02.15.26", "version": "02.16.00", "updatable": True}


def _supervisor(tmp_path, monkeypatch, enable):
    config_file = write_release_config(tmp_path)
    if enable:
        config_file.write_text(config_file.read_text(encoding="utf-8") + "\n[ota]\nenable_install = true\n", encoding="utf-8")
    config = load_config(config_file)
    supervisor = ReleaseSupervisor(config=config, paths=resolve_paths(config_file, config))
    monkeypatch.setattr(supervisor, "_vacuums_payload", lambda: {"vacuums": [{"duid": "robot", "local_key": "k"}]})
    monkeypatch.setattr(supervisor, "cloud_manager", UpdatableCloud(current="02.16.00"))
    return supervisor


def test_the_config_default_is_off(tmp_path) -> None:
    config_file = write_release_config(tmp_path)
    assert load_config(config_file).ota.enable_install is False


def test_the_update_button_is_refused_unless_enabled(tmp_path, monkeypatch) -> None:
    supervisor = _supervisor(tmp_path, monkeypatch, enable=False)
    result = asyncio.run(supervisor._firmware_ota_response("/ota/device/robot/upgrade", "POST", {}))
    assert result[1]["code"] == 501


def test_the_update_button_starts_an_install_of_the_offered_version(tmp_path, monkeypatch) -> None:
    supervisor = _supervisor(tmp_path, monkeypatch, enable=True)
    robot = Robot(["idle", "downloading", "installing", "idle"])

    class FakeClient:
        def __init__(self, *args):
            pass

        async def connect(self):
            pass

        async def send_command(self, method, params):
            return await robot.send_command(method, params)

        async def close(self):
            pass

    monkeypatch.setattr(ota_install, "_RoutineMqttClient", FakeClient)

    async def fake_to_file(url, target):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(PACKAGE)
        return MD5, {}

    monkeypatch.setattr(ota_dry_run, "_download_to_file", fake_to_file)
    monkeypatch.setattr(ota_dry_run, "POLL_SECONDS", 0)
    monkeypatch.setattr(ota_dry_run, "INSTALL_WATCH_SECONDS", 2)

    async def go():
        route, body = await supervisor._firmware_ota_response("/ota/device/robot/upgrade", "POST", {})
        assert body["success"] is True and body["data"]["version"] == "02.16.00"
        again = await supervisor.ota_installer.start("robot")
        assert again["started"] is False
        await asyncio.gather(*supervisor.ota_installer._running.values())

    asyncio.run(go())
    sent = next(params for method, params in robot.asked if method == "miIO.ota")
    assert sent["install"] == "1" and sent["proc"] == "dnld install"
    assert supervisor.ota_installer.results["robot"]["ran"] is True


def test_latest_stable_is_still_refused(tmp_path, monkeypatch) -> None:
    supervisor = _supervisor(tmp_path, monkeypatch, enable=True)
    result = asyncio.run(supervisor._firmware_ota_response("/ota/device/robot/upgrade/latest-stable", "POST", {}))
    assert result[1]["code"] == 501


def test_the_package_cache_keeps_one_file_and_is_cleared_after_a_good_install(tmp_path, monkeypatch) -> None:
    cache = tmp_path / "ota_packages"
    cache.mkdir()
    (cache / "stale.pkg").write_bytes(b"old")
    (cache / "half.pkg.part").write_bytes(b"x")
    (cache / MD5_NAME).write_bytes(b"keep")
    ota_dry_run.clean_package_cache(cache, keep=MD5_NAME)
    assert [p.name for p in cache.iterdir()] == [MD5_NAME]


MD5_NAME = "keep.pkg"


def test_the_env_var_overrides_the_config_file(tmp_path, monkeypatch) -> None:
    config_file = write_release_config(tmp_path)
    monkeypatch.setenv("ROBOROCK_SERVER_OTA_ENABLE_INSTALL", "true")
    assert load_config(config_file).ota.enable_install is True
    monkeypatch.setenv("ROBOROCK_SERVER_OTA_ENABLE_INSTALL", "false")
    assert load_config(config_file).ota.enable_install is False


def test_the_app_polls_the_local_status_during_an_install(tmp_path, monkeypatch) -> None:
    supervisor = _supervisor(tmp_path, monkeypatch, enable=True)
    installer = supervisor.ota_installer
    assert installer.live_status("robot") is None

    async def ask(path, query=None):
        return await supervisor._firmware_ota_response(path, "GET", query or {})

    # Nothing running here: the question goes to the cloud (which the fake cloud answers as an error).
    assert supervisor._local_ota_status("/ota/firmware/robot/upgrade/status", "") is None

    installer._set_live("robot", "START")
    installer._robot_state("robot", "downloading", 42)
    route, body = asyncio.run(ask("/ota/firmware/robot/upgrade/status"))
    assert route == "ota_firmware_status_local"
    assert body["result"]["status"] == "DOWNLOADING" and body["result"]["progress"] == "42"

    installer._robot_state("robot", "installing", 0)
    installer._robot_state("robot", "idle", 0)  # an idle robot mid-install must not look like success
    assert installer.live_status("robot")["status"] == "INSTALLING"

    route, body = asyncio.run(ask("/ota/firmware/upgrade/status", {"duids": ["robot"]}))
    assert body["result"] == [{"duid": "robot", "status": "INSTALLING", "progress": "100", "errCode": 0, "errMsg": ""}]

    installer._set_live("robot", "FAILED", err_msg="The robot did not finish", err_code=1)
    assert installer.live_status("robot")["errMsg"] == "The robot did not finish"


def test_a_finished_install_reports_idle_and_a_failed_one_reports_the_reason(tmp_path, monkeypatch) -> None:
    supervisor = _supervisor(tmp_path, monkeypatch, enable=True)
    robot = Robot(["idle", "downloading", "installing", None, "idle"])

    class FakeClient:
        def __init__(self, *args):
            pass

        async def connect(self):
            pass

        async def send_command(self, method, params):
            return await robot.send_command(method, params)

        async def close(self):
            pass

    async def fake_to_file(url, target):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(PACKAGE)
        return MD5, {}

    monkeypatch.setattr(ota_install, "_RoutineMqttClient", FakeClient)
    monkeypatch.setattr(ota_dry_run, "_download_to_file", fake_to_file)
    monkeypatch.setattr(ota_dry_run, "POLL_SECONDS", 0)
    monkeypatch.setattr(ota_dry_run, "INSTALL_WATCH_SECONDS", 2)

    async def go():
        await supervisor.ota_installer.start("robot")
        assert supervisor.ota_installer.live_status("robot")["status"] in {"START", "DOWNLOADING", "INSTALLING"}
        await asyncio.gather(*supervisor.ota_installer._running.values())

    asyncio.run(go())
    assert supervisor.ota_installer.live_status("robot")["status"] == "IDLE"
    records = list((supervisor.paths.runtime_dir / "ota_results").glob("*_robot.json"))
    assert len(records) == 1 and "trace" in records[0].read_text(encoding="utf-8")


def test_the_progress_does_not_fall_back_to_zero_within_a_phase(tmp_path, monkeypatch) -> None:
    installer = _supervisor(tmp_path, monkeypatch, enable=True).ota_installer
    installer._robot_state("robot", "downloading", 40)
    installer._robot_state("robot", "downloading", None)
    installer._robot_state("robot", "downloading", 0)
    assert installer.live_status("robot")["progress"] == "40"
    installer._robot_state("robot", "downloading", 55)
    assert installer.live_status("robot")["progress"] == "55"
    installer._robot_state("robot", "installing", 0)  # the robot's query answers 0 while installing
    assert installer.live_status("robot")["progress"] == "100"


def test_the_install_logger_is_one_that_has_a_handler() -> None:
    assert ota_install.logger.name == "real_stack.api"


def test_an_unknown_package_path_is_a_404_not_the_generic_ok(tmp_path, monkeypatch) -> None:
    supervisor = _supervisor(tmp_path, monkeypatch, enable=False)
    client = TestClient(supervisor.app)
    assert client.get("/ota_test/abcdefghijklmnopqrstuvwxyz/pkg.signed.pkg").status_code == 404
