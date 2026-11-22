import asyncio
import json

from test_ota_upgrade_button import _supervisor as button_supervisor


def test_the_live_status_survives_a_restart_and_a_running_install_turns_into_a_failure(tmp_path, monkeypatch) -> None:
    supervisor = button_supervisor(tmp_path, monkeypatch, enable=True)
    supervisor.ota_installer._set_live("robot", "INSTALLING", "100")
    supervisor.ota_installer._set_live("done", "IDLE", "100")

    from roborock_local_server.ota_install import OtaInstaller

    restarted = OtaInstaller(supervisor)
    live = restarted.live_status("robot")
    assert live["status"] == "FAILED" and "restarted" in live["errMsg"] and live["errCode"] == 1
    assert restarted.live_status("done")["status"] == "IDLE"
    assert "wall" not in live and "at" not in live


def test_a_broken_live_file_is_ignored(tmp_path, monkeypatch) -> None:
    supervisor = button_supervisor(tmp_path, monkeypatch, enable=True)
    path = supervisor.paths.runtime_dir / "ota_live.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    assert supervisor.ota_installer.live_status("robot") is None
    path.write_text(json.dumps({"robot": {"status": "IDLE"}, "x": 5}), encoding="utf-8")
    from roborock_local_server.ota_install import OtaInstaller

    assert OtaInstaller(supervisor).live_status("robot") is None


def test_the_path_form_status_poll_is_forwarded_to_the_cloud(tmp_path, monkeypatch) -> None:
    supervisor = button_supervisor(tmp_path, monkeypatch, enable=True)
    seen = []

    async def iot_get(path, params=None):
        seen.append((path, params))
        return {"status": "IDLE"}

    supervisor.cloud_manager.iot_get = iot_get
    route, body = asyncio.run(supervisor._firmware_ota_response("/ota/firmware/robot/upgrade/status", "GET", {}))
    assert route == "ota_firmware_status" and body["result"] == {"status": "IDLE"}
    assert seen == [("/ota/firmware/robot/upgrade/status", {})]


def test_only_the_read_only_firmware_gets_may_repeat_a_signature(tmp_path, monkeypatch) -> None:
    supervisor = button_supervisor(tmp_path, monkeypatch, enable=True)
    for path in ("/ota/firmware/robot/updatev2", "/ota/firmware/updatev2", "/ota/firmware/upgrade/status", "/ota/firmware/robot/upgrade/status"):
        assert supervisor._is_firmware_read(path)
    for path in ("/ota/device/robot/upgrade", "/ota/device/robot/upgrade/version", "/ota/firmware/robot/other", "/user/homes"):
        assert not supervisor._is_firmware_read(path)
