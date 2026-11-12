from pathlib import Path

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor

CHECK = "/ota/firmware/duid-1/updatev2"
UPGRADE = "/ota/device/duid-1/upgrade"
INFO = {"version": "02.45.78", "currentVersion": "02.43.62", "updatable": True, "desc": "Fixes"}


def _client(tmp_path: Path) -> tuple[TestClient, ReleaseSupervisor]:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    supervisor = ReleaseSupervisor(config=config, paths=resolve_paths(config_file, config))
    return TestClient(supervisor.app), supervisor


def test_firmware_check_is_read_from_the_cloud(tmp_path, monkeypatch) -> None:
    client, supervisor = _client(tmp_path)
    seen = {}

    async def fake(duid, *, lang="en"):
        seen.update(duid=duid, lang=lang)
        return INFO

    monkeypatch.setattr(supervisor.cloud_manager, "firmware_update_info", fake)
    body = client.get(CHECK, params={"lang": "de"}).json()

    assert seen == {"duid": "duid-1", "lang": "de"}
    assert body["success"] is True
    assert body["result"] == INFO and body["data"] == INFO


def test_firmware_check_reports_why_it_is_unavailable(tmp_path, monkeypatch) -> None:
    client, supervisor = _client(tmp_path)

    async def fake(duid, *, lang="en"):
        raise ValueError("No cloud login is stored. Request a code and sign in first.")

    monkeypatch.setattr(supervisor.cloud_manager, "firmware_update_info", fake)
    body = client.get(CHECK).json()

    assert body["success"] is False and body["code"] == 502
    assert "No cloud login" in body["data"]["error"]


def test_firmware_upgrade_is_refused_instead_of_pretending(tmp_path) -> None:
    client, _ = _client(tmp_path)
    body = client.post(UPGRADE, json={}).json()

    assert body["success"] is False and body["code"] == 501
    assert body["msg"] == "firmware_upgrade_not_supported"
