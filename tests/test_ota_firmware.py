from pathlib import Path

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor
from shared.protocol_auth import ProtocolAuthStore, build_hawk_authorization
from test_admin_api import _hawk_headers, _seed_protocol_snapshot

CHECK = "/ota/firmware/updatev2"
CHECK_BY_PATH = "/ota/firmware/duid-1/updatev2"
STATUS = "/ota/firmware/upgrade/status"
UPGRADE = "/ota/device/duid-1/upgrade"
LATEST_STABLE = "/ota/device/duid-1/upgrade/latest-stable"
INFO = {"version": "02.45.78", "currentVersion": "02.43.62", "updatable": True, "desc": "Fixes"}


def _client(tmp_path: Path) -> tuple[TestClient, ReleaseSupervisor, Path]:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    _seed_protocol_snapshot(paths.cloud_snapshot_path)
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    return TestClient(supervisor.app), supervisor, paths.cloud_snapshot_path


def _signed(snapshot: Path, path: str, **query: str) -> dict[str, str]:
    user = ProtocolAuthStore(snapshot).availability().user
    assert user is not None
    return {"Authorization": build_hawk_authorization(
        user=user, path=path, query_values=query or None, nonce="n-" + path.replace("/", "-"),
    )}


def _record_reads(supervisor, monkeypatch, result=INFO, error=None) -> list:
    calls: list = []

    async def fake(path, params=None):
        calls.append((path, params))
        if error:
            raise error
        return result

    monkeypatch.setattr(supervisor.cloud_manager, "iot_get", fake)
    return calls


def test_the_apps_check_is_read_from_the_cloud(tmp_path, monkeypatch) -> None:
    client, supervisor, snapshot = _client(tmp_path)
    calls = _record_reads(supervisor, monkeypatch, result=[INFO])

    body = client.get(CHECK, params={"duids": "duid-1", "lang": "de"}, headers=_signed(snapshot, CHECK, duids="duid-1", lang="de")).json()

    assert calls == [("/ota/firmware/updatev2", {"duids": "duid-1", "lang": "de"})]
    assert body["success"] is True and body["result"] == [INFO] and body["data"] == [INFO]


def test_the_older_path_style_check_is_read_from_the_cloud(tmp_path, monkeypatch) -> None:
    client, supervisor, snapshot = _client(tmp_path)
    calls = _record_reads(supervisor, monkeypatch)

    body = client.get(CHECK_BY_PATH, headers=_signed(snapshot, CHECK_BY_PATH)).json()

    assert calls == [("/ota/firmware/duid-1/updatev2", {"lang": "en"})]
    assert body["result"] == INFO


def test_upgrade_progress_is_read_from_the_cloud(tmp_path, monkeypatch) -> None:
    client, supervisor, snapshot = _client(tmp_path)
    calls = _record_reads(supervisor, monkeypatch, result={"status": "idle"})

    body = client.get(STATUS, params={"duids": "duid-1"}, headers=_signed(snapshot, STATUS, duids="duid-1")).json()

    assert calls == [("/ota/firmware/upgrade/status", {"duids": "duid-1"})]
    assert body["result"] == {"status": "idle"}


def test_a_failed_read_reports_why(tmp_path, monkeypatch) -> None:
    client, supervisor, snapshot = _client(tmp_path)
    _record_reads(supervisor, monkeypatch, error=ValueError("No cloud login is stored. Request a code and sign in first."))

    body = client.get(CHECK, params={"duids": "duid-1"}, headers=_signed(snapshot, CHECK, duids="duid-1")).json()

    assert body["success"] is False and body["code"] == 502
    assert "No cloud login" in body["data"]["error"]


def test_upgrades_are_refused_instead_of_pretending(tmp_path) -> None:
    client, _, snapshot = _client(tmp_path)
    for path in (UPGRADE, LATEST_STABLE):
        body = client.post(path, json={}, headers=_hawk_headers(snapshot, path, json_values={})).json()
        assert body["success"] is False and body["code"] == 501
        assert body["msg"] == "firmware_upgrade_not_supported"


def test_firmware_routes_need_the_app_signature(tmp_path, monkeypatch) -> None:
    client, supervisor, _ = _client(tmp_path)
    calls = _record_reads(supervisor, monkeypatch)

    assert client.get(CHECK, params={"duids": "duid-1"}).status_code == 401
    assert client.get(STATUS, params={"duids": "duid-1"}).status_code == 401
    assert client.post(UPGRADE, json={}).status_code == 401
    assert calls == []


def test_a_resent_firmware_read_is_not_refused_as_a_replay(tmp_path, monkeypatch) -> None:
    client, supervisor, snapshot = _client(tmp_path)
    _record_reads(supervisor, monkeypatch, result={"status": "idle"})
    headers = _signed(snapshot, STATUS, duids="duid-1")

    first = client.get(STATUS, params={"duids": "duid-1"}, headers=headers)
    again = client.get(STATUS, params={"duids": "duid-1"}, headers=headers)

    assert first.json()["success"] is True and again.json()["success"] is True


def test_a_tampered_firmware_read_is_still_refused(tmp_path, monkeypatch) -> None:
    client, supervisor, snapshot = _client(tmp_path)
    calls = _record_reads(supervisor, monkeypatch)
    headers = _signed(snapshot, STATUS, duids="duid-1")

    assert client.get(STATUS, params={"duids": "duid-2"}, headers=headers).status_code == 401
    assert calls == []


def test_an_upgrade_post_is_still_refused_as_a_replay(tmp_path) -> None:
    client, _, snapshot = _client(tmp_path)
    headers = _hawk_headers(snapshot, UPGRADE, json_values={})

    assert client.post(UPGRADE, json={}, headers=headers).json()["code"] == 501
    assert client.post(UPGRADE, json={}, headers=headers).status_code == 401
