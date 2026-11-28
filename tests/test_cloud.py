import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import aiohttp
import pytest
from roborock.exceptions import RoborockInvalidCredentials, RoborockRateLimit, RoborockTimeout

from roborock_local_server import cloud as cloud_module
from roborock_local_server.backend import _merge_existing_inventory_mutations
from roborock_local_server.cloud import CloudImportManager, _to_jsonable

_FAKE_USER_DATA = object()
_FAKE_HOME_DATA = SimpleNamespace(
    id=1,
    name="Test Home",
    lon=None,
    lat=None,
    geo_name=None,
    products=[],
    devices=[],
    received_devices=[],
    rooms=[],
)


async def _fake_fetch_cloud_home_data_with_api(api, user_data):
    return _FAKE_HOME_DATA


async def _fake_fetch_additional_web_cache(api, user_data, home_data):
    return {}


def _patch_backend_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cloud_module, "_fetch_cloud_home_data_with_api", _fake_fetch_cloud_home_data_with_api)
    monkeypatch.setattr(cloud_module, "_fetch_additional_web_cache", _fake_fetch_additional_web_cache)


_fake_client_instances: list["_FakeRoborockApiClientBase"] = []
_fake_device_counter = 0


class _FakeRoborockApiClientBase:
    """Fake replacing roborock.web_api.RoborockApiClient. No network access."""

    # Subclasses set these to model what getUrlByEmail would resolve to.
    fixed_base_url = "https://euiot.roborock.com"

    def __init__(self, *, username: str, base_url: str | None = None, session=None) -> None:
        global _fake_device_counter
        self.username = username
        self._base_url = base_url or self.fixed_base_url
        _fake_device_counter += 1
        self._device_identifier = f"device-{_fake_device_counter}"
        self.code_login_calls: list[str] = []
        self.code_login_v4_calls: list[tuple[str, str | None, int | None]] = []
        _fake_client_instances.append(self)

    async def request_code_v4(self) -> None:
        return None

    @property
    async def base_url(self):
        return self._base_url

    async def code_login(self, code):
        self.code_login_calls.append(code)
        return _FAKE_USER_DATA

    async def code_login_v4(self, code, country=None, country_code=None):
        self.code_login_v4_calls.append((code, country, country_code))
        return _FAKE_USER_DATA


class _FakeRoborockApiClientV1Fallback(_FakeRoborockApiClientBase):
    """Models the bug scenario: usiot answers country_code=44 but country=None.

    A second lookup (e.g. a fresh client re-deriving from euiot) would answer "GB".
    submit_code() must not trigger that second lookup.
    """

    country_lookup_calls = 0

    @property
    async def country(self):
        type(self).country_lookup_calls += 1
        if type(self).country_lookup_calls == 1:
            return None
        return "GB"

    @property
    async def country_code(self):
        return 44


class _FakeRoborockApiClientV4(_FakeRoborockApiClientBase):
    """Models the normal case: country and country_code both resolved up front."""

    @property
    async def country(self):
        return "GB"

    @property
    async def country_code(self):
        return 44


@pytest.fixture(autouse=True)
def _reset_fake_client_state():
    global _fake_device_counter
    _fake_client_instances.clear()
    _fake_device_counter = 0
    _FakeRoborockApiClientV1Fallback.country_lookup_calls = 0
    yield


class _FakeSchema:
    def __init__(self, payload):
        self._payload = payload

    def as_dict(self):
        return self._payload


def test_to_jsonable_converts_nested_schema_objects() -> None:
    raw = {
        "root": _FakeSchema(
            {
                "child": _FakeSchema({"name": "vacuum"}),
                "items": [_FakeSchema({"id": 1}), Path("/tmp/test")],
            }
        )
    }

    converted = _to_jsonable(raw)

    assert converted == {
        "root": {
            "child": {"name": "vacuum"},
            "items": [{"id": 1}, str(Path("/tmp/test"))],
        }
    }


def test_cloud_inventory_merge_preserves_local_rooms_and_scenes() -> None:
    cloud_inventory = {
        "home": {"id": 123, "name": "Cloud Home", "rooms": [{"id": 1, "name": "Living"}]},
        "rooms": [{"id": 1, "name": "Living"}, {"id": 2, "name": "Kitchen"}],
        "devices": [{"duid": "cloud-device", "name": "Vacuum"}],
        "scenes": [{"id": 10, "name": "Cloud routine"}, {"id": 20, "name": "Cloud-only routine"}],
        "home_scenes": [{"id": 10, "name": "Cloud routine"}, {"id": 20, "name": "Cloud-only routine"}],
        "scene_order": [10, 20],
    }
    existing_inventory = {
        "home": {"id": 123, "name": "Old Home", "rooms": [{"id": 1, "name": "Living local"}]},
        "rooms": [{"id": 1, "name": "Living local"}, {"id": 9, "name": "Office"}],
        "devices": [{"duid": "old-device", "name": "Old Vacuum"}],
        "scenes": [{"id": 10, "name": "Renamed routine"}, {"id": 90, "name": "Local-only routine"}],
        "home_scenes": [{"id": 10, "name": "Renamed routine"}, {"id": 90, "name": "Local-only routine"}],
        "scene_order": [90, 10],
    }

    merged = _merge_existing_inventory_mutations(cloud_inventory, existing_inventory)

    assert merged["devices"] == [{"duid": "cloud-device", "name": "Vacuum"}]
    assert merged["rooms"] == [
        {"id": 1, "name": "Living local"},
        {"id": 2, "name": "Kitchen"},
        {"id": 9, "name": "Office"},
    ]
    assert merged["home"]["rooms"] == merged["rooms"]
    assert merged["scenes"] == [
        {"id": 10, "name": "Renamed routine"},
        {"id": 20, "name": "Cloud-only routine"},
        {"id": 90, "name": "Local-only routine"},
    ]
    assert merged["home_scenes"] == [
        {"id": 10, "name": "Renamed routine"},
        {"id": 20, "name": "Cloud-only routine"},
        {"id": 90, "name": "Local-only routine"},
    ]
    assert merged["scene_order"] == [90, 10, 20]


def test_cloud_refresh_preserves_schedule_occurrence_claims():
    existing = {"schedule_occurrences": {"robot-test": {"42001": 1792789740}}}
    cloud = {"schedules": {"robot-test": [{"id": 42001, "enabled": True}]}}
    merged = _merge_existing_inventory_mutations(cloud, existing)
    assert merged["schedule_occurrences"] == existing["schedule_occurrences"]
    assert merged["schedules"] == cloud["schedules"]
    merged["schedule_occurrences"]["robot-test"]["42001"] += 60
    assert existing["schedule_occurrences"]["robot-test"]["42001"] == 1792789740


def _make_manager(tmp_path: Path) -> CloudImportManager:
    return CloudImportManager(
        inventory_path=tmp_path / "inventory.json",
        snapshot_path=tmp_path / "cloud_snapshot.json",
    )


def test_request_code_falls_back_to_v1_when_country_is_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(cloud_module, "RoborockApiClient", _FakeRoborockApiClientV1Fallback)
    manager = _make_manager(tmp_path)

    result = asyncio.run(manager.request_code(email="user@example.com"))

    assert result["success"] is True
    assert result["country"] is None
    assert result["country_code"] == 44
    assert '"country": null' in json.dumps(result, indent=2)

    session = manager._sessions[result["session_id"]]
    assert session.country is None
    assert session.country_code == 44
    assert session.login_method == "v1"


def test_submit_code_uses_v1_login_when_request_used_v1(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(cloud_module, "RoborockApiClient", _FakeRoborockApiClientV1Fallback)
    _patch_backend_calls(monkeypatch)
    manager = _make_manager(tmp_path)

    request_result = asyncio.run(manager.request_code(email="user@example.com"))
    submit_result = asyncio.run(
        manager.submit_code(session_id=request_result["session_id"], code="123456")
    )

    assert submit_result["success"] is True
    assert len(_fake_client_instances) == 2
    request_client, submit_client = _fake_client_instances
    assert submit_client.code_login_calls == ["123456"]
    assert submit_client.code_login_v4_calls == []
    # A fresh client re-deriving country would see "GB" (euiot); the fix never asks.
    assert _FakeRoborockApiClientV1Fallback.country_lookup_calls == 1
    assert submit_client._device_identifier == request_client._device_identifier


def test_request_code_and_submit_code_use_v4_with_stored_country(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(cloud_module, "RoborockApiClient", _FakeRoborockApiClientV4)
    _patch_backend_calls(monkeypatch)
    manager = _make_manager(tmp_path)

    request_result = asyncio.run(manager.request_code(email="user@example.com"))
    assert request_result["country"] == "GB"
    assert request_result["country_code"] == 44

    session = manager._sessions[request_result["session_id"]]
    assert session.login_method == "v4"

    submit_result = asyncio.run(
        manager.submit_code(session_id=request_result["session_id"], code="654321")
    )

    assert submit_result["success"] is True
    _, submit_client = _fake_client_instances
    assert submit_client.code_login_v4_calls == [("654321", "GB", 44)]
    assert submit_client.code_login_calls == []


def test_submit_code_unknown_session_raises_value_error(tmp_path) -> None:
    manager = _make_manager(tmp_path)

    with pytest.raises(ValueError):
        asyncio.run(manager.submit_code(session_id="does-not-exist", code="123456"))


def test_submit_code_expired_session_raises_value_error(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(cloud_module, "RoborockApiClient", _FakeRoborockApiClientV4)
    _patch_backend_calls(monkeypatch)
    manager = _make_manager(tmp_path)

    request_result = asyncio.run(manager.request_code(email="user@example.com"))
    manager._sessions[request_result["session_id"]].expires_at_ts = 0.0

    with pytest.raises(ValueError):
        asyncio.run(manager.submit_code(session_id=request_result["session_id"], code="123456"))


_STORED_USER_DATA = {
    "rriot": {"u": "u", "s": "s", "h": "h", "k": "k", "r": {"r": "EU", "a": "https://api", "m": "ssl://mqtt", "l": "https://l"}},
    "uid": 1,
    "token": "stored-token",
}
_NEW_CATALOGS = {
    "fetched_at_utc": "2026-11-11T00:00:00+00:00",
    "plugins": {
        "path": "/api/v1/plugins",
        "params": {"type": 2, "apiLevel": 10043},
        "data": {"categoryPluginList": [{"categoryId": 1, "category": "robot.vacuum.cleaner", "version": 7006, "url": "https://files.roborock.com/p.zip", "md5": None}]},
    },
    "appplugin": {
        "path": "/api/v1/appplugin",
        "json": {"type": 2, "apilevel": 10043, "productids": [110]},
        "data": [{"productid": 110, "version": 7006, "apilevel": 10043, "url": "https://files.roborock.com/a.zip"}],
    },
}


def _write_snapshot(manager: CloudImportManager, **overrides) -> None:
    snapshot = {
        "meta": {"username": "user@example.com", "base_url": "https://euiot.roborock.com", "device_identifier": "dev-9"},
        "user_data": _STORED_USER_DATA,
        "web_api_cache": {"rooms": [1, 2], "plugin_catalogs": {"fetched_at_utc": "old"}},
    }
    snapshot.update(overrides)
    manager.snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")


def _patch_plugin_fetch(monkeypatch: pytest.MonkeyPatch, catalogs: dict, seen: dict | None = None) -> None:
    async def fake_catalogs(api, user_data, home_data):
        if seen is not None:
            seen.update(token=user_data.token, device_identifier=api._device_identifier)
        return catalogs

    monkeypatch.setattr(cloud_module, "RoborockApiClient", _FakeRoborockApiClientV4)
    monkeypatch.setattr(cloud_module, "_fetch_cloud_home_data_with_api", _fake_fetch_cloud_home_data_with_api)
    monkeypatch.setattr(cloud_module, "_fetch_plugin_catalogs", fake_catalogs)


def test_refresh_plugin_catalogs_replaces_only_the_catalogs(tmp_path, monkeypatch) -> None:
    manager = _make_manager(tmp_path)
    _write_snapshot(manager)
    seen: dict = {}
    _patch_plugin_fetch(monkeypatch, _NEW_CATALOGS, seen)

    result = asyncio.run(manager.refresh_plugin_catalogs())

    assert seen == {"token": "stored-token", "device_identifier": "dev-9"}
    assert result["success"] is True
    assert result["plugins"]["plugins"] == [
        {"version": 7006, "url": "https://files.roborock.com/p.zip", "categoryId": 1, "category": "robot.vacuum.cleaner"}
    ]
    assert result["appplugin"]["plugins"][0]["url"] == "https://files.roborock.com/a.zip"
    stored = json.loads(manager.snapshot_path.read_text(encoding="utf-8"))
    assert stored["web_api_cache"]["rooms"] == [1, 2]
    assert stored["web_api_cache"]["plugin_catalogs"]["plugins"]["data"]["categoryPluginList"][0]["version"] == 7006
    assert manager.plugin_catalogs()["appplugin"]["plugins"][0]["version"] == 7006


def test_refresh_plugin_catalogs_needs_a_stored_login(tmp_path, monkeypatch) -> None:
    manager = _make_manager(tmp_path)
    _patch_plugin_fetch(monkeypatch, _NEW_CATALOGS)

    with pytest.raises(ValueError, match="No cloud login"):
        asyncio.run(manager.refresh_plugin_catalogs())
    _write_snapshot(manager, user_data={})
    with pytest.raises(ValueError, match="No cloud login"):
        asyncio.run(manager.refresh_plugin_catalogs())


def test_refresh_plugin_catalogs_keeps_the_snapshot_when_the_cloud_gives_nothing(tmp_path, monkeypatch) -> None:
    manager = _make_manager(tmp_path)
    _write_snapshot(manager)
    before = manager.snapshot_path.read_text(encoding="utf-8")
    failing = {"fetched_at_utc": "now", "plugins": {"path": "/p", "error": "code 2010"}, "appplugin": {"path": "/a", "error": "code 2010"}}
    _patch_plugin_fetch(monkeypatch, failing)

    with pytest.raises(ValueError, match="no plugin catalogs"):
        asyncio.run(manager.refresh_plugin_catalogs())
    assert manager.snapshot_path.read_text(encoding="utf-8") == before


def test_refresh_plugin_catalogs_reports_a_rejected_login(tmp_path, monkeypatch) -> None:
    manager = _make_manager(tmp_path)
    _write_snapshot(manager)
    _patch_plugin_fetch(monkeypatch, _NEW_CATALOGS)

    async def rejected(api, user_data):
        raise RoborockInvalidCredentials("invalid token")

    monkeypatch.setattr(cloud_module, "_fetch_cloud_home_data_with_api", rejected)
    with pytest.raises(ValueError, match="sign in again"):
        asyncio.run(manager.refresh_plugin_catalogs())


def test_refresh_plugin_catalogs_keeps_stored_entries_that_failed_this_time(tmp_path, monkeypatch) -> None:
    manager = _make_manager(tmp_path)
    stored_ios = {"path": "/ios", "json": {"type": 1}, "data": [{"productid": 110, "version": 1, "url": "https://files.roborock.com/ios.zip"}]}
    _write_snapshot(manager, web_api_cache={"plugin_catalogs": {"fetched_at_utc": "old", "appplugin_ios": stored_ios}})
    partial = dict(_NEW_CATALOGS, appplugin_ios={"path": "/ios", "error": "No product ids available"})
    _patch_plugin_fetch(monkeypatch, partial)

    result = asyncio.run(manager.refresh_plugin_catalogs())

    assert result["kept_previous"] == ["appplugin_ios"]
    assert result["appplugin_ios"]["plugins"][0]["url"] == "https://files.roborock.com/ios.zip"
    assert "error" not in result["appplugin_ios"]
    stored = json.loads(manager.snapshot_path.read_text(encoding="utf-8"))["web_api_cache"]["plugin_catalogs"]
    assert stored["appplugin_ios"] == {"fetched_at_utc": "old", **stored_ios}
    assert result["appplugin_ios"]["fetched_at_utc"] == "old"
    assert "fetched_at_utc" not in result["appplugin"]
    assert stored["appplugin"]["data"][0]["version"] == 7006


def test_refresh_plugin_catalogs_stores_an_error_entry_when_nothing_good_was_stored(tmp_path, monkeypatch) -> None:
    manager = _make_manager(tmp_path)
    _write_snapshot(manager)
    partial = dict(_NEW_CATALOGS, appplugin_ios={"path": "/ios", "error": "No product ids available"})
    _patch_plugin_fetch(monkeypatch, partial)

    result = asyncio.run(manager.refresh_plugin_catalogs())

    assert "kept_previous" not in result
    assert result["appplugin_ios"]["error"] == "No product ids available"


def test_refresh_plugin_catalogs_does_not_revert_a_sign_in_that_finished_meanwhile(tmp_path, monkeypatch) -> None:
    manager = _make_manager(tmp_path)
    _write_snapshot(manager)

    async def slow_catalogs(api, user_data, home_data):
        # A sign-in lands while the cloud request is in flight.
        _write_snapshot(manager, user_data=dict(_STORED_USER_DATA, token="new-token"), meta={"username": "user@example.com", "source": "new"})
        return _NEW_CATALOGS

    _patch_plugin_fetch(monkeypatch, _NEW_CATALOGS)
    monkeypatch.setattr(cloud_module, "_fetch_plugin_catalogs", slow_catalogs)

    with pytest.raises(ValueError, match="new sign-in finished"):
        asyncio.run(manager.refresh_plugin_catalogs())
    stored = json.loads(manager.snapshot_path.read_text(encoding="utf-8"))
    assert stored["user_data"]["token"] == "new-token"
    assert stored["meta"]["source"] == "new"


def test_refresh_plugin_catalogs_reports_a_snapshot_that_vanished_meanwhile(tmp_path, monkeypatch) -> None:
    manager = _make_manager(tmp_path)
    _write_snapshot(manager)

    async def slow_catalogs(api, user_data, home_data):
        manager.snapshot_path.write_text("{ not json", encoding="utf-8")
        return _NEW_CATALOGS

    _patch_plugin_fetch(monkeypatch, _NEW_CATALOGS)
    monkeypatch.setattr(cloud_module, "_fetch_plugin_catalogs", slow_catalogs)

    with pytest.raises(ValueError, match="missing or unreadable"):
        asyncio.run(manager.refresh_plugin_catalogs())


def test_refresh_plugin_catalogs_keeps_other_snapshot_changes_made_meanwhile(tmp_path, monkeypatch) -> None:
    manager = _make_manager(tmp_path)
    _write_snapshot(manager)

    async def slow_catalogs(api, user_data, home_data):
        _write_snapshot(manager, web_api_cache={"rooms": [9], "plugin_catalogs": {"fetched_at_utc": "old"}})
        return _NEW_CATALOGS

    _patch_plugin_fetch(monkeypatch, _NEW_CATALOGS)
    monkeypatch.setattr(cloud_module, "_fetch_plugin_catalogs", slow_catalogs)

    asyncio.run(manager.refresh_plugin_catalogs())

    stored = json.loads(manager.snapshot_path.read_text(encoding="utf-8"))
    assert stored["web_api_cache"]["rooms"] == [9]
    assert stored["web_api_cache"]["plugin_catalogs"]["appplugin"]["data"][0]["version"] == 7006


def test_snapshot_writes_go_through_the_atomic_writer(tmp_path, monkeypatch) -> None:
    written: list[Path] = []
    real = cloud_module.atomic_write_inventory

    def spy(path, data):
        written.append(path)
        real(path, data)

    monkeypatch.setattr(cloud_module, "atomic_write_inventory", spy)
    manager = _make_manager(tmp_path)
    _write_snapshot(manager)
    _patch_plugin_fetch(monkeypatch, _NEW_CATALOGS)
    asyncio.run(manager.refresh_plugin_catalogs())
    _patch_backend_calls(monkeypatch)
    request_result = asyncio.run(manager.request_code(email="user@example.com"))
    asyncio.run(manager.submit_code(session_id=request_result["session_id"], code="123456"))

    assert written.count(manager.snapshot_path) == 2
    assert not list(manager.snapshot_path.parent.glob(".*.tmp"))


def test_refresh_plugin_catalogs_leaves_the_snapshot_intact_when_the_write_fails(tmp_path, monkeypatch) -> None:
    manager = _make_manager(tmp_path)
    _write_snapshot(manager)
    before = manager.snapshot_path.read_text(encoding="utf-8")
    _patch_plugin_fetch(monkeypatch, _NEW_CATALOGS)

    def boom(path, data):
        raise OSError("disk full")

    monkeypatch.setattr(cloud_module, "atomic_write_inventory", boom)
    with pytest.raises(OSError):
        asyncio.run(manager.refresh_plugin_catalogs())
    assert manager.snapshot_path.read_text(encoding="utf-8") == before


def test_submit_code_stores_the_device_identifier(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(cloud_module, "RoborockApiClient", _FakeRoborockApiClientV4)
    _patch_backend_calls(monkeypatch)
    manager = _make_manager(tmp_path)

    request_result = asyncio.run(manager.request_code(email="user@example.com"))
    asyncio.run(manager.submit_code(session_id=request_result["session_id"], code="123456"))

    stored = json.loads(manager.snapshot_path.read_text(encoding="utf-8"))
    assert stored["meta"]["device_identifier"] == _fake_client_instances[0]._device_identifier


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (RoborockRateLimit("slow down"), "rate limiting"),
        (RoborockInvalidCredentials("bad token"), "sign in again"),
        (TimeoutError(), "did not answer in time"),
        (RoborockTimeout("t"), "did not answer in time"),
        (aiohttp.ClientConnectionError("dns"), "could not be reached"),
        (RuntimeError("something odd"), "request failed"),
    ],
)
def test_refresh_plugin_catalogs_gives_each_failure_its_own_message(tmp_path, monkeypatch, error, expected) -> None:
    manager = _make_manager(tmp_path)
    _write_snapshot(manager)
    _patch_plugin_fetch(monkeypatch, _NEW_CATALOGS)

    async def failing(api, user_data):
        raise error

    monkeypatch.setattr(cloud_module, "_fetch_cloud_home_data_with_api", failing)
    with pytest.raises(ValueError, match=expected) as raised:
        asyncio.run(manager.refresh_plugin_catalogs())
    if expected != "sign in again":
        assert "sign in again" not in str(raised.value)


def test_refresh_error_classifier_follows_the_cause_chain() -> None:
    try:
        try:
            raise RoborockInvalidCredentials("expired")
        except RoborockInvalidCredentials as inner:
            raise RuntimeError("Failed to fetch cloud home_data: expired") from inner
    except RuntimeError as outer:
        assert "sign in again" in cloud_module._describe_refresh_error(outer)


def test_firmware_update_info_is_read_with_the_stored_login(tmp_path, monkeypatch) -> None:
    manager = _make_manager(tmp_path)
    _write_snapshot(manager)
    seen: dict = {}

    async def fake_hawk(api, user_data, path, *, params=None):
        seen.update(path=path, params=params, token=user_data.token, device_identifier=api._device_identifier)
        return {"version": "02.45.78", "updatable": True}

    monkeypatch.setattr(cloud_module, "RoborockApiClient", _FakeRoborockApiClientV4)
    monkeypatch.setattr(cloud_module, "_hawk_get_result", fake_hawk)

    result = asyncio.run(manager.firmware_update_info("duid-1", lang="de"))

    assert result == {"version": "02.45.78", "updatable": True}
    assert seen == {
        "path": "/ota/firmware/duid-1/updatev2", "params": {"lang": "de"},
        "token": "stored-token", "device_identifier": "dev-9",
    }


def test_firmware_update_info_needs_a_stored_login(tmp_path) -> None:
    with pytest.raises(ValueError, match="No cloud login"):
        asyncio.run(_make_manager(tmp_path).firmware_update_info("duid-1"))


_HOME = {
    "products": [{"id": "p116", "model": "roborock.vacuum.a101"}, {"id": "p223", "model": "roborock.vacuum.a245"}],
    "devices": [
        {"duid": "pro", "name": "Quevo", "product_id": "p116", "fv": "02.15.26", "online": True},
        {"duid": "flow", "name": "Curv", "product_id": "p223", "fv": "02.40.00", "online": False},
    ],
    "received_devices": [],
}


def test_firmware_status_lists_every_account_robot_and_isolates_failures(tmp_path, monkeypatch) -> None:
    manager = _make_manager(tmp_path)
    _write_snapshot(manager, home_data=_HOME)
    asked: list = []

    async def fake_iot_get(path, params=None):
        asked.append((path, params))
        if params["duids"] == "pro":
            raise RuntimeError("boom")
        return [{"version": "02.45.78", "updatable": True}]

    monkeypatch.setattr(manager, "iot_get", fake_iot_get)
    rows = asyncio.run(manager.firmware_status(lang="de"))

    assert asked == [
        ("/ota/firmware/updatev2", {"duids": "pro", "lang": "de"}),
        ("/ota/firmware/updatev2", {"duids": "flow", "lang": "de"}),
    ]
    assert [(r["name"], r["model"], r["cloud_firmware"]) for r in rows] == [
        ("Quevo", "roborock.vacuum.a101", "02.15.26"), ("Curv", "roborock.vacuum.a245", "02.40.00"),
    ]
    assert rows[0]["error"] == "boom" and "update" not in rows[0]
    assert rows[1]["update"] == [{"version": "02.45.78", "updatable": True}]


def test_firmware_status_needs_a_login_and_devices(tmp_path) -> None:
    manager = _make_manager(tmp_path)
    with pytest.raises(ValueError, match="No cloud login"):
        asyncio.run(manager.firmware_status())
    _write_snapshot(manager)
    with pytest.raises(ValueError, match="No devices are stored"):
        asyncio.run(manager.firmware_status())
