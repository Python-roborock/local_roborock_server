import asyncio
import hashlib
import json

import pytest
from conftest import write_release_config
from test_ota_install import Robot

from roborock_local_server import ota_dry_run, ota_install
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.firmware_catalog import FirmwareCatalog
from roborock_local_server.server import ReleaseSupervisor

MODEL = "roborock.vacuum.a245"
OLD, NEW = b"old firmware" * 50, b"new firmware" * 50
OLD_MD5, NEW_MD5 = hashlib.md5(OLD).hexdigest(), hashlib.md5(NEW).hexdigest()
OLD_URL = f"https://cdn.example.com/rpkg_a245_3348_fullos.{OLD_MD5}.signed.pkg"
NEW_URL = f"https://cdn.example.com/rpkg_a245_3552_fullos.{NEW_MD5}.signed.pkg"
BYTES = {OLD_URL: (OLD, OLD_MD5), NEW_URL: (NEW, NEW_MD5)}


class Store:
    def __init__(self, version):
        self.version = version

    def get(self, duid, include_map=False):
        return {"firmware_version": self.version} if self.version else None


class Cloud:
    """The cloud as it was after a local install: it still believes the robot runs 02.33.48."""

    def __init__(self, urls=None):
        self.urls = urls if urls is not None else {"02.33.48": OLD_URL, "02.35.52": NEW_URL}
        self.asked = []

    async def firmware_update_info(self, duid, *, lang="en"):
        return {"currentVersion": "02.33.48", "version": "02.35.52", "updatable": True}

    async def iot_get(self, path, params=None):
        self.asked.append((path, params))
        return {"url": self.urls.get((params or {}).get("version"))}


def _supervisor(tmp_path, monkeypatch, reported="02.33.48", extra=""):
    config_file = write_release_config(tmp_path)
    config_file.write_text(config_file.read_text(encoding="utf-8") + f"\n[ota]\nenable_install = true\n{extra}", encoding="utf-8")
    config = load_config(config_file)
    supervisor = ReleaseSupervisor(config=config, paths=resolve_paths(config_file, config))
    monkeypatch.setattr(supervisor, "_vacuums_payload", lambda: {"vacuums": [{"duid": "robot", "local_key": "k", "model": MODEL}]})
    monkeypatch.setattr(supervisor, "cloud_manager", Cloud())
    store = Store(reported)
    monkeypatch.setattr(supervisor.context, "snapshot_store", store)
    return supervisor, store


@pytest.fixture
def robot(monkeypatch):
    """A robot that installs whatever it is sent, reboots, and then reports the version installed."""
    robot = Robot(["idle", "downloading", "installing", None, "idle"])
    robot.on_install = lambda params: None

    class FakeClient:
        def __init__(self, *args):
            pass

        async def connect(self):
            pass

        async def send_command(self, method, params):
            if method == "miIO.ota":
                robot.on_install(params)
            return await robot.send_command(method, params)

        async def close(self):
            pass

    async def fake_to_file(url, target):
        data, md5 = BYTES[url]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        robot.downloads.append(url)
        return md5, {}

    robot.downloads = []
    monkeypatch.setattr(ota_install, "_RoutineMqttClient", FakeClient)
    monkeypatch.setattr(ota_dry_run, "_download_to_file", fake_to_file)
    monkeypatch.setattr(ota_dry_run, "POLL_SECONDS", 0)
    monkeypatch.setattr(ota_dry_run, "INSTALL_WATCH_SECONDS", 2)
    return robot


def _install(supervisor, store, robot, start, target):
    robot.states = ["idle", "downloading", "installing", None, "idle"]
    robot.on_install = lambda params: setattr(store, "version", target)

    async def go():
        started = await start()
        await asyncio.gather(*supervisor.ota_installer._running.values())
        return started

    return asyncio.run(go())


def test_entries_are_deduped_per_model_and_version_and_never_removed(tmp_path) -> None:
    catalog = FirmwareCatalog(tmp_path / "catalog.json")
    catalog.add(MODEL, "02.33.48", source="robot_reported", url=OLD_URL, md5=OLD_MD5)
    catalog.add(MODEL, "02.33.48", source="cloud_offer")
    catalog.add(MODEL, "02.35.52", source="cloud_offer")
    catalog.add("roborock.vacuum.a101", "02.15.26", source="install")
    catalog.add(MODEL, "02.33.48", source="install", url=NEW_URL, md5=NEW_MD5)  # another checksum is not taken

    old = catalog.entry(MODEL, "02.33.48")
    assert old["md5"] == OLD_MD5 and old["sources"] == ["robot_reported", "cloud_offer", "install"] and old["first_seen"]
    assert [e["version"] for e in catalog.versions(MODEL)] == ["02.35.52", "02.33.48"]
    assert sorted(catalog.models()) == ["roborock.vacuum.a101", MODEL] and list(catalog.models(MODEL)) == [MODEL]
    assert "02.33.48" in json.loads((tmp_path / "catalog.json").read_text(encoding="utf-8"))["models"][MODEL]


def test_released_is_kept_and_never_overwritten_by_an_empty_value(tmp_path) -> None:
    catalog = FirmwareCatalog(tmp_path / "catalog.json")
    catalog.add(MODEL, "02.33.48", source="probe", released="2025-07-25T06:27:35Z")
    catalog.add(MODEL, "02.33.48", source="install", released="")
    assert catalog.entry(MODEL, "02.33.48")["released"] == "2025-07-25T06:27:35Z"
    catalog.add(MODEL, "02.35.52", source="probe")
    assert "released" not in catalog.entry(MODEL, "02.35.52")


def test_an_install_records_the_version_before_it_and_the_package_installed(tmp_path, monkeypatch, robot) -> None:
    supervisor, store = _supervisor(tmp_path, monkeypatch)
    started = _install(supervisor, store, robot, lambda: supervisor.ota_installer.start("robot"), "02.35.52")

    assert started == {"started": True, "version": "02.35.52"}
    catalog = FirmwareCatalog(supervisor.paths.runtime_dir / "firmware_catalog.json")  # read back from disk
    before, after = catalog.entry(MODEL, "02.33.48"), catalog.entry(MODEL, "02.35.52")
    assert (before["url"], before["md5"], before["sources"]) == (OLD_URL, OLD_MD5, ["robot_reported"])
    assert (after["url"], after["md5"], after["size"], after["sources"]) == (NEW_URL, NEW_MD5, len(NEW), ["install"])
    assert catalog.robot("robot")["previous_version"] == "02.33.48"
    assert catalog.robot("robot")["installed_version"] == "02.35.52"


def test_a_refused_install_does_not_replace_the_remembered_previous_version(tmp_path, monkeypatch, robot) -> None:
    supervisor, store = _supervisor(tmp_path, monkeypatch, reported="02.35.52")
    supervisor.ota_installer.catalog.remember_install("robot", MODEL, "02.33.48", "02.35.52")
    robot.battery = 10
    supervisor.cloud_manager.firmware_update_info = _offer("02.36.00")
    supervisor.cloud_manager.urls["02.36.00"] = NEW_URL
    _install(supervisor, store, robot, lambda: supervisor.ota_installer.start("robot"), "02.36.00")
    assert supervisor.ota_installer.catalog.robot("robot")["previous_version"] == "02.33.48"


def _offer(version):
    async def info(duid, *, lang="en"):
        return {"currentVersion": "02.33.48", "version": version, "updatable": True}

    return info


def test_the_versions_the_cloud_offers_are_learned(tmp_path, monkeypatch) -> None:
    supervisor, _ = _supervisor(tmp_path, monkeypatch)
    installer = supervisor.ota_installer

    async def go():
        installer.learn_offers({"version": "02.35.52", "updatable": True}, "robot")
        installer.learn_offers([{"duid": "robot", "firmwareUpdateResponse": {"version": "02.35.52"}}])
        installer.learn_offers([{"duid": "other", "firmwareUpdateResponse": {"version": "09.00.00"}}])  # unknown model
        await asyncio.gather(*installer._lookups.values())

    asyncio.run(go())
    entry = installer.catalog.entry(MODEL, "02.35.52")
    assert (entry["url"], entry["sources"]) == (NEW_URL, ["cloud_offer"])
    assert supervisor.cloud_manager.asked == [("/user/devices/robot/fw", {"version": "02.35.52"})]
    assert list(installer.catalog.models()) == [MODEL]


def test_the_update_check_feeds_the_catalog(tmp_path, monkeypatch) -> None:
    supervisor, _ = _supervisor(tmp_path, monkeypatch)

    async def go():
        await supervisor._firmware_ota_response("/ota/firmware/robot/updatev2", "GET", {})
        await asyncio.gather(*supervisor.ota_installer._lookups.values())

    supervisor.cloud_manager.iot_get = _updatev2(supervisor.cloud_manager)
    asyncio.run(go())
    assert supervisor.ota_installer.catalog.entry(MODEL, "02.35.52")["md5"] == NEW_MD5


def _updatev2(cloud):
    plain = cloud.iot_get

    async def iot_get(path, params=None):
        if path.endswith("/updatev2"):
            return {"currentVersion": "02.33.48", "version": "02.35.52", "updatable": True}
        return await plain(path, params)

    return iot_get


@pytest.mark.parametrize("keep", [False, True])
def test_the_package_files_are_kept_only_when_configured(tmp_path, monkeypatch, robot, keep) -> None:
    supervisor, store = _supervisor(tmp_path, monkeypatch, extra=f"keep_previous_package = {str(keep).lower()}\n")
    cache = supervisor.ota_installer.cache_dir
    cache.mkdir(parents=True)
    (cache / f"{OLD_MD5}.pkg").write_bytes(OLD)  # the package of the version the robot runs now
    _install(supervisor, store, robot, lambda: supervisor.ota_installer.start("robot"), "02.35.52")
    kept = sorted(path.name for path in cache.iterdir())
    assert kept == (sorted([f"{OLD_MD5}.pkg", f"{NEW_MD5}.pkg"]) if keep else [])


def test_the_admin_lists_the_catalog_for_all_models_or_one(tmp_path, monkeypatch) -> None:
    from fastapi.testclient import TestClient

    supervisor, _ = _supervisor(tmp_path, monkeypatch)
    supervisor.ota_installer.catalog.add(MODEL, "02.33.48", source="install", url=OLD_URL, md5=OLD_MD5)
    supervisor.ota_installer.catalog.add("roborock.vacuum.a101", "02.15.26", source="install")
    client = TestClient(supervisor.app)
    assert client.get("/admin/api/firmware/catalog").status_code == 401
    client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert sorted(client.get("/admin/api/firmware/catalog").json()["models"]) == ["roborock.vacuum.a101", MODEL]
    one = client.get("/admin/api/firmware/catalog", params={"model": MODEL}).json()["models"]
    assert [entry["version"] for entry in one[MODEL]] == ["02.33.48"] and list(one) == [MODEL]
