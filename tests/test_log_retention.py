from __future__ import annotations

import json
import logging
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import write_release_config

from roborock_local_server import backend as _backend  # noqa: F401
from roborock_local_server import log_retention
from roborock_local_server.backend import append_jsonl as backend_append
from roborock_local_server.bundled_backend.https_server.routes.user.scene.service import (
    _scene_zone_ranges_from_mqtt,
)
from roborock_local_server.bundled_backend.shared.io_utils import (
    append_jsonl,
    setup_file_logger,
)
from roborock_local_server.bundled_backend.shared.runtime_credentials import (
    RuntimeCredentialsStore,
)
from roborock_local_server.bundled_backend.shared.zone_ranges_store import (
    ZoneRangesStore,
)
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.log_retention import (
    BoundedRotatingFileHandler,
    configure_jsonl_logging,
    iter_log_lines,
    log_paths,
)
from roborock_local_server.server import ReleaseSupervisor


def _record(message: str) -> logging.LogRecord:
    return logging.LogRecord("test", logging.INFO, "", 0, message, (), None)


def _retained_json(path: Path) -> list[dict]:
    return [json.loads(line) for line in iter_log_lines(path)]


@pytest.mark.parametrize("backup_count", [0, 2])
def test_service_logs_rotate_and_expire_old_records(tmp_path, capsys, backup_count):
    path = tmp_path / "api_server.log"
    logger = setup_file_logger("rotation", path, max_bytes=150, backup_count=backup_count)
    try:
        for index in range(30):
            logger.info("event-%02d %s", index, "x" * 60)
        files = [p for p in log_paths(path) if p.exists()]
        assert len(files) == backup_count + 1
        assert all(p.stat().st_size <= 150 for p in files)
        retained = "".join(iter_log_lines(path))
        assert "event-29" in retained
        assert "event-00" not in retained
        output = capsys.readouterr().err
        assert "event-00" in output and "event-29" in output
    finally:
        for handler in logger.handlers:
            handler.close()


def test_utf8_byte_limit_and_whole_oversized_record(tmp_path):
    path = tmp_path / "test.log"
    handler = BoundedRotatingFileHandler(path, max_bytes=12, backup_count=2)
    try:
        handler.handle(_record("ééé"))  # Seven bytes, including the newline.
        handler.handle(_record("ééé"))
        assert path.with_name("test.log.1").read_bytes() == "ééé\n".encode()
        handler.handle(_record("z" * 40))
        assert path.read_bytes() == b"z" * 40 + b"\n"
        handler.handle(_record("new"))
        assert path.read_text() == "new\n"
        assert path.with_name("test.log.1").read_bytes() == b"z" * 40 + b"\n"
    finally:
        handler.close()


@pytest.mark.parametrize("backup_count", [0, 3])
def test_jsonl_rotation_preserves_format_and_limits_backups(tmp_path, backup_count):
    path = tmp_path / "decompiled_http.jsonl"
    configure_jsonl_logging(path, max_bytes=70, backup_count=backup_count)
    for index in range(20):
        append_jsonl(path, {"index": index, "message": "room\nwith unicode é"})
    records = _retained_json(path)
    assert [entry["index"] for entry in records] == list(range(19 - backup_count, 20))
    assert all(p.stat().st_size <= 70 for p in log_paths(path))


def test_concurrent_jsonl_writes_share_lock_across_backend_import_paths(tmp_path):
    path = tmp_path / "decompiled_mqtt.jsonl"
    configure_jsonl_logging(path, max_bytes=128, backup_count=20)

    def write(index):
        writer = append_jsonl if index % 2 else backend_append
        writer(path, {"index": index, "text": "é\n"})

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(write, range(60)))
    records = _retained_json(path)
    assert sorted(entry["index"] for entry in records) == list(range(60))
    assert all(p.stat().st_size <= 128 for p in log_paths(path))


def test_restart_trims_legacy_logs_and_reduced_retention_only(tmp_path):
    path = tmp_path / "decompiled_http.jsonl"
    old = b'{"old":true}\n' * 100
    recent = b'{"recent":true}\n'
    for suffix in ("", ".1", ".2", ".3", ".4"):
        path.with_name(path.name + suffix).write_bytes(old + recent + b'{"partial":')
    unrelated = tmp_path / "runtime_credentials.json"
    unrelated.write_bytes(old)
    manual_copy = path.with_name(path.name + ".saved")
    manual_copy.write_bytes(old)

    configure_jsonl_logging(path, max_bytes=60, backup_count=2)

    assert not path.with_name(path.name + ".3").exists()
    assert not path.with_name(path.name + ".4").exists()
    assert unrelated.read_bytes() == old
    assert manual_copy.read_bytes() == old
    for retained in log_paths(path):
        assert retained.stat().st_size <= 60
        assert json.loads(retained.read_text().splitlines()[-1]) == {"recent": True}
        assert all(isinstance(json.loads(line), dict) for line in retained.read_text().splitlines())
    append_jsonl(path, {"after_restart": True})
    assert _retained_json(path)[-1] == {"after_restart": True}


def test_migration_does_not_load_entire_legacy_file(tmp_path):
    path = tmp_path / "large.log"
    with path.open("wb") as handle:
        handle.seek(16 * 1024 * 1024)
        handle.write(b"\nkeep this recent line\n")
    tracemalloc.start()
    try:
        handler = BoundedRotatingFileHandler(path, max_bytes=128, backup_count=1)
        _, peak = tracemalloc.get_traced_memory()
        handler.close()
    finally:
        tracemalloc.stop()
    assert peak < 1024 * 1024
    assert path.read_bytes() == b"keep this recent line\n"


def test_failed_atomic_trim_leaves_original_log_intact(tmp_path, monkeypatch):
    path = tmp_path / "test.log"
    original = b"old entry\n" * 30
    path.write_bytes(original)

    def fail_replace(source, destination):
        raise OSError("replacement failed")

    monkeypatch.setattr(log_retention.os, "replace", fail_replace)
    with pytest.raises(OSError, match="replacement failed"):
        BoundedRotatingFileHandler(path, max_bytes=100, backup_count=1)
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


def test_reconfiguring_logger_closes_previous_file_handler(tmp_path):
    path = tmp_path / "test.log"
    logger = setup_file_logger("replace", path, max_bytes=100, backup_count=1)
    logger.info("old")
    previous = logger.handlers[0]
    replacement = setup_file_logger("replace", path, max_bytes=200, backup_count=2)
    try:
        assert previous.stream is None
        assert len(replacement.handlers) == 2
        replacement.info("new")
        assert "new" in path.read_text()
    finally:
        for handler in replacement.handlers:
            handler.close()


def zone_entry(coords):
    return {"decoded_messages": [{"rpc": {"method": "set_scenes_zones", "params": {
        "data": [{"tid": "scene", "zones": [{"zid": 1, "range": coords}]}],
    }}}]}


def test_zone_recovery_uses_all_backups_oldest_to_newest_without_active_file(tmp_path):
    path = tmp_path / "decompiled_mqtt.jsonl"
    for suffix, coords in ((10, [1, 2, 3, 4]), (2, [5, 6, 7, 8]), (1, [9, 10, 11, 12])):
        path.with_name(f"{path.name}.{suffix}").write_text(json.dumps(zone_entry(coords)) + "\n")
    store = ZoneRangesStore(tmp_path)
    assert store.seed_from_mqtt_jsonl(path) == 1
    assert store.get("scene", 1) == [9, 10, 11, 12]
    assert ZoneRangesStore(tmp_path).get("scene", 1) == [9, 10, 11, 12]


def test_scene_fallback_reads_backups_and_latest_coordinates_win(tmp_path):
    path = tmp_path / "decompiled_mqtt.jsonl"
    path.with_name(path.name + ".1").write_text(json.dumps(zone_entry([1, 2, 3, 4])) + "\n")
    ctx = SimpleNamespace(mqtt_jsonl=path)
    assert _scene_zone_ranges_from_mqtt(ctx, tids_filter={"scene"}) == {("scene", 1): [1, 2, 3, 4]}
    path.write_text(json.dumps(zone_entry([5, 6, 7, 8])) + "\n")
    assert _scene_zone_ranges_from_mqtt(ctx, tids_filter={"scene"}) == {("scene", 1): [5, 6, 7, 8]}


@pytest.mark.parametrize("source_suffix", ["", ".4"])
def test_supervisor_recovers_state_before_trimming_or_removing_logs(tmp_path, source_suffix):
    config_file = write_release_config(tmp_path)
    config_file.write_text(config_file.read_text() + '\n[logging]\nmax_size_mb=1\nbackup_count=0\n')
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    paths.runtime_dir.mkdir(parents=True)
    credentials = RuntimeCredentialsStore(paths.runtime_credentials_path)
    credentials.ensure_device(did="123", duid="vacuum", device_mqtt_usr="c25b14ceac358d2a", assign_localkey=False)
    connect = "CONNECT len=82 hex=105000044d51545404c2001e00106130313233393163623566386263393700106332356231346365616333353864326100206666383932326432346139613961663831663138663335646365653961356135"
    mqtt_log = paths.runtime_dir / ("mqtt_server.log" + source_suffix)
    mqtt_log.write_text("[INFO] " + connect + "\n" + "later event\n" * 100_000)
    mqtt_jsonl = paths.runtime_dir / ("decompiled_mqtt.jsonl" + source_suffix)
    mqtt_jsonl.write_text(json.dumps(zone_entry([1, 2, 3, 4])) + "\n" + '{"later":true}\n' * 100_000)
    # Also exercise cleanup for an inactive service, which may not emit on startup.
    (paths.runtime_dir / "unknown_server.log").write_text("old\n" * 300_000)

    supervisor = ReleaseSupervisor(config=config, paths=paths)
    try:
        persisted = RuntimeCredentialsStore(paths.runtime_credentials_path)
        assert persisted.resolve_device(duid="vacuum")["device_mqtt_pass"] == "ff8922d24a9a9af81f18f35dcee9a5a5"
        assert ZoneRangesStore(paths.runtime_dir).get("scene", 1) == [1, 2, 3, 4]
        assert supervisor.context.zone_ranges_store.get("scene", 1) == [1, 2, 3, 4]
        for path in (mqtt_log, mqtt_jsonl, paths.runtime_dir / "unknown_server.log"):
            assert not path.exists() or path.stat().st_size <= config.logging.max_bytes
        if source_suffix:
            assert not mqtt_log.exists() and not mqtt_jsonl.exists()
        else:
            assert "CONNECT" not in mqtt_log.read_text()
            assert "set_scenes_zones" not in mqtt_jsonl.read_text()
        # The supervisor must configure both aliases used by the vendored backend.
        for index in range(3):
            backend_append(paths.http_jsonl_path, {"index": index, "payload": "x" * 600_000})
        assert len(_retained_json(paths.http_jsonl_path)) == 1
        assert not paths.http_jsonl_path.with_name(paths.http_jsonl_path.name + ".1").exists()
    finally:
        for logger in supervisor.loggers.values():
            for handler in logger.handlers:
                handler.close()
