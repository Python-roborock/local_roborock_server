import json
import logging
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest

from roborock_local_server import backend  # initializes bundled import path
from shared import inventory_io


def test_replace_failure_preserves_old_inventory_and_cleans_temp(tmp_path, monkeypatch):
    path = tmp_path / inventory_io.WEB_API_INVENTORY_FILE
    path.write_text('{"devices": [{"did": "original"}]}', encoding="utf-8")
    original = path.read_bytes()

    def fail_replace(*args):
        raise OSError("disk failure")

    monkeypatch.setattr(inventory_io.os, "replace", fail_replace)
    with pytest.raises(OSError):
        inventory_io.atomic_write_inventory(path, {"devices": []})
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


def test_mutations_from_threads_keep_both_updates(tmp_path):
    path = tmp_path / inventory_io.WEB_API_INVENTORY_FILE
    inventory_io.atomic_write_inventory(path, {"devices": [], "scenes": []})
    ctx = SimpleNamespace(http_jsonl=tmp_path / "http.jsonl")
    start = Barrier(2)

    @inventory_io.inventory_mutation
    def mutate(ctx, field):
        loaded = inventory_io.load_inventory(ctx)
        loaded[field].append({"id": field})
        assert inventory_io.write_inventory(ctx, loaded)

    def run(field):
        start.wait(timeout=5)
        mutate(ctx, field)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run, field) for field in ("devices", "scenes")]
        for future in futures:
            future.result(timeout=5)
    assert json.loads(path.read_text()) == {
        "devices": [{"id": "devices"}], "scenes": [{"id": "scenes"}],
    }


def test_corrupt_inventory_is_not_replaced_by_mutation(tmp_path):
    path = tmp_path / inventory_io.WEB_API_INVENTORY_FILE
    path.write_text('{broken', encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        with inventory_io.inventory_transaction(path):
            inventory_io.atomic_write_inventory(path, {})
    assert path.read_text() == '{broken'


def test_context_write_failure_returns_false_and_logs(tmp_path, monkeypatch, caplog):
    ctx = SimpleNamespace(http_jsonl=tmp_path / "http.jsonl")

    def fail(*args):
        raise OSError("disk full")

    monkeypatch.setattr(inventory_io, "atomic_write_inventory", fail)
    with caplog.at_level(logging.ERROR):
        assert inventory_io.write_inventory(ctx, {}) is False
    assert "Unable to persist inventory" in caplog.text


def test_cached_inventory_reads_the_file_only_when_it_changed(tmp_path, monkeypatch):
    ctx = SimpleNamespace(http_jsonl=tmp_path / "http.jsonl")
    inventory_io.atomic_write_inventory(tmp_path / inventory_io.WEB_API_INVENTORY_FILE, {"schedules": {}})
    reads = []
    real_load = inventory_io.load_inventory
    monkeypatch.setattr(inventory_io, "load_inventory", lambda c: reads.append(1) or real_load(c))
    cache = inventory_io.CachedInventory(ctx)

    assert cache.read() == {"schedules": {}}
    assert cache.read() == {"schedules": {}}
    assert len(reads) == 1

    inventory_io.atomic_write_inventory(tmp_path / inventory_io.WEB_API_INVENTORY_FILE, {"schedules": {"a": []}})
    assert cache.read() == {"schedules": {"a": []}}
    assert len(reads) == 2


def test_cached_inventory_follows_a_file_that_appears_later(tmp_path):
    ctx = SimpleNamespace(http_jsonl=tmp_path / "http.jsonl")
    cache = inventory_io.CachedInventory(ctx)
    assert cache.read() == {}
    inventory_io.atomic_write_inventory(tmp_path / inventory_io.WEB_API_INVENTORY_FILE, {"x": 1})
    assert cache.read() == {"x": 1}


def test_cached_inventory_notices_a_same_size_replacement_with_the_same_mtime(tmp_path):
    import os

    path = tmp_path / inventory_io.WEB_API_INVENTORY_FILE
    ctx = SimpleNamespace(http_jsonl=tmp_path / "http.jsonl")
    inventory_io.atomic_write_inventory(path, {"x": 1})
    stamp = path.stat().st_mtime_ns
    cache = inventory_io.CachedInventory(ctx)
    assert cache.read() == {"x": 1}
    inventory_io.atomic_write_inventory(path, {"x": 2})
    os.utime(path, ns=(stamp, stamp))
    if path.stat().st_ino == 0:
        pytest.skip("this filesystem reports no file id")
    assert cache.read() == {"x": 2}
