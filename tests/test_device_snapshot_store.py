from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path

import pytest

from roborock_local_server.bundled_backend.shared.device_snapshot_store import DeviceSnapshotStore

DUID = "2e2txkqKqxVifcIdyOT1lY"


def _store(tmp_path: Path) -> DeviceSnapshotStore:
    return DeviceSnapshotStore(tmp_path, flush_interval_s=0.0, map_interval_s=0.0)


def test_unknown_device_has_no_snapshot(tmp_path: Path) -> None:
    assert _store(tmp_path).get(DUID) is None


def test_status_push_records_battery_state_and_error(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record_dps(DUID, json.dumps({"t": 1, "dps": {"122": 5}}))
    store.record_dps(DUID, json.dumps({"t": 2, "dps": {"121": 12, "120": 4}}))

    status = store.get(DUID)["status"]

    assert (status["battery"], status["state"], status["error_code"]) == (5, 12, 4)
    assert status["updated_at"]


def test_get_status_answer_is_read_from_the_one_item_list(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record_status_result(DUID, [{"state": 8, "battery": 100, "error_code": 0, "ignored": "x"}])

    status = store.get(DUID)["status"]

    assert (status["state"], status["battery"], status["error_code"]) == (8, 100, 0)
    assert "ignored" not in status


def test_dps_ignores_unrelated_or_malformed_payloads(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record_dps(DUID, "not json")
    store.record_dps(DUID, json.dumps({"dps": {"101": "{}"}}))
    store.record_dps(DUID, json.dumps({"dps": {"122": True}}))

    assert store.get(DUID) is None


def test_offline_is_marked_and_cleared_when_the_robot_speaks_again(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.mark_seen(DUID)
    store.mark_offline(DUID)
    assert store.get(DUID)["offline_at"]

    store.mark_seen(DUID)
    assert store.get(DUID)["offline_at"] is None


def test_state_survives_a_restart(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record_dps(DUID, json.dumps({"dps": {"122": 5}}))
    store.mark_offline(DUID)
    store.flush()

    reopened = _store(tmp_path).get(DUID)

    assert reopened["status"]["battery"] == 5
    assert reopened["offline_at"]


def test_unsafe_device_ids_are_refused(tmp_path: Path) -> None:
    store = _store(tmp_path)
    for bad in ("", "../x", "a/b", "a b"):
        store.mark_seen(bad)
        store.mark_offline(bad)
        store.record_dps(bad, json.dumps({"dps": {"122": 5}}))

    assert not (tmp_path / "device_snapshots").exists()


def test_request_nonce_is_found_in_the_escaped_rpc_payload(tmp_path: Path) -> None:
    store = _store(tmp_path)
    payload = (
        '{"dps":{"101":"{\\"id\\":29755,\\"method\\":\\"get_map_v1\\",\\"params\\":[],'
        '\\"security\\":{\\"endpoint\\":\\"w5Mpv215\\",\\"nonce\\":\\"0fd7440a89d9e25af17aa00493c29025\\"}}"},"t":1}'
    )

    store.note_request(DUID, payload)

    assert store._nonces[DUID] == {"w5Mpv215": "0fd7440a89d9e25af17aa00493c29025"}


def test_map_reply_without_a_known_nonce_is_ignored(tmp_path: Path) -> None:
    store = _store(tmp_path)

    store.record_map(DUID, b"w5Mpv215" + b"\x00" * 64)

    assert store.get(DUID) is None


def test_map_reply_is_decrypted_and_its_position_stored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from roborock.protocol import Utils

    from roborock_local_server.bundled_backend.shared import device_snapshot_store as module

    class Point:
        def __init__(self, x: int, y: int, a: int) -> None:
            self.x, self.y, self.a = x, y, a

    map_bytes = b"fake map bytes"
    nonce = bytes(range(16))
    header = b"w5Mpv215" + b"\x00" * 8 + b"\x01\x00" + b"\x00" * 6
    body = Utils.encrypt_cbc(gzip.compress(map_bytes), nonce)
    monkeypatch.setattr(module, "_parse_map", lambda data: (module._point(Point(24343, 38108, 170)), module._point(Point(26306, 25598, -177))) if data == map_bytes else (None, None))

    store = _store(tmp_path)
    store.note_request(
        DUID,
        '{"dps":{"101":"{\\"security\\":{\\"endpoint\\":\\"w5Mpv215\\",\\"nonce\\":\\"%s\\"}}"}}' % nonce.hex(),
    )
    store.record_map(DUID, header + body)

    snapshot = store.get(DUID, include_map=True)

    assert snapshot["position"]["robot"] == {"x": 24343, "y": 38108, "angle": 170}
    assert snapshot["position"]["charger"] == {"x": 26306, "y": 25598, "angle": -177}
    assert base64.b64decode(snapshot["map"]) == map_bytes
    assert snapshot["has_map"] is True
    assert "map" not in store.get(DUID)
