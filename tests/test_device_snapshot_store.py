from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path

import pytest

from roborock_local_server.bundled_backend.shared.device_snapshot_store import DeviceSnapshotStore, is_status_answer

DUID = "duid-test-1"


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
        '\\"security\\":{\\"endpoint\\":\\"testep01\\",\\"nonce\\":\\"00112233445566778899aabbccddeeff\\"}}"},"t":1}'
    )

    store.note_request(DUID, payload)

    assert store._nonces[DUID] == {"testep01": "00112233445566778899aabbccddeeff"}


def test_map_reply_without_a_known_nonce_is_ignored(tmp_path: Path) -> None:
    store = _store(tmp_path)

    store.record_map(DUID, b"testep01" + b"\x00" * 64)

    assert store.get(DUID) is None


def test_map_reply_is_decrypted_and_its_position_stored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from roborock.protocol import Utils

    from roborock_local_server.bundled_backend.shared import device_snapshot_store as module

    class Point:
        def __init__(self, x: int, y: int, a: int) -> None:
            self.x, self.y, self.a = x, y, a

    map_bytes = b"fake map bytes"
    nonce = bytes(range(16))
    header = b"testep01" + b"\x00" * 8 + b"\x01\x00" + b"\x00" * 6
    body = Utils.encrypt_cbc(gzip.compress(map_bytes), nonce)
    monkeypatch.setattr(module, "_parse_map", lambda data: (module._point(Point(24343, 38108, 170)), module._point(Point(26306, 25598, -177))) if data == map_bytes else (None, None))

    store = _store(tmp_path)
    store.note_request(
        DUID,
        '{"dps":{"101":"{\\"security\\":{\\"endpoint\\":\\"testep01\\",\\"nonce\\":\\"%s\\"}}"}}' % nonce.hex(),
    )
    store.record_map(DUID, header + body)

    snapshot = store.get(DUID, include_map=True)

    assert snapshot["position"]["robot"] == {"x": 24343, "y": 38108, "angle": 170}
    assert snapshot["position"]["charger"] == {"x": 26306, "y": 25598, "angle": -177}
    assert base64.b64decode(snapshot["map"]) == map_bytes
    assert snapshot["has_map"] is True
    assert "map" not in store.get(DUID)


def _log_line(time: str, direction: str, topic: str, *messages: dict) -> str:
    return json.dumps({"time": time, "direction": direction, "topic": topic, "decoded_messages": list(messages)}) + "\n"


def _seed_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, map_bytes: bytes = b"last map bytes") -> Path:
    from roborock.protocol import Utils

    from roborock_local_server.bundled_backend.shared import device_snapshot_store as module

    class Point:
        def __init__(self, x: int, y: int, a: int) -> None:
            self.x, self.y, self.a = x, y, a

    monkeypatch.setattr(
        module,
        "_parse_map",
        lambda data: (module._point(Point(24343, 38108, 170)), module._point(Point(26306, 25598, -177)))
        if data == map_bytes
        else (None, None),
    )
    nonce = bytes(range(16))
    header = b"testep01" + b"\x00" * 8 + b"\x01\x00" + b"\x00" * 6
    reply = header + Utils.encrypt_cbc(gzip.compress(map_bytes), nonce)
    request = '{"dps":{"101":"{\\"security\\":{\\"endpoint\\":\\"testep01\\",\\"nonce\\":\\"%s\\"}}"}}' % nonce.hex()
    robot = "rr/d/i/did-test-1/abc"
    path = tmp_path / "decoded.jsonl"
    path.write_text(
        _log_line("2026-10-22T00:20:00+00:00", "c2b", f"rr/m/i/user/abcd1234/{DUID}", {"protocol_value": 101, "payload_utf8": request})
        + _log_line("2026-10-22T00:24:17+00:00", "c2b", robot, {"protocol_value": 102, "payload_utf8": '{"dps":{"122":7}}'})
        + _log_line("2026-10-22T00:25:00+00:00", "c2b", robot, {"protocol_value": 301, "payload_hex": reply.hex()})
        + _log_line(
            "2026-10-22T00:30:00+00:00", "c2b", robot,
            {"protocol_value": 102, "response_to": {"request_method": "get_status", "error": None, "result": [{"state": 2, "battery": 6}]}},
        )
        + _log_line("2026-10-22T00:33:57+00:00", "c2b", robot, {"protocol_value": 102, "payload_utf8": '{"dps":{"122":5}}'})
        # An app's own traffic and unrelated lines must not count as the robot speaking.
        + _log_line("2026-10-22T03:00:00+00:00", "b2c", "rr/d/o/did-test-1/abc", {"protocol_value": 102, "payload_utf8": '{"dps":{"122":99}}'})
        + "not json at all\n",
        encoding="utf-8",
    )
    return path


def test_seed_recovers_the_last_status_map_and_time_from_the_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = _seed_log(tmp_path, monkeypatch)
    store = _store(tmp_path / "state")

    added = store.seed_from_mqtt_jsonl(log, lambda did: DUID if did == "did-test-1" else "")

    snapshot = store.get(DUID, include_map=True)
    assert added == 1
    assert snapshot["last_seen_at"] == "2026-10-22T00:33:57+00:00"
    assert snapshot["status"]["battery"] == 5
    assert snapshot["status"]["state"] == 2
    assert snapshot["position"]["robot"] == {"x": 24343, "y": 38108, "angle": 170}
    assert snapshot["position"]["map_updated_at"] == "2026-10-22T00:25:00+00:00"
    assert base64.b64decode(snapshot["map"]) == b"last map bytes"


def test_seed_persists_so_a_restart_keeps_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = _seed_log(tmp_path, monkeypatch)
    _store(tmp_path / "state").seed_from_mqtt_jsonl(log, lambda did: DUID)

    reopened = _store(tmp_path / "state").get(DUID)

    assert reopened["status"]["battery"] == 5
    assert reopened["position"]["robot"]["x"] == 24343


def test_seed_leaves_a_device_that_already_has_a_snapshot_alone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = _seed_log(tmp_path, monkeypatch)
    store = _store(tmp_path / "state")
    store.record_dps(DUID, json.dumps({"dps": {"122": 80}}))

    added = store.seed_from_mqtt_jsonl(log, lambda did: DUID)

    assert added == 0
    assert store.get(DUID)["status"]["battery"] == 80


def test_seed_skips_robots_it_cannot_name_and_missing_logs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = _seed_log(tmp_path, monkeypatch)
    store = _store(tmp_path / "state")

    assert store.seed_from_mqtt_jsonl(log, lambda did: "") == 0
    assert store.seed_from_mqtt_jsonl(tmp_path / "missing.jsonl", lambda did: DUID) == 0


def test_room_mapping_answer_is_kept_and_survives_a_restart(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record_room_mapping(DUID, [[21, "1001", 6], [16, "1002", 8], [18, "1003"]])
    store.flush()

    rooms = _store(tmp_path).get(DUID)["rooms"]

    assert rooms == [
        {"segment": 21, "iot_id": "1001", "tag": 6},
        {"segment": 16, "iot_id": "1002", "tag": 8},
        {"segment": 18, "iot_id": "1003", "tag": None},
    ]


def test_room_mapping_ignores_empty_and_malformed_answers(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record_room_mapping(DUID, [])
    store.record_room_mapping(DUID, "nope")
    store.record_room_mapping(DUID, [["x", "1"], [3], [4, None]])

    assert store.get(DUID) is None


def test_get_prop_get_status_counts_as_a_status_answer() -> None:
    assert is_status_answer({"request_method": "get_status"})
    assert is_status_answer({"request_method": "get_prop", "request_params": ["get_status"]})
    assert not is_status_answer({"request_method": "get_prop", "request_params": ["get_consumable"]})
    assert not is_status_answer({"request_method": "get_prop"})
    assert not is_status_answer({"request_method": "get_room_mapping"})


def _request(security: dict) -> str:
    return json.dumps({"dps": {"101": json.dumps({"id": 1, "method": "get_map_v1", "security": security})}})


@pytest.mark.parametrize("endpoint", ["w5Mp+215", "ab/Cd+Ef", "testep01"])
def test_note_request_accepts_base64_endpoints_and_either_key_order(tmp_path: Path, endpoint: str) -> None:
    store = _store(tmp_path)
    store.note_request(DUID, _request({"endpoint": endpoint, "nonce": "00ff"}))
    assert store._nonces[DUID] == {endpoint: "00ff"}

    other = _store(tmp_path / "second")
    other.note_request(DUID, _request({"nonce": "00ff", "endpoint": endpoint}))
    assert other._nonces[DUID] == {endpoint: "00ff"}


def test_note_request_ignores_a_non_hex_nonce_and_malformed_security(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.note_request(DUID, _request({"endpoint": "testep01", "nonce": "zz"}))
    store.note_request(DUID, _request({"endpoint": "", "nonce": "00ff"}))
    store.note_request(DUID, '{"security": "oops"}')
    assert store._nonces == {}


def test_map_reply_with_a_base64_endpoint_is_decrypted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from roborock.protocol import Utils

    from roborock_local_server.bundled_backend.shared import device_snapshot_store as module

    nonce = bytes(range(16))
    header = b"tst/+001" + b"\x00" * 16
    monkeypatch.setattr(module, "_parse_map", lambda data: (None, None))
    store = _store(tmp_path)
    store.note_request(DUID, _request({"nonce": nonce.hex(), "endpoint": "tst/+001"}))
    store.record_map(DUID, header + Utils.encrypt_cbc(gzip.compress(b"map"), nonce))

    assert base64.b64decode(store.get(DUID, include_map=True)["map"]) == b"map"


def test_a_robot_rebuilt_from_the_log_is_offline_since_it_last_spoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = _seed_log(tmp_path, monkeypatch)
    store = _store(tmp_path / "state")
    store.seed_from_mqtt_jsonl(log, lambda did: DUID)

    assert store.get(DUID)["offline_at"] == "2026-10-22T00:33:57+00:00"
    store.mark_seen(DUID)
    assert store.get(DUID)["offline_at"] is None


def test_flush_writes_pending_changes_and_a_new_store_reads_them(tmp_path: Path) -> None:
    store = DeviceSnapshotStore(tmp_path, flush_interval_s=3600.0, map_interval_s=0.0)
    store.record_dps(DUID, json.dumps({"dps": {"122": 9}}))
    store.record_dps(DUID, json.dumps({"dps": {"122": 8}}))
    store.flush()

    assert DeviceSnapshotStore(tmp_path).get(DUID)["status"]["battery"] == 8


def test_an_entry_loaded_from_disk_is_offline_until_the_robot_speaks(tmp_path: Path) -> None:
    first = _store(tmp_path)
    first.mark_seen(DUID)
    first.flush()

    reopened = _store(tmp_path)
    assert reopened.get(DUID)["offline_at"] == reopened.get(DUID)["last_seen_at"]
    reopened.mark_seen(DUID)
    assert reopened.get(DUID)["offline_at"] is None


def test_seed_skips_mowers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = _seed_log(tmp_path, monkeypatch)
    store = _store(tmp_path / "state")

    store.seed_from_mqtt_jsonl(log, lambda did: DUID, lambda duid: True)

    entry = store.get(DUID)
    assert entry["last_seen_at"]
    assert entry["status"] == {}


def test_a_failed_write_keeps_the_change_dirty_for_the_next_flush(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = DeviceSnapshotStore(tmp_path, flush_interval_s=3600.0, map_interval_s=0.0)
    monkeypatch.setattr(DeviceSnapshotStore, "_write", staticmethod(lambda path, content: False))
    store.record_dps(DUID, json.dumps({"dps": {"122": 9}}))
    store.flush()
    assert DUID in store._dirty

    monkeypatch.undo()
    store.flush()
    assert DeviceSnapshotStore(tmp_path).get(DUID)["status"]["battery"] == 9


def test_concurrent_flushes_never_leave_older_content_on_disk(tmp_path: Path) -> None:
    import threading

    store = DeviceSnapshotStore(tmp_path, flush_interval_s=3600.0, map_interval_s=0.0)
    stop = threading.Event()

    def flusher() -> None:
        while not stop.is_set():
            store.flush()

    threads = [threading.Thread(target=flusher) for _ in range(3)]
    for thread in threads:
        thread.start()
    for battery in range(1, 60):
        store.record_dps(DUID, json.dumps({"dps": {"122": battery}}))
    stop.set()
    for thread in threads:
        thread.join()
    store.flush()

    assert DeviceSnapshotStore(tmp_path).get(DUID)["status"]["battery"] == 59
