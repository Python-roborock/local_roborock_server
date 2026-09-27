from __future__ import annotations

import json
from pathlib import Path

from roborock_local_server.activity_log import (
    _tail_lines,
    activity_raw_enabled,
    read_recent_activity,
)


def _write_jsonl(path: Path, entries: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(entry) for entry in entries) + "\n", encoding="utf-8")


def test_activity_raw_enabled_default_false() -> None:
    assert activity_raw_enabled({}) is False


def test_activity_raw_enabled_true_values() -> None:
    for value in ("1", "true", "TRUE", "yes", "on"):
        assert activity_raw_enabled({"ROBOROCK_SERVER_ACTIVITY_RAW": value}) is True


def test_activity_raw_enabled_false_values() -> None:
    for value in ("0", "false", "no", "off", ""):
        assert activity_raw_enabled({"ROBOROCK_SERVER_ACTIVITY_RAW": value}) is False


def test_tail_lines_missing_file_returns_empty(tmp_path: Path) -> None:
    assert _tail_lines(tmp_path / "missing.jsonl", 10) == []


def test_tail_lines_returns_last_n_in_order(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    path.write_text("\n".join(f"line-{i}" for i in range(1, 21)) + "\n", encoding="utf-8")

    assert _tail_lines(path, 3) == ["line-18", "line-19", "line-20"]


def test_tail_lines_handles_chunk_boundary(tmp_path: Path) -> None:
    # Force multiple internal read chunks by writing a file bigger than _CHUNK_SIZE.
    path = tmp_path / "big.jsonl"
    lines = [f"line-{i}-{'x' * 200}" for i in range(1, 2000)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    tailed = _tail_lines(path, 5)

    assert tailed == lines[-5:]


def test_tail_lines_zero_or_negative_limit(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    path.write_text("line-1\n", encoding="utf-8")

    assert _tail_lines(path, 0) == []


def test_read_recent_activity_redacts_by_default(tmp_path: Path) -> None:
    http_path = tmp_path / "http.jsonl"
    mqtt_path = tmp_path / "mqtt.jsonl"
    _write_jsonl(
        http_path,
        [
            {
                "time": "2026-01-01T00:00:00Z",
                "method": "POST",
                "clean_path": "/api/v1/user/login",
                "headers": {"authorization": "Bearer super-secret"},
                "body_json": {"localkey": "abc123", "password": "hunter2"},
                "body_len": 42,
                "route": "login",
                "remote": "10.0.0.5:443",
            }
        ],
    )
    _write_jsonl(
        mqtt_path,
        [
            {
                "time": "2026-01-01T00:00:01Z",
                "direction": "in",
                "topic": "rr/abc/duid1",
                "payload_hex": "aabbcc",
                "decoded_messages": [{"rpc": {"method": "get_status", "params": ["secret-token"]}}],
            }
        ],
    )

    entries = read_recent_activity(http_jsonl_path=http_path, mqtt_jsonl_path=mqtt_path)

    assert len(entries) == 2
    serialized = json.dumps(entries)
    assert "super-secret" not in serialized
    assert "hunter2" not in serialized
    assert "abc123" not in serialized
    assert "secret-token" not in serialized

    http_entry = next(e for e in entries if e["source"] == "http")
    assert http_entry["method"] == "POST"
    assert http_entry["path"] == "/api/v1/user/login"
    assert "headers" not in http_entry
    assert "body_json" not in http_entry

    mqtt_entry = next(e for e in entries if e["source"] == "mqtt")
    assert mqtt_entry["topic"] == "rr/abc/duid1"
    assert mqtt_entry["rpc_methods"] == ["get_status"]
    assert "payload_hex" not in mqtt_entry
    assert "decoded_messages" not in mqtt_entry


def test_read_recent_activity_raw_mode_returns_full_entries(tmp_path: Path) -> None:
    http_path = tmp_path / "http.jsonl"
    mqtt_path = tmp_path / "mqtt.jsonl"
    _write_jsonl(
        http_path,
        [
            {
                "time": "2026-01-01T00:00:00Z",
                "method": "POST",
                "headers": {"authorization": "Bearer super-secret"},
            }
        ],
    )
    _write_jsonl(mqtt_path, [])

    entries = read_recent_activity(http_jsonl_path=http_path, mqtt_jsonl_path=mqtt_path, raw=True)

    assert len(entries) == 1
    assert entries[0]["source"] == "http"
    assert entries[0]["headers"] == {"authorization": "Bearer super-secret"}


def test_read_recent_activity_sorts_newest_first_across_sources(tmp_path: Path) -> None:
    http_path = tmp_path / "http.jsonl"
    mqtt_path = tmp_path / "mqtt.jsonl"
    _write_jsonl(http_path, [{"time": "2026-01-01T00:00:00Z", "method": "GET", "clean_path": "/a"}])
    _write_jsonl(mqtt_path, [{"time": "2026-01-01T00:00:05Z", "topic": "rr/x"}])

    entries = read_recent_activity(http_jsonl_path=http_path, mqtt_jsonl_path=mqtt_path)

    assert [entry["source"] for entry in entries] == ["mqtt", "http"]


def test_read_recent_activity_missing_files_returns_empty(tmp_path: Path) -> None:
    entries = read_recent_activity(
        http_jsonl_path=tmp_path / "missing_http.jsonl",
        mqtt_jsonl_path=tmp_path / "missing_mqtt.jsonl",
    )
    assert entries == []


def test_read_recent_activity_skips_malformed_lines(tmp_path: Path) -> None:
    http_path = tmp_path / "http.jsonl"
    mqtt_path = tmp_path / "mqtt.jsonl"
    http_path.write_text(
        "not json at all\n" + json.dumps({"time": "2026-01-01T00:00:00Z", "method": "GET"}) + "\n",
        encoding="utf-8",
    )
    _write_jsonl(mqtt_path, [])

    entries = read_recent_activity(http_jsonl_path=http_path, mqtt_jsonl_path=mqtt_path)

    assert len(entries) == 1
    assert entries[0]["method"] == "GET"


def test_read_recent_activity_respects_limit(tmp_path: Path) -> None:
    http_path = tmp_path / "http.jsonl"
    mqtt_path = tmp_path / "mqtt.jsonl"
    _write_jsonl(
        http_path,
        [{"time": f"2026-01-01T00:00:{i:02d}Z", "method": "GET", "clean_path": "/a"} for i in range(10)],
    )
    _write_jsonl(mqtt_path, [])

    entries = read_recent_activity(http_jsonl_path=http_path, mqtt_jsonl_path=mqtt_path, limit=3)

    assert len(entries) == 3
    assert entries[0]["time"] == "2026-01-01T00:00:09Z"


def test_read_recent_activity_without_mitm_path_is_unaffected(tmp_path: Path) -> None:
    http_path = tmp_path / "http.jsonl"
    mqtt_path = tmp_path / "mqtt.jsonl"
    _write_jsonl(http_path, [{"time": "2026-01-01T00:00:00Z", "method": "GET"}])
    _write_jsonl(mqtt_path, [])

    entries = read_recent_activity(http_jsonl_path=http_path, mqtt_jsonl_path=mqtt_path)

    assert len(entries) == 1


def test_read_recent_activity_redacts_mitm_entries_by_default(tmp_path: Path) -> None:
    http_path = tmp_path / "http.jsonl"
    mqtt_path = tmp_path / "mqtt.jsonl"
    mitm_path = tmp_path / "mitm.jsonl"
    _write_jsonl(http_path, [])
    _write_jsonl(mqtt_path, [])
    _write_jsonl(
        mitm_path,
        [
            {
                "time": "2026-01-01T00:00:00Z",
                "host": "usiot.roborock.com",
                "method": "GET",
                "path": "/api/v1/userinfo",
                "status": 200,
                "rewritten": True,
                "request_headers": {"authorization": "real-cloud-token-999"},
                "response_body": "real account data here",
            }
        ],
    )

    entries = read_recent_activity(http_jsonl_path=http_path, mqtt_jsonl_path=mqtt_path, mitm_jsonl_path=mitm_path)

    assert len(entries) == 1
    entry = entries[0]
    assert entry["source"] == "mitm"
    assert entry["host"] == "usiot.roborock.com"
    assert entry["method"] == "GET"
    assert entry["path"] == "/api/v1/userinfo"
    assert entry["status"] == 200
    assert entry["rewritten"] is True
    assert "request_headers" not in entry
    assert "response_body" not in entry
    assert "real-cloud-token-999" not in json.dumps(entry)


def test_read_recent_activity_mitm_raw_mode_returns_full_entry(tmp_path: Path) -> None:
    http_path = tmp_path / "http.jsonl"
    mqtt_path = tmp_path / "mqtt.jsonl"
    mitm_path = tmp_path / "mitm.jsonl"
    _write_jsonl(http_path, [])
    _write_jsonl(mqtt_path, [])
    _write_jsonl(
        mitm_path,
        [{"time": "2026-01-01T00:00:00Z", "host": "usiot.roborock.com", "request_headers": {"x": "y"}}],
    )

    entries = read_recent_activity(
        http_jsonl_path=http_path,
        mqtt_jsonl_path=mqtt_path,
        mitm_jsonl_path=mitm_path,
        raw=True,
    )

    assert entries[0]["source"] == "mitm"
    assert entries[0]["request_headers"] == {"x": "y"}


def test_read_recent_activity_sorts_across_all_three_sources(tmp_path: Path) -> None:
    http_path = tmp_path / "http.jsonl"
    mqtt_path = tmp_path / "mqtt.jsonl"
    mitm_path = tmp_path / "mitm.jsonl"
    _write_jsonl(http_path, [{"time": "2026-01-01T00:00:00Z", "method": "GET"}])
    _write_jsonl(mqtt_path, [{"time": "2026-01-01T00:00:02Z", "topic": "rr/x"}])
    _write_jsonl(mitm_path, [{"time": "2026-01-01T00:00:01Z", "host": "usiot.roborock.com"}])

    entries = read_recent_activity(http_jsonl_path=http_path, mqtt_jsonl_path=mqtt_path, mitm_jsonl_path=mitm_path)

    assert [entry["source"] for entry in entries] == ["mqtt", "mitm", "http"]
