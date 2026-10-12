import json
from pathlib import Path

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server.activity_log import read_recent_activity
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor

QREVO = "2e2txkqKqxVifcIdyOT1lY"
QREVO_DID = "1103829226788"
S7 = "1OVJHS7cL6XxkYkoOGr2Hw"


def _write_jsonl(path: Path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(entry) for entry in entries) + "\n", encoding="utf-8")


def test_device_filter_matches_whole_segments_across_http_and_mqtt(tmp_path: Path) -> None:
    http = tmp_path / "http.jsonl"
    mqtt = tmp_path / "mqtt.jsonl"
    _write_jsonl(
        http,
        [
            {"time": "2026-01-01T00:00:01Z", "clean_path": f"/user/devices/{QREVO}/jobs", "method": "GET"},
            {"time": "2026-01-01T00:00:02Z", "clean_path": f"/user/devices/{S7}/jobs", "method": "GET"},
            {"time": "2026-01-01T00:00:03Z", "clean_path": "/region", "method": "GET"},
            {"time": "2026-01-01T00:00:04Z", "clean_path": "/nc/prepare", "did": QREVO_DID, "method": "POST"},
            # A longer id that merely contains the wanted one must not match.
            {"time": "2026-01-01T00:00:05Z", "clean_path": f"/user/devices/{QREVO}extra/jobs", "method": "GET"},
        ],
    )
    _write_jsonl(
        mqtt,
        [
            {"time": "2026-01-01T00:00:06Z", "topic": f"rr/d/i/{QREVO_DID}/c6420abe", "direction": "c2b"},
            {"time": "2026-01-01T00:00:07Z", "topic": "rr/d/i/999/other", "direction": "c2b"},
            {"time": "2026-01-01T00:00:08Z", "topic": f"rr/m/o/u/user/{QREVO}", "direction": "b2c"},
        ],
    )

    entries = read_recent_activity(
        http_jsonl_path=http,
        mqtt_jsonl_path=mqtt,
        limit=50,
        device_ids={QREVO, QREVO_DID, "c6420abe"},
    )

    assert [entry["time"] for entry in entries] == [
        "2026-01-01T00:00:08Z",
        "2026-01-01T00:00:06Z",
        "2026-01-01T00:00:04Z",
        "2026-01-01T00:00:01Z",
    ]


def test_device_filter_looks_past_the_newest_lines_to_find_a_quiet_device(tmp_path: Path) -> None:
    http = tmp_path / "http.jsonl"
    quiet = {"time": "2026-01-01T00:00:00Z", "clean_path": f"/user/devices/{S7}/jobs", "method": "GET"}
    # limit=3 reads a 30-line tail when filtering; 25 noisy lines + the quiet one fit inside it.
    noisy = [
        {"time": f"2026-01-01T00:01:{i:02d}Z", "clean_path": f"/user/devices/{QREVO}/jobs", "method": "GET"}
        for i in range(25)
    ]
    _write_jsonl(http, [quiet, *noisy])

    entries = read_recent_activity(
        http_jsonl_path=http, mqtt_jsonl_path=tmp_path / "none.jsonl", limit=3, device_ids={S7}
    )

    assert [entry["time"] for entry in entries] == ["2026-01-01T00:00:00Z"]


def test_empty_device_ids_match_nothing(tmp_path: Path) -> None:
    http = tmp_path / "http.jsonl"
    _write_jsonl(http, [{"time": "2026-01-01T00:00:00Z", "clean_path": "/region"}])

    assert read_recent_activity(
        http_jsonl_path=http, mqtt_jsonl_path=tmp_path / "none.jsonl", device_ids=set()
    ) == []


def _supervisor(tmp_path: Path) -> tuple[ReleaseSupervisor, object]:
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    paths.inventory_path.parent.mkdir(parents=True, exist_ok=True)
    paths.inventory_path.write_text(
        json.dumps(
            {
                "home": {"id": 1, "name": "Home"},
                "devices": [
                    {"duid": QREVO, "name": "Quevo", "did": QREVO_DID},
                    {"duid": S7, "name": "Downstairs S7"},
                ],
            }
        ),
        encoding="utf-8",
    )
    _write_jsonl(
        paths.http_jsonl_path,
        [
            {"time": "2026-01-01T00:00:01Z", "clean_path": f"/user/devices/{QREVO}/jobs", "method": "GET"},
            {"time": "2026-01-01T00:00:02Z", "clean_path": f"/user/devices/{S7}/jobs", "method": "GET"},
        ],
    )
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    supervisor.refresh_inventory_state()
    return supervisor, paths


def _login(supervisor: ReleaseSupervisor) -> TestClient:
    client = TestClient(supervisor.app)
    response = client.post("/admin/api/login", json={"password": "correct horse battery staple"})
    assert response.status_code == 200
    return client


def test_activity_endpoint_returns_only_the_selected_vacuums_traffic(tmp_path: Path) -> None:
    supervisor, _paths = _supervisor(tmp_path)
    client = _login(supervisor)

    everything = client.get("/admin/api/activity").json()["entries"]
    one = client.get("/admin/api/activity", params={"device": QREVO}).json()

    assert len(everything) == 2
    assert [entry["path"] for entry in one["entries"]] == [f"/user/devices/{QREVO}/jobs"]
    assert one["device"] == QREVO


def test_activity_finds_device_traffic_that_only_names_its_did_and_mqtt_user(tmp_path: Path) -> None:
    supervisor, paths = _supervisor(tmp_path)
    # The vacuum's own MQTT topics carry its did and MQTT user, never the duid.
    supervisor.runtime_credentials.ensure_device(did=QREVO_DID, duid=QREVO, device_mqtt_usr="c6420abe")
    _write_jsonl(
        paths.mqtt_jsonl_path,
        [
            {"time": "2026-01-01T00:00:09Z", "topic": f"rr/d/i/{QREVO_DID}/c6420abe", "direction": "c2b"},
            {"time": "2026-01-01T00:00:10Z", "topic": "rr/d/i/555/someoneelse", "direction": "c2b"},
        ],
    )
    client = _login(supervisor)

    topics = [
        entry.get("topic")
        for entry in client.get("/admin/api/activity", params={"device": QREVO}).json()["entries"]
        if entry["source"] == "mqtt"
    ]

    assert topics == [f"rr/d/i/{QREVO_DID}/c6420abe"]


def test_activity_endpoint_404s_for_an_unknown_vacuum(tmp_path: Path) -> None:
    supervisor, _paths = _supervisor(tmp_path)
    client = _login(supervisor)

    response = client.get("/admin/api/activity", params={"device": "nope"})

    assert response.status_code == 404


def test_dashboard_has_a_device_selector_and_a_server_panel(tmp_path: Path) -> None:
    supervisor, _paths = _supervisor(tmp_path)
    client = _login(supervisor)

    page = client.get("/admin").text

    assert 'id="deviceTabs"' in page
    assert 'id="devicePanel"' in page
    assert 'id="serverPanel"' in page
    # The global cards live under Server now, not stacked beneath every vacuum.
    assert page.index('id="serverPanel"') < page.index("Cloud Import") < page.index("New Connections")
    assert "Vacuums (raw)" not in page
    # The local key is a credential and must never be rendered, even in raw details.
    assert '"<redacted>"' in page
