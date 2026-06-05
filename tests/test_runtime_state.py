from pathlib import Path
from datetime import datetime, timezone
import json

from roborock_local_server.bundled_backend.shared.runtime_credentials import RuntimeCredentialsStore
from roborock_local_server.bundled_backend.shared.runtime_state import RuntimeState


def test_runtime_state_keeps_vacuum_connected_when_old_conn_closes_after_reconnect(tmp_path: Path) -> None:
    state = RuntimeState(log_dir=tmp_path, key_state_file=None)

    state.record_mqtt_connection(conn_id="old", client_ip="testclient", client_port=1883)
    state.record_mqtt_message(
        conn_id="old",
        direction="c2b",
        topic="rr/d/i/1103811971559/dd211305e2d4873b",
        payload_preview="{}",
    )

    state.record_mqtt_connection(conn_id="new", client_ip="testclient", client_port=1883)
    state.record_mqtt_message(
        conn_id="new",
        direction="c2b",
        topic="rr/d/i/1103811971559/dd211305e2d4873b",
        payload_preview="{}",
    )

    state.record_mqtt_disconnect(conn_id="old")

    snapshot = state.vacuum_snapshot()
    assert len(snapshot) == 1
    assert snapshot[0]["did"] == "1103811971559"
    assert snapshot[0]["connected"] is True


def test_runtime_state_onboarding_session_adopts_selected_duid_identity(tmp_path: Path) -> None:
    credentials_path = tmp_path / "runtime_credentials.json"
    credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "devices": [
                    {
                        "did": "",
                        "duid": "cloud-q7-a",
                        "name": "Q7 Upstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-a",
                        "localkey": "local-key-a",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    credentials = RuntimeCredentialsStore(credentials_path)
    state = RuntimeState(log_dir=tmp_path, key_state_file=None, runtime_credentials=credentials)
    state.upsert_vacuum("cloud-q7-a", name="Q7 Upstairs", id_kind="duid")
    session = state.start_onboarding_session(target_duid="cloud-q7-a", target_name="Q7 Upstairs")

    event_time = datetime.now(timezone.utc).isoformat()
    state.record_http_event(
        event_time=event_time,
        route_name="region",
        clean_path="/region",
        raw_path="/region",
        method="GET",
        host="api-roborock.example.com",
        remote="192.168.8.10:54321",
        did="1103821560705",
    )

    snapshot = state.onboarding_session_snapshot()
    linked = credentials.resolve_device(did="1103821560705")
    assert linked is not None
    assert linked["duid"] == "cloud-q7-a"
    assert snapshot["session_id"] == session["session_id"]
    assert snapshot["target"]["duid"] == "cloud-q7-a"
    assert snapshot["target"]["did"] == "1103821560705"
    assert snapshot["identity_conflict"] == ""
    vacuums = state.vacuum_snapshot()
    assert [vacuum["duid"] for vacuum in vacuums] == ["cloud-q7-a"]
    assert vacuums[0]["did"] == "1103821560705"
    assert vacuums[0]["last_http_route"] == "region"
    assert vacuums[0]["onboarding_steps"]["region"] == event_time


def test_runtime_state_onboarding_session_reports_identity_conflict(tmp_path: Path) -> None:
    credentials_path = tmp_path / "runtime_credentials.json"
    credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "devices": [
                    {
                        "did": "1103821560705",
                        "duid": "cloud-q7-b",
                        "name": "Q7 Downstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-b",
                        "localkey": "local-key-b",
                    },
                    {
                        "did": "",
                        "duid": "cloud-q7-a",
                        "name": "Q7 Upstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-a",
                        "localkey": "local-key-a",
                    },
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    credentials = RuntimeCredentialsStore(credentials_path)
    state = RuntimeState(log_dir=tmp_path, key_state_file=None, runtime_credentials=credentials)
    state.upsert_vacuum("cloud-q7-a", name="Q7 Upstairs", id_kind="duid")
    state.start_onboarding_session(target_duid="cloud-q7-a", target_name="Q7 Upstairs")

    state.record_http_event(
        event_time=datetime.now(timezone.utc).isoformat(),
        route_name="region",
        clean_path="/region",
        raw_path="/region",
        method="GET",
        host="api-roborock.example.com",
        remote="192.168.8.11:54321",
        did="1103821560705",
    )

    snapshot = state.onboarding_session_snapshot()
    linked = credentials.resolve_device(did="1103821560705")
    assert linked is not None
    assert linked["duid"] == "cloud-q7-b"
    assert "already linked to DUID cloud-q7-b" in snapshot["identity_conflict"]
    assert snapshot["status"] == "conflict"


def test_runtime_state_merges_existing_did_phantom_when_onboarding_links_selected_duid(tmp_path: Path) -> None:
    credentials_path = tmp_path / "runtime_credentials.json"
    credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "devices": [
                    {
                        "did": "",
                        "duid": "cloud-q7-a",
                        "name": "Q7 Upstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-a",
                        "localkey": "local-key-a",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    credentials = RuntimeCredentialsStore(credentials_path)
    state = RuntimeState(log_dir=tmp_path, key_state_file=None, runtime_credentials=credentials)
    state.upsert_vacuum("cloud-q7-a", name="Q7 Upstairs", id_kind="duid")
    state.upsert_vacuum(
        "1103821560705",
        did="1103821560705",
        id_kind="did",
        last_nc_at="2026-06-04T17:35:34+00:00",
    )
    state.start_onboarding_session(target_duid="cloud-q7-a", target_name="Q7 Upstairs")

    event_time = datetime.now(timezone.utc).isoformat()
    state.record_http_event(
        event_time=event_time,
        route_name="region",
        clean_path="/region",
        raw_path="/region",
        method="GET",
        host="api-roborock.example.com",
        remote="192.168.8.10:54321",
        did="1103821560705",
    )

    vacuums = state.vacuum_snapshot()
    assert [vacuum["duid"] for vacuum in vacuums] == ["cloud-q7-a"]
    assert vacuums[0]["did"] == "1103821560705"
    assert set(vacuums[0]["onboarding_steps"]) == {"nc_prepare", "region"}


def test_runtime_state_merge_rewrites_active_mqtt_connection_mapping(tmp_path: Path) -> None:
    credentials_path = tmp_path / "runtime_credentials.json"
    credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "devices": [
                    {
                        "did": "",
                        "duid": "cloud-q7-a",
                        "name": "Q7 Upstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-a",
                        "localkey": "local-key-a",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    credentials = RuntimeCredentialsStore(credentials_path)
    state = RuntimeState(log_dir=tmp_path, key_state_file=None, runtime_credentials=credentials)
    state.upsert_vacuum("cloud-q7-a", name="Q7 Upstairs", id_kind="duid")
    state.record_mqtt_connection(conn_id="mqtt-1", client_ip="192.168.8.10", client_port=54321)
    state.record_mqtt_message(
        conn_id="mqtt-1",
        direction="c2b",
        topic="rr/d/i/1103821560705/c25b14ceac358d2a",
        payload_preview="{}",
    )
    state.start_onboarding_session(target_duid="cloud-q7-a", target_name="Q7 Upstairs")

    state.record_http_event(
        event_time=datetime.now(timezone.utc).isoformat(),
        route_name="region",
        clean_path="/region",
        raw_path="/region",
        method="GET",
        host="api-roborock.example.com",
        remote="192.168.8.10:54321",
        did="1103821560705",
    )

    [vacuum] = state.vacuum_snapshot()
    assert vacuum["duid"] == "cloud-q7-a"
    assert vacuum["connected"] is True
    assert state._conn_to_vacuums["mqtt-1"] == {"cloud-q7-a"}

    state.record_mqtt_disconnect(conn_id="mqtt-1")

    [vacuum] = state.vacuum_snapshot()
    assert vacuum["duid"] == "cloud-q7-a"
    assert state._vacuums["cloud-q7-a"]["connected"] is False


def test_runtime_state_onboarding_device_mqtt_candidate_requires_matching_ip_and_public_key(tmp_path: Path) -> None:
    credentials_path = tmp_path / "runtime_credentials.json"
    credentials_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "devices": [
                    {
                        "did": "",
                        "duid": "cloud-q7-a",
                        "name": "Q7 Upstairs",
                        "model": "roborock.vacuum.sc05",
                        "product_id": "product-q7-a",
                        "localkey": "local-key-a",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    key_state_path = tmp_path / "device_key_state.json"
    key_state_path.write_text(
        json.dumps(
            {
                "devices": {
                    "1103821560705": {
                        "modulus_hex": "ab",
                    }
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )
    credentials = RuntimeCredentialsStore(credentials_path)
    state = RuntimeState(log_dir=tmp_path, key_state_file=key_state_path, runtime_credentials=credentials)
    state.upsert_vacuum("cloud-q7-a", name="Q7 Upstairs", id_kind="duid")
    state.start_onboarding_session(target_duid="cloud-q7-a", target_name="Q7 Upstairs")

    event_time = datetime.now(timezone.utc).isoformat()
    state.record_http_event(
        event_time=event_time,
        route_name="region",
        clean_path="/region",
        raw_path="/region",
        method="GET",
        host="api-roborock.example.com",
        remote="192.168.8.10:54321",
        did="1103821560705",
    )
    state.record_http_event(
        event_time=event_time,
        route_name="nc_prepare",
        clean_path="/nc",
        raw_path="/nc",
        method="GET",
        host="api-roborock.example.com",
        remote="192.168.8.10:54321",
        did="1103821560705",
    )

    candidate = state.onboarding_device_mqtt_candidate(client_ip="192.168.8.10")
    assert candidate is not None
    assert candidate["did"] == "1103821560705"
    assert candidate["duid"] == "cloud-q7-a"
    assert state.onboarding_device_mqtt_candidate(client_ip="192.168.8.11") is None
