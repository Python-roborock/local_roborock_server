import json
from pathlib import Path

import pytest

from roborock_local_server.backend import default_endpoint_rules, resolve_route
from roborock_local_server.server import ReleaseSupervisor
from test_scene_delete import _ctx, _write


# Cloud response captured 2026-10-10 by replaying an authenticated app report.
CLOUD_SUCCESS = json.loads((Path(__file__).parent / "fixtures" / "scene_validity_cloud_success.json").read_text(encoding="utf-8"))


def _resolve(tmp_path: Path, reports, *, method="PUT", path="/user/scene/validity"):
    raw = json.dumps(reports)
    return resolve_route(
        rules=default_endpoint_rules(), context=_ctx(tmp_path), clean_path=path,
        query_params={}, body_params={"__json": [raw]}, method=method,
    )


def test_reports_persist_and_clear_without_changing_actions(tmp_path):
    param = json.dumps({"action": {"items": [{"id": 1, "enabled": True}, {"id": 3}]}})
    inventory = {
        "scenes": [{"id": 42, "param": param, "enabled": True,
                    "extra": json.dumps({"other": {"keep": True}})},
                   {"id": 99, "param": "untouched", "extra": None}],
        "home_scenes": [{"id": 42, "param": param, "extra": {"tag": "keep"}}],
        "scene_order": [99, 42], "devices": [{"duid": "test-device"}],
    }
    path = _write(tmp_path, inventory)
    route, response = _resolve(tmp_path, [{"sceneId": "42", "extra": '{"invalidActions":[1,3]}'}])
    assert route == "put_scene_validity"
    assert response == CLOUD_SUCCESS
    saved = json.loads(path.read_text())
    for key in ("scenes", "home_scenes"):
        scene = saved[key][0]
        assert scene["param"] == param
        assert (json.loads(scene["extra"]) if isinstance(scene["extra"], str) else scene["extra"])["invalidActions"] == [1, 3]
    assert json.loads(saved["scenes"][0]["extra"])["other"] == {"keep": True}
    assert saved["home_scenes"][0]["extra"]["tag"] == "keep"
    assert saved["scenes"][0]["enabled"] is True
    assert saved["scenes"][1] == inventory["scenes"][1]
    assert saved["scene_order"] == inventory["scene_order"]
    assert saved["devices"] == inventory["devices"]

    _resolve(tmp_path, [{"sceneId": 42, "extra": {"invalidActions": []}}])
    cleared = json.loads(path.read_text())
    assert json.loads(cleared["scenes"][0]["extra"])["invalidActions"] == []
    assert cleared["scenes"][0]["param"] == param


def test_unknown_scene_and_empty_reports_do_not_create_or_write(tmp_path):
    path = _write(tmp_path, {"scenes": [{"id": 1, "extra": None}]})
    original = path.read_bytes()
    for reports in ([], [{"sceneId": "999", "extra": '{"invalidActions":[1]}'}]):
        assert _resolve(tmp_path, reports)[0] == "put_scene_validity"
        assert path.read_bytes() == original


@pytest.mark.parametrize("reports", [{}, None, "not an array"])
def test_non_array_rejected_without_write(tmp_path, reports, caplog):
    path = _write(tmp_path, {"scenes": [{"id": 42, "extra": None}]})
    original = path.read_bytes()
    route, response = _resolve(tmp_path, reports)
    assert route == "put_scene_validity"
    assert response["status"] == "BAD_REQUEST"
    assert response["code"] == "parameter.error"
    assert "api" not in response and "result" not in response
    assert path.read_bytes() == original
    assert "Scene validity rejected" in caplog.text


@pytest.mark.parametrize("bad", [
    None, {"sceneId": "42", "extra": "private malformed extra"},
    {"sceneId": True, "extra": {"invalidActions": []}},
    {"sceneId": "2" * 5000, "extra": {"invalidActions": []}},
    {"sceneId": "²", "extra": {"invalidActions": []}},
    {"sceneId": "42", "extra": {"invalidActions": [True]}},
    {"sceneId": "42", "extra": {"invalidActions": ["1"]}},
])
def test_invalid_entry_does_not_block_independent_valid_report(tmp_path, bad, caplog):
    path = _write(tmp_path, {"scenes": [{"id": 42, "extra": None}, {"id": "43"}]})
    reports = [bad, {"sceneId": 43, "extra": '{"invalidActions":[1]}'}]
    assert _resolve(tmp_path, reports)[1]["success"] is True
    saved = json.loads(path.read_text())["scenes"]
    assert saved[0] == {"id": 42, "extra": None}
    assert json.loads(saved[1]["extra"]) == {"invalidActions": [1]}
    assert "Skipping scene validity entry 0" in caplog.text
    assert "private malformed extra" not in caplog.text


@pytest.mark.parametrize("extra", [None, "", "{}", "null", {}, {"other": 1}])
def test_missing_invalid_actions_is_not_a_clear_report(tmp_path, extra):
    path = _write(tmp_path, {"scenes": [{"id": 42, "extra": '{"invalidActions":[1]}'}]})
    original = path.read_bytes()
    assert _resolve(tmp_path, [{"sceneId": "42", "extra": extra}])[1]["success"] is True
    assert path.read_bytes() == original


def test_method_and_path_are_scoped_and_use_existing_hawk_gate(tmp_path):
    assert _resolve(tmp_path, [], path="/user/scene/validity/")[0] == "put_scene_validity"
    for method in ("GET", "POST", "DELETE"):
        assert _resolve(tmp_path, [], method=method)[0] == "catchall"
    assert _resolve(tmp_path, [], path="/user/scene/validity/other")[0] == "catchall"
    assert ReleaseSupervisor._required_protocol_auth("/user/scene/validity") == "hawk"


def test_repeated_and_multiple_reports_preserve_unrelated_extra(tmp_path, monkeypatch):
    path = _write(tmp_path, {"scenes": [{"id": 1, "extra": '{"other":1}'}, {"id": 2}]})
    reports = [{"sceneId": "1", "extra": '{"invalidActions":[5],"other":99}'},
               {"sceneId": "2", "extra": '{"invalidActions":[7]}'}]
    _resolve(tmp_path, reports)
    original = path.read_bytes()
    def unexpected_write(*_args):
        pytest.fail("Identical validity reports must not rewrite the inventory")
    monkeypatch.setattr("https_server.routes.user.scene.validity.write_inventory", unexpected_write)
    _resolve(tmp_path, reports)
    assert path.read_bytes() == original
    scenes = json.loads(original)["scenes"]
    assert json.loads(scenes[0]["extra"]) == {"other": 1, "invalidActions": [5]}
    assert json.loads(scenes[1]["extra"])["invalidActions"] == [7]


@pytest.mark.parametrize("stored_extra", ["bad private value", [], "[]"])
def test_malformed_stored_extra_preserved_while_other_reports_saved(tmp_path, stored_extra, caplog):
    bad = {"id": 2, "extra": stored_extra, "param": "unchanged"}
    path = _write(tmp_path, {"scenes": [{"id": 1}, bad]})
    reports = [{"sceneId": str(i), "extra": '{"invalidActions":[1]}'} for i in (1, 2)]
    assert _resolve(tmp_path, reports)[1]["success"] is True
    saved = json.loads(path.read_text())["scenes"]
    assert json.loads(saved[0]["extra"]) == {"invalidActions": [1]}
    assert saved[1] == bad
    assert "stored scenes record 1" in caplog.text
    assert "bad private value" not in caplog.text


@pytest.mark.parametrize("stored_extra", [None, "", "   ", "null"])
def test_blank_stored_extra_accepts_reports(tmp_path, stored_extra):
    path = _write(tmp_path, {"scenes": [{"id": 42, "extra": stored_extra}]})
    assert _resolve(tmp_path, [{"sceneId": "42", "extra": '{"invalidActions":[1]}'}])[1]["success"] is True
    assert json.loads(json.loads(path.read_text())["scenes"][0]["extra"]) == {"invalidActions": [1]}


def test_write_failure_is_logged_without_changing_ack(tmp_path, monkeypatch, caplog):
    path = _write(tmp_path, {"scenes": [{"id": 42}]})
    original = path.read_bytes()
    monkeypatch.setattr("https_server.routes.user.scene.validity.write_inventory", lambda *_: False)
    response = _resolve(tmp_path, [{"sceneId": "42", "extra": '{"invalidActions":[1]}'}])[1]
    assert response == CLOUD_SUCCESS
    assert "Scene validity inventory write failed" in caplog.text
    assert path.read_bytes() == original


@pytest.mark.parametrize("body, fixture_key, authenticated", [
    (b"{}", "non_array_body", True),
    (b"{", "malformed_json", True),
    (b"[]", "missing_authentication", False),
    (json.dumps([{"sceneId": "9223372036854775807", "extra": json.dumps({"invalidActions": "not-a-list"})}]).encode(), "invalid_actions_type", True),
    (b'[{"sceneId":"9223372036854775807","extra":"{\\\"invalidActions\\\":[1]}"}]', "unknown_scene_id", True),
])
def test_http_response_matches_cloud_probe(tmp_path, body, fixture_key, authenticated):
    from datetime import datetime
    from fastapi.testclient import TestClient
    from test_protocol_auth import _build_supervisor
    from shared.protocol_auth import build_hawk_authorization

    supervisor, paths = _build_supervisor(tmp_path)
    original = paths.inventory_path.read_bytes()
    headers = {"content-type": "application/json"}
    if authenticated:
        user = supervisor.protocol_auth.availability().user
        assert user is not None
        headers["authorization"] = build_hawk_authorization(
            user=user, path="/user/scene/validity", json_body=body,
        )
    response = TestClient(supervisor.app).put("/user/scene/validity", content=body, headers=headers)
    fixture = json.loads((Path(__file__).parent / "fixtures" / "scene_validity_cloud_errors.json").read_text(encoding="utf-8"))[fixture_key]
    assert response.status_code == fixture["http_status"]
    actual = response.json()
    expected = dict(fixture["response"])
    if "timestamp" in expected:
        assert datetime.fromisoformat(actual.pop("timestamp")).utcoffset().total_seconds() == 0
        expected.pop("timestamp")
    assert actual == expected
    assert paths.inventory_path.read_bytes() == original
