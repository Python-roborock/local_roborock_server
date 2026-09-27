import json
import logging
from pathlib import Path

from roborock_local_server.backend import default_endpoint_rules, resolve_route, ServerContext


def _ctx(tmp_path: Path) -> ServerContext:
    return ServerContext(
        api_host="api.example.com",
        mqtt_host="mqtt.example.com",
        wood_host="wood.example.com",
        region="us",
        protocol_login_email="user@example.com",
        localkey="k",
        duid="duid-1",
        mqtt_usr="u",
        mqtt_passwd="p",
        mqtt_clientid="c",
        https_port=443,
        mqtt_tls_port=8883,
        http_jsonl=tmp_path / "http.jsonl",
        mqtt_jsonl=tmp_path / "mqtt.jsonl",
        loggers={"api": logging.getLogger("test-scene-delete")},
    )


def _write(tmp_path: Path, inventory: dict) -> Path:
    path = tmp_path / "web_api_inventory.json"
    path.write_text(json.dumps(inventory), encoding="utf-8")
    return path


def _resolve(ctx, path, method):
    return resolve_route(
        rules=default_endpoint_rules(), context=ctx, clean_path=path,
        query_params={}, body_params={}, method=method,
    )


def test_delete_scene_removes_from_all_collections(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    inv_path = _write(tmp_path, {
        "home": {"id": 1},
        "scenes": [{"id": 1, "name": "A", "device_id": "duid-1"}, {"id": 2, "name": "B", "device_id": "duid-1"}],
        "home_scenes": [{"id": 1, "name": "A"}, {"id": 2, "name": "B"}],
        "scene_order": [2, 1],
    })

    route, payload = _resolve(ctx, "/user/scene/1", "DELETE")

    assert route == "delete_scene"
    assert payload["success"] is True
    inv = json.loads(inv_path.read_text())
    assert [s["id"] for s in inv["scenes"]] == [2]
    assert [s["id"] for s in inv["home_scenes"]] == [2]
    assert inv["scene_order"] == [2]


def test_delete_unknown_scene_is_idempotent(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    inv_path = _write(tmp_path, {"scenes": [{"id": 2, "name": "B"}], "scene_order": [2]})

    route, payload = _resolve(ctx, "/user/scene/99", "DELETE")

    assert route == "delete_scene"
    assert payload["success"] is True
    assert [s["id"] for s in json.loads(inv_path.read_text())["scenes"]] == [2]


def test_get_on_scene_id_does_not_hit_delete(tmp_path: Path) -> None:
    route, _ = _resolve(_ctx(tmp_path), "/user/scene/1", "GET")
    assert route != "delete_scene"
