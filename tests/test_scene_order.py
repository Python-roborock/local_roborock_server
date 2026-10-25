import json
from pathlib import Path

from roborock_local_server.backend import (
    ServerContext,
    default_endpoint_rules,
    resolve_route,
)


def _make_context(tmp_path: Path) -> ServerContext:
    return ServerContext(
        api_host="api.example.com",
        mqtt_host="mqtt.example.com",
        wood_host="wood.example.com",
        region="us",
        protocol_login_email="user@example.com",
        localkey="key123",
        duid="duid-1",
        mqtt_usr="usr",
        mqtt_passwd="pwd",
        mqtt_clientid="cid",
        https_port=443,
        mqtt_tls_port=8883,
        http_jsonl=tmp_path / "http.jsonl",
        mqtt_jsonl=tmp_path / "mqtt.jsonl",
        loggers={},
    )


def _write_inventory(tmp_path: Path, *, scenes: list[dict[str, object]], scene_order: list[object]) -> None:
    (tmp_path / "web_api_inventory.json").write_text(
        json.dumps(
            {
                "home": {"id": 424242, "name": "Test Home"},
                "scenes": scenes,
                "scene_order": scene_order,
            }
        )
        + "\n",
        encoding="utf-8",
    )


def _get_scene_order(tmp_path: Path, query_params: dict[str, list[str]] | None = None) -> tuple[str, dict]:
    return resolve_route(
        rules=default_endpoint_rules(),
        context=_make_context(tmp_path),
        clean_path="/user/scene/order",
        query_params=query_params or {"homeId": ["424242"]},
        body_params={},
        method="GET",
    )


_SCENES = [
    {"id": 101, "name": "Scene 1", "device_id": "device-a"},
    {"id": 102, "name": "Scene 2", "device_id": "device-b"},
    {"id": 103, "name": "Scene 3", "device_id": "device-a"},
]


def test_scene_order_groups_scene_ids_per_device(tmp_path: Path) -> None:
    _write_inventory(tmp_path, scenes=_SCENES, scene_order=[103, 102, 101])

    route, payload = _get_scene_order(tmp_path)

    assert route == "get_scene_order"
    # ApiReturn<List<SceneOrder>> with SceneOrder = {"duid", "sceneIds"}.
    assert payload["data"] == [
        {"duid": "device-a", "sceneIds": [103, 101]},
        {"duid": "device-b", "sceneIds": [102]},
    ]
    assert payload["result"] == payload["data"]


def test_scene_order_reads_cloud_object_form_from_inventory(tmp_path: Path) -> None:
    # The cloud import stores the cloud's own response verbatim.
    _write_inventory(
        tmp_path,
        scenes=_SCENES,
        scene_order=[
            {"duid": "device-b", "sceneIds": [102]},
            {"duid": "device-a", "sceneIds": [103, 101]},
        ],
    )

    _, payload = _get_scene_order(tmp_path)

    assert payload["data"] == [
        {"duid": "device-b", "sceneIds": [102]},
        {"duid": "device-a", "sceneIds": [103, 101]},
    ]


def test_scene_order_respects_duids_filter(tmp_path: Path) -> None:
    _write_inventory(tmp_path, scenes=_SCENES, scene_order=[101, 102, 103])

    _, payload = _get_scene_order(tmp_path, {"homeId": ["424242"], "duids": ["device-b"]})

    assert payload["data"] == [{"duid": "device-b", "sceneIds": [102]}]


def test_scene_order_for_other_home_is_empty_list(tmp_path: Path) -> None:
    _write_inventory(tmp_path, scenes=_SCENES, scene_order=[101, 102, 103])

    _, payload = _get_scene_order(tmp_path, {"homeId": ["999"]})

    assert payload["data"] == []


def test_delete_scene_keeps_remaining_order_from_cloud_object_form(tmp_path: Path) -> None:
    from roborock_local_server.bundled_backend.https_server.routes.user.scene.service import delete_scene

    _write_inventory(
        tmp_path,
        scenes=_SCENES,
        scene_order=[{"duid": "device-a", "sceneIds": [103, 101]}, {"duid": "device-b", "sceneIds": [102]}],
    )

    delete_scene(_make_context(tmp_path), 101)

    _, payload = _get_scene_order(tmp_path)
    assert payload["data"] == [
        {"duid": "device-a", "sceneIds": [103]},
        {"duid": "device-b", "sceneIds": [102]},
    ]
