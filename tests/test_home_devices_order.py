import json
from pathlib import Path

from roborock_local_server.backend import (
    ServerContext,
    default_endpoint_rules,
    resolve_route,
)


class _PairedRuntimeCredentials:
    """Treat every inventory device as paired so home_payload keeps it."""

    def resolve_device(self, *, duid: str = "", **_kwargs):
        return {"did": f"did-{duid}", "device_mqtt_usr": "mqtt-user"}

    def __getattr__(self, _name):
        return lambda *args, **kwargs: None


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
        runtime_credentials=_PairedRuntimeCredentials(),
    )


def test_home_devices_order_returns_device_sort_container(tmp_path: Path) -> None:
    (tmp_path / "web_api_inventory.json").write_text(
        json.dumps(
            {
                "home": {"id": 424242, "name": "Test Home"},
                "devices": [
                    {"duid": "device-a", "name": "Vacuum A", "model": "roborock.vacuum.a15", "product_id": "product-a"},
                    {"duid": "device-b", "name": "Vacuum B", "model": "roborock.vacuum.a15", "product_id": "product-a"},
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    route, payload = resolve_route(
        rules=default_endpoint_rules(),
        context=_make_context(tmp_path),
        clean_path="/api/v1/home/424242/devices/order",
        query_params={},
        body_params={},
        method="GET",
    )

    assert route == "home_devices_order"
    assert payload["code"] == 200
    # DeviceSortContainerV2 is an object, not a bare list of duids.
    assert payload["data"] == {
        "type": "HOME",
        "listOrders": [
            {"source": "RR", "did": "device-a", "order": 0},
            {"source": "RR", "did": "device-b", "order": 1},
        ],
    }
