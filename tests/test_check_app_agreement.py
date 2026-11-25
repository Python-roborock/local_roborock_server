import json
from pathlib import Path

from roborock_local_server.backend import (
    ServerContext,
    default_endpoint_rules,
    resolve_route,
)


class _StubRuntimeCredentials:
    """Treat inventory devices as paired so home_payload keeps them."""

    def __init__(self, paired: bool = True) -> None:
        self._paired = paired

    def resolve_device(self, *, duid: str = "", **_kwargs):
        if not self._paired:
            return None
        return {"did": f"did-{duid}", "device_mqtt_usr": "mqtt-user"}

    def __getattr__(self, _name):
        return lambda *args, **kwargs: None


def _make_context(tmp_path: Path, *, paired: bool = True) -> ServerContext:
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
        runtime_credentials=_StubRuntimeCredentials(paired),
    )


def _write_inventory(tmp_path: Path, devices: list[dict[str, object]]) -> None:
    (tmp_path / "web_api_inventory.json").write_text(
        json.dumps({"home": {"id": 424242, "name": "Test Home"}, "devices": devices}) + "\n",
        encoding="utf-8",
    )


def _check_app_agreement(tmp_path: Path, *, paired: bool = True) -> tuple[str, dict]:
    return resolve_route(
        rules=default_endpoint_rules(),
        context=_make_context(tmp_path, paired=paired),
        clean_path="/api/v1/checkAppAgreement",
        query_params={},
        body_params={},
        method="GET",
    )


def test_check_app_agreement_reports_all_agreements_accepted(tmp_path: Path) -> None:
    _write_inventory(
        tmp_path,
        [
            {"duid": "device-a", "name": "Vacuum A", "model": "roborock.vacuum.a15", "product_id": "product-a"},
            {"duid": "device-b", "name": "Vacuum B", "model": "roborock.vacuum.a15", "product_id": "product-a"},
        ],
    )

    route, payload = _check_app_agreement(tmp_path)

    assert route == "check_app_agreement_v1"
    assert payload["code"] == 200
    data = payload["data"]
    assert data["userAndPrivacyAgree"] is True
    assert data["improvementPlanAgree"] is True
    assert data["recommendationAgree"] is True
    agreements = data["userPluginAgreementList"]
    assert {entry["deviceId"] for entry in agreements} == {"device-a", "device-b"}
    for entry in agreements:
        assert set(entry) == {"deviceId", "type", "version", "extra"}
        assert isinstance(entry["type"], str)
        assert isinstance(entry["version"], int)
        assert entry["extra"] == ""
    assert sorted(entry["type"] for entry in agreements if entry["deviceId"] == "device-a") == ["PRIVACY_POLICY", "USER_AGREEMENT"]


def test_check_app_agreement_without_paired_devices_returns_empty_plugin_list(tmp_path: Path) -> None:
    _write_inventory(
        tmp_path,
        [{"duid": "device-a", "name": "Vacuum A", "model": "roborock.vacuum.a15", "product_id": "product-a"}],
    )

    route, payload = _check_app_agreement(tmp_path, paired=False)

    assert route == "check_app_agreement_v1"
    assert payload["data"]["userAndPrivacyAgree"] is True
    assert payload["data"]["userPluginAgreementList"] == []
