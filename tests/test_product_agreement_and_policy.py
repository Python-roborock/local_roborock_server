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


def _resolve(tmp_path: Path, clean_path: str) -> tuple[str, dict]:
    return resolve_route(
        rules=default_endpoint_rules(),
        context=_make_context(tmp_path),
        clean_path=clean_path,
        query_params={"country": ["NO"], "productid": ["41"]},
        body_params={},
        method="GET",
    )


def test_product_agreement_and_policy_returns_document_urls(tmp_path: Path) -> None:
    route, payload = _resolve(tmp_path, "/api/v1/product/agreementAndPolicy")

    assert route == "product_agreement_and_policy_v1"
    assert payload["code"] == 200
    data = payload["data"]
    assert set(data) == {"userAgreement", "privacyProtocol"}
    for document in data.values():
        assert isinstance(document["version"], str) and document["version"]
        assert document["langUrl"]["en"].startswith("https://")


def test_product_agreement_and_policy_matches_latest_agreements(tmp_path: Path) -> None:
    _, policy = _resolve(tmp_path, "/api/v1/product/agreementAndPolicy")
    _, latest = _resolve(tmp_path, "/api/v4/app/agreement/latest")

    for name in ("userAgreement", "privacyProtocol"):
        assert policy["data"][name] == latest["data"][name]
