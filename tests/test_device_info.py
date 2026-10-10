"""Signed firmware metadata must never overwrite another device's identity."""

import base64
import json
import logging
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import roborock_local_server.backend as backend
from https_server.routes.bootstrap import catchall, device_info


@pytest.fixture
def setup_report(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    inventory = {
        "home": {"name": "Home"},
        "devices": [
            {"did": "123", "duid": "cloud-a", "name": "My Vacuum", "productId": "product-a", "localKey": "existing-key"},
            {"did": "456", "duid": "cloud-b", "sn": "OTHER"},
        ],
    }
    path = tmp_path / "web_api_inventory.json"
    path.write_text(json.dumps(inventory))
    ctx = SimpleNamespace(http_jsonl=tmp_path / "http.jsonl", runtime_credentials=None,
                          device_public_key=lambda did: key.public_key() if did == "123" else None)
    fields = {"did": "123", "featureset": "123456789", "newfeatureset": "0000000AbCD", "pid": "roborock.vacuum.a87", "sn": "TESTSERIAL"}
    canonical = "&".join(f"{name}={value}" for name, value in fields.items()).encode()
    params = {name: [value] for name, value in fields.items()}
    params["signature"] = [base64.b64encode(key.sign(canonical, padding.PKCS1v15(), hashes.SHA256())).decode()]
    return ctx, path, inventory, params


def _request(ctx, params, *, path="/devices/123/info", method="POST"):
    return backend.resolve_route(rules=backend.default_endpoint_rules(), context=ctx, clean_path=path,
                                 query_params={}, body_params=params, method=method)


def test_verified_upload_updates_only_metadata(setup_report):
    ctx, path, original, params = setup_report
    route, response = _request(ctx, params)
    assert route == "device_info"
    assert response["code"] == 200
    assert response == catchall.build(ctx, {}, params, "/devices/123/info")
    updated = json.loads(path.read_text())
    device = updated["devices"][0]
    assert device["sn"] == "TESTSERIAL"
    assert device["featureSet"] == "123456789"
    assert device["newFeatureSet"] == "0000000AbCD"  # Preserve leading zeroes.
    assert set(device) - set(original["devices"][0]) == {"sn", "featureSet", "newFeatureSet"}
    for key, value in original["devices"][0].items():
        assert device[key] == value
    assert updated["devices"][1] == original["devices"][1]
    assert updated["home"] == original["home"]
    before = path.read_bytes()
    _request(ctx, params)
    assert path.read_bytes() == before


@pytest.mark.parametrize("change", ["tampered", "missing", "duplicate", "extra", "wrong_did", "unknown_key", "bad_base64"])
def test_unverifiable_upload_acknowledged_without_writes(setup_report, change):
    ctx, path, _, params = setup_report
    before = path.read_bytes()
    if change == "tampered": params["sn"] = ["ALTERED"]
    if change == "missing": del params["signature"]
    if change == "duplicate": params["did"].append("456")
    if change == "extra": params["other"] = ["value"]
    if change == "wrong_did": params["did"] = ["456"]
    if change == "unknown_key": ctx.device_public_key = lambda did: None
    if change == "bad_base64": params["signature"] = ["!!!!"]
    route, response = _request(ctx, params)
    assert route == "device_info" and response["code"] == 200
    assert path.read_bytes() == before


def test_cloud_duid_link_selects_known_device(setup_report):
    ctx, path, _, params = setup_report
    inventory = json.loads(path.read_text())
    del inventory["devices"][0]["did"]
    path.write_text(json.dumps(inventory))
    ctx.runtime_credentials = SimpleNamespace(resolve_device=lambda **kwargs: {"did": "123", "duid": "cloud-a"})
    _request(ctx, params)
    assert json.loads(path.read_text())["devices"][0]["sn"] == "TESTSERIAL"


def test_verified_unknown_device_does_not_create_inventory_entry(setup_report):
    ctx, path, _, params = setup_report
    path.write_text('{"devices": []}')
    _request(ctx, params)
    assert json.loads(path.read_text()) == {"devices": []}


def test_existing_feature_aliases_stay_consistent(setup_report):
    ctx, path, _, params = setup_report
    inventory = json.loads(path.read_text())
    inventory["devices"][0].update(feature_set="old", new_feature_set="old")
    path.write_text(json.dumps(inventory))
    _request(ctx, params)
    device = json.loads(path.read_text())["devices"][0]
    assert device["feature_set"] == device["featureSet"] == "123456789"
    assert device["new_feature_set"] == device["newFeatureSet"] == "0000000AbCD"


@pytest.mark.parametrize("method,path", [("GET", "/devices/123/info"), ("POST", "/user/devices/123/info"), ("POST", "/devices/abc/info")])
def test_route_scope(setup_report, method, path):
    ctx, inventory_path, _, params = setup_report
    before = inventory_path.read_bytes()
    route, _ = _request(ctx, params, path=path, method=method)
    assert route == "catchall"
    assert inventory_path.read_bytes() == before


@pytest.mark.parametrize("change,outcome", [
    ("valid", "stored"), ("repeat", "unchanged"), ("tampered", "invalid_signature"),
    ("missing_key", "missing_key"), ("unmatched", "unmatched"),
    ("write_failed", "write_failed"),
])
def test_outcome_diagnostics_are_sanitized(setup_report, caplog, monkeypatch, change, outcome):
    ctx, path, _, params = setup_report
    if change == "repeat":
        _request(ctx, params)
    elif change == "tampered":
        params["sn"] = ["ALTERED"]
    elif change == "missing_key":
        ctx.device_public_key = lambda did: None
    elif change == "unmatched":
        path.write_text('{"devices": []}')
    elif change == "write_failed":
        monkeypatch.setattr(device_info, "write_inventory", lambda *args: False)
    with caplog.at_level(logging.INFO, logger=device_info.__name__):
        _request(ctx, params)
    assert f"did=123 outcome={outcome} updated=" in caplog.text
    assert params["sn"][0] not in caplog.text
    assert params["signature"][0] not in caplog.text


@pytest.mark.parametrize("prefix", ["", "/.roborock.com"])
def test_real_http_form_preserves_base64_signature(tmp_path, prefix):
    from conftest import write_release_config
    from fastapi.testclient import TestClient
    from roborock_local_server.config import load_config, resolve_paths
    from roborock_local_server.server import ReleaseSupervisor

    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    paths = resolve_paths(config_file, config)
    fields = {"did": "123", "featureset": "123456789", "newfeatureset": "0000000AbCD",
              "pid": "roborock.vacuum.a87", "sn": "TESTSERIAL"}
    canonical = "&".join(f"{name}={value}" for name, value in fields.items()).encode()
    # Select a synthetic key whose signature exercises both URL-escaped chars.
    for _ in range(100):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        signature = base64.b64encode(key.sign(canonical, padding.PKCS1v15(), hashes.SHA256())).decode()
        if "+" in signature and "/" in signature:
            break
    else:
        pytest.fail("Could not produce representative synthetic signature")
    for path, payload in (
        (paths.inventory_path, {"devices": [{"did": "123", "duid": "cloud-a"}]}),
        (paths.device_key_state_path,
         {"devices": {"123": {"modulus_hex": format(key.public_key().public_numbers().n, "x")}}}),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload))
    supervisor = ReleaseSupervisor(config=config, paths=paths)
    body = urlencode({**fields, "signature": signature})
    assert "%2B" in body and "%2F" in body
    with TestClient(supervisor.app) as client:
        response = client.post(f"{prefix}/devices/123/info", content=body,
                               headers={"content-type": "application/x-www-form-urlencoded"})
    assert response.status_code == 200
    assert response.json() == catchall.build(supervisor.context, {}, {}, "/devices/123/info")
    inventory = json.loads(paths.inventory_path.read_text())
    assert inventory["devices"][0]["sn"] == fields["sn"]
    entries = [json.loads(line) for line in paths.http_jsonl_path.read_text().splitlines()]
    assert entries[-1]["route"] == "device_info"
