import asyncio

from fastapi.testclient import TestClient

from conftest import write_release_config
from roborock_local_server import matter_proxy
from roborock_local_server.config import load_config, resolve_paths
from roborock_local_server.server import ReleaseSupervisor


def test_only_the_matter_key_get_matches() -> None:
    assert matter_proxy.matches("/iot.roborock.com/fwapi/matter/key", "GET")
    assert matter_proxy.matches("/fwapi/matter/key", "get")
    assert not matter_proxy.matches("/iot.roborock.com/fwapi/matter/key", "POST")
    assert not matter_proxy.matches("/iot.roborock.com/fwapi/createca", "GET")
    assert not matter_proxy.matches("/fwapi/matter/keys", "GET")


def test_the_upstream_is_the_regional_cloud_host() -> None:
    assert matter_proxy.upstream_url("us", "did=1") == "https://usiot.roborock.com/fwapi/matter/key?did=1"
    assert matter_proxy.upstream_url("eu", "") == "https://euiot.roborock.com/fwapi/matter/key"
    assert matter_proxy.upstream_url("../x", "") == "https://usiot.roborock.com/fwapi/matter/key"


def test_it_is_off_unless_enabled(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("ROBOROCK_SERVER_MATTER_KEY_PROXY", raising=False)
    config_file = write_release_config(tmp_path)
    assert load_config(config_file).matter.key_proxy is False
    monkeypatch.setenv("ROBOROCK_SERVER_MATTER_KEY_PROXY", "true")
    assert load_config(config_file).matter.key_proxy is True


def test_a_request_is_forwarded_and_the_answer_returned(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ROBOROCK_SERVER_MATTER_KEY_PROXY", "true")
    config_file = write_release_config(tmp_path)
    config = load_config(config_file)
    supervisor = ReleaseSupervisor(config=config, paths=resolve_paths(config_file, config))
    seen = {}

    async def fake_forward(request, region):
        from fastapi.responses import Response

        seen["region"], seen["auth"] = region, request.headers.get("authorization")
        return Response(content=b"KEYBYTES", status_code=200, media_type="application/octet-stream")

    monkeypatch.setattr(matter_proxy, "forward", fake_forward)
    client = TestClient(supervisor.app)
    response = client.get("/iot.roborock.com/fwapi/matter/key?x=1", headers={"Authorization": "abc"})

    assert response.status_code == 200 and response.content == b"KEYBYTES"
    assert seen["auth"] == "abc" and seen["region"]
