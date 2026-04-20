import importlib
import io
import json
import ssl
import sys
import types
from urllib.error import HTTPError

import pytest


class _FakeResponse:
    def __init__(self, status: int = 200) -> None:
        self.status = status

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def read(self) -> bytes:
        return b""


def _load_mitm_redirect(monkeypatch):
    fake_log = types.SimpleNamespace(
        info=lambda *args, **kwargs: None,
        warn=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    )
    fake_mitmproxy = types.SimpleNamespace(
        ctx=types.SimpleNamespace(log=fake_log),
        http=types.SimpleNamespace(HTTPFlow=object),
    )
    monkeypatch.setitem(sys.modules, "mitmproxy", fake_mitmproxy)
    sys.modules.pop("mitm_redirect", None)
    return importlib.import_module("mitm_redirect")


def _sample_user_data() -> dict[str, object]:
    return {
        "token": "real-cloud-token-999",
        "rruid": "real-cloud-rruid-999",
        "rriot": {
            "u": "real-cloud-hawk-user",
            "s": "real-cloud-hawk-session",
            "h": "real-cloud-hawk-secret",
            "k": "real-cloud-mqtt-key",
        },
    }


class _FakeRequest:
    def __init__(self, host: str, path: str) -> None:
        self.pretty_host = host
        self.path = path
        self.pretty_url = f"https://{host}{path}"
        self.method = "GET"
        self.headers: dict[str, str] = {}
        self.content = b""
        self.scheme = "https"
        self.host = host
        self.port = 443


class _FakeFlow:
    def __init__(self, host: str, path: str) -> None:
        self.request = _FakeRequest(host, path)
        self.response = None


class _FakeResponseFlow:
    def __init__(self, host: str, path: str, content: bytes) -> None:
        self.request = _FakeRequest(host, path)
        self.response = types.SimpleNamespace(
            headers={"content-type": "application/json"},
            content=content,
            status_code=200,
            reason="OK",
        )


def test_sync_protocol_user_data_verifies_tls_by_default(monkeypatch) -> None:
    mitm_redirect = _load_mitm_redirect(monkeypatch)
    captured: dict[str, object] = {}

    def fake_urlopen(request, timeout, context):
        captured["request"] = request
        captured["timeout"] = timeout
        captured["context"] = context
        return _FakeResponse()

    monkeypatch.setattr(mitm_redirect, "urlopen", fake_urlopen)
    mitm_redirect.LOCAL_SYNC_SECRET = "abcdefghijklmnopqrstuvwxyz123456"
    mitm_redirect.LOCAL_API = "api-roborock.example.com"

    mitm_redirect._sync_protocol_user_data(_sample_user_data())

    context = captured["context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_preflight_sync_endpoint_accepts_expected_missing_user_data(monkeypatch) -> None:
    mitm_redirect = _load_mitm_redirect(monkeypatch)

    def fake_urlopen(request, timeout, context):
        raise HTTPError(
            request.full_url,
            400,
            "Bad Request",
            hdrs=None,
            fp=io.BytesIO(
                b'{"code":40041,"msg":"protocol_sync_failed","data":{"reason":"missing_user_data"}}'
            ),
        )

    monkeypatch.setattr(mitm_redirect, "urlopen", fake_urlopen)

    mitm_redirect._preflight_sync_endpoint("https://api-roborock.example.com", "abcdefghijklmnopqrstuvwxyz123456")


def test_preflight_sync_endpoint_rejects_invalid_secret(monkeypatch) -> None:
    mitm_redirect = _load_mitm_redirect(monkeypatch)

    def fake_urlopen(request, timeout, context):
        raise HTTPError(
            request.full_url,
            401,
            "Unauthorized",
            hdrs=None,
            fp=io.BytesIO(
                b'{"code":40041,"msg":"protocol_sync_failed","data":{"reason":"invalid_sync_secret"}}'
            ),
        )

    monkeypatch.setattr(mitm_redirect, "urlopen", fake_urlopen)

    with pytest.raises(mitm_redirect.SyncEndpointError, match="preflight failed: HTTP 401 - protocol_sync_failed - invalid_sync_secret"):
        mitm_redirect._preflight_sync_endpoint("https://api-roborock.example.com", "bad-secret")


def test_login_response_is_blocked_when_sync_fails(monkeypatch) -> None:
    mitm_redirect = _load_mitm_redirect(monkeypatch)
    monkeypatch.setattr(mitm_redirect, "_log_flow", lambda *args, **kwargs: None)

    def fake_sync(_user_data):
        raise mitm_redirect.SyncEndpointError(
            "https://127.0.0.1:555/internal/protocol/user-data",
            "request failed: certificate verify failed",
        )

    monkeypatch.setattr(mitm_redirect, "_sync_protocol_user_data", fake_sync)
    flow = _FakeResponseFlow(
        "usiot.roborock.com",
        "/api/v5/auth/email/login/code",
        json.dumps({"data": _sample_user_data()}).encode("utf-8"),
    )

    mitm_redirect.response(flow)

    assert flow.response.status_code == 502
    body = json.loads(flow.response.content)
    assert body["msg"] == "local_sync_failed"
    assert body["data"]["reason"] == "sync_unreachable"
    assert "127.0.0.1:555" in body["data"]["syncUrl"]


def test_rewrite_value_supports_custom_ports(monkeypatch) -> None:
    mitm_redirect = _load_mitm_redirect(monkeypatch)
    mitm_redirect.LOCAL_API_HOST = "api-roborock.example.com"
    mitm_redirect.LOCAL_API_PORT = 8443
    mitm_redirect.LOCAL_MQTT_HOST = "mqtt-roborock.example.com"
    mitm_redirect.LOCAL_MQTT_PORT = 9443
    mitm_redirect.LOCAL_WOOD_HOST = "wood-roborock.example.com"
    mitm_redirect.LOCAL_WOOD_PORT = 8443

    rewritten = mitm_redirect._rewrite_value(
        "https://api-us.roborock.com ssl://mqtt-us.roborock.com:8883 https://wood-us.roborock.com"
    )

    assert "https://api-roborock.example.com:8443" in rewritten
    assert "ssl://mqtt-roborock.example.com:9443" in rewritten
    assert "https://wood-roborock.example.com:8443" in rewritten


def test_rewrite_value_preserves_default_mqtt_port_when_only_host_changes(monkeypatch) -> None:
    mitm_redirect = _load_mitm_redirect(monkeypatch)
    mitm_redirect.LOCAL_MQTT_HOST = "api-roborock.example.com"
    mitm_redirect.LOCAL_MQTT_PORT = None

    rewritten = mitm_redirect._rewrite_value("ssl://mqtt-us.roborock.com:8883")

    assert rewritten == "ssl://api-roborock.example.com:8883"


def test_request_routes_to_custom_api_port(monkeypatch) -> None:
    mitm_redirect = _load_mitm_redirect(monkeypatch)
    mitm_redirect.LOCAL_API = "api-roborock.example.com:8443"
    mitm_redirect.LOCAL_API_HOST = "api-roborock.example.com"
    mitm_redirect.LOCAL_API_PORT = 8443
    flow = _FakeFlow("api-us.roborock.com", "/api/v1/getHomeDetail")

    mitm_redirect.request(flow)

    assert flow.request.host == "api-roborock.example.com"
    assert flow.request.port == 8443
    assert flow.request.headers["Host"] == "api-roborock.example.com:8443"
