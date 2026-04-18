import importlib
import ssl
import sys
import types


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
    fake_log = types.SimpleNamespace(info=lambda *args, **kwargs: None, warn=lambda *args, **kwargs: None)
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
    mitm_redirect.LOCAL_SYNC_BASE_URL = "https://api-roborock.example.com"

    mitm_redirect._sync_protocol_user_data(_sample_user_data())

    context = captured["context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
