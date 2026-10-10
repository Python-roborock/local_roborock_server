from __future__ import annotations

from io import StringIO

import pytest

import onboarding_shared

_ACTUAL_CAMERA_RESPONSE_PROBE = onboarding_shared._probe_camera_response


@pytest.fixture(autouse=True)
def _avoid_camera_network_requests(monkeypatch):
    monkeypatch.setattr(onboarding_shared, "_probe_camera_response", lambda **kw: None)


def _camera_status(*, mode: str = "external", running: bool = True) -> dict:
    return {
        "turn": {"mode": mode},
        "health": {"services": [
            {"name": name, "running": True, "enabled": True}
            for name in ("https_server", "mqtt_tls_proxy", "mqtt_backend_broker")
        ] + [{"name": "turn_relay", "running": running, "enabled": mode == "provided"}]},
    }


def test_camera_preflight_checks_token_port_and_country_host_with_trusted_tls(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(onboarding_shared, "_probe_tls_endpoint", lambda **kw: calls.append(kw))
    onboarding_shared.perform_camera_preflight(
        api=_FakeApi(_camera_status()), output=StringIO(), stack_server="vac.cc:556/",
        country_domain="api-vac.cc/", model="",
    )
    assert [(c["host"], c["port"], c["allow_insecure_tls"]) for c in calls] == [
        ("vac.cc", 556, False), ("api-vac.cc", 443, False),
    ]


def test_missing_camera_alias_tls_is_actionable(monkeypatch) -> None:
    def probe(**kw):
        if kw["host"] == "vac.cc":
            raise RuntimeError("TLS certificate verification failed")
    monkeypatch.setattr(onboarding_shared, "_probe_tls_endpoint", probe)
    with pytest.raises(RuntimeError, match="Camera bootstrap preflight failed.*wildcard/SAN"):
        onboarding_shared.perform_camera_preflight(
            api=_FakeApi(_camera_status()), output=StringIO(), stack_server="vac.cc:556/",
            country_domain="api-vac.cc/", model="",
        )


def test_provided_relay_death_blocks_camera_pairing(monkeypatch) -> None:
    monkeypatch.setattr(onboarding_shared, "_probe_tls_endpoint", lambda **kw: None)
    with pytest.raises(RuntimeError, match="provided TURN relay is not running"):
        onboarding_shared.perform_camera_preflight(
            api=_FakeApi(_camera_status(mode="provided", running=False)),
            output=StringIO(), stack_server="vac.cc:556/", country_domain="api-vac.cc/", model="",
        )


def test_active_turn_does_not_force_camera_checks_for_ordinary_pairing(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(onboarding_shared, "_probe_tls_endpoint", lambda **kw: calls.append(kw))
    onboarding_shared.perform_onboarding_preflight(
        api=_FakeApi(_camera_status(mode="provided", running=False)),
        api_base_url="https://api-roborock.example.com:555", allow_insecure_tls=False,
        output=StringIO(),
    )
    assert len(calls) == 2


def test_initial_configuration_defers_camera_checks_until_device_selection(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(onboarding_shared, "_probe_tls_endpoint", lambda **kw: calls.append(kw))
    onboarding_shared.perform_onboarding_preflight(
        api=_FakeApi(_camera_status()), api_base_url="https://api-roborock.example.com:555",
        allow_insecure_tls=False, output=StringIO(),
    )
    assert len(calls) == 2


@pytest.mark.parametrize(("model", "token", "country", "endpoint"), [
    ("roborock.vacuum.a144", "roborock.example.com:555/", "api-vac.cc/", ("api-vac.cc", 443)),
    ("roborock.vacuum.a87", "vac.cc:556/", "api-vac.cc/", ("vac.cc", 556)),
])
def test_selected_model_only_requires_observed_camera_endpoint(monkeypatch, model, token, country, endpoint):
    calls = []
    monkeypatch.setattr(onboarding_shared, "_probe_tls_endpoint", lambda **kw: calls.append(kw))
    onboarding_shared.perform_camera_preflight(
        api=_FakeApi(_camera_status()), stack_server=token, country_domain=country,
        model=model, output=StringIO(),
    )
    assert [(c["host"], c["port"]) for c in calls] == [endpoint]
    assert calls[0]["allow_insecure_tls"] is False


@pytest.mark.parametrize("value", ["vac.cc:555", "too-long.example:555/", "123456789012345"])
def test_camera_token_requires_slash_and_15_character_limit(value) -> None:
    with pytest.raises(ValueError, match="Camera token.r.*15 characters"):
        onboarding_shared.camera_bootstrap_endpoints(stack_server=value, country_domain="api-vac.cc/")


def test_camera_requires_server_turn_support_before_pairing(monkeypatch):
    status = _camera_status()
    del status["turn"]
    with pytest.raises(RuntimeError, match="update it before camera onboarding"):
        onboarding_shared.perform_camera_preflight(api=_FakeApi(status), stack_server="vac.cc/",
            country_domain="api-vac.cc/", model="roborock.vacuum.a87", output=StringIO())


@pytest.mark.parametrize("payload", [
    {"code": 200, "data": {"url": "turn:relay.example:3478"}},
    {"code": 200, "result": {"urls": ["turn:relay.example:3478", "stun:relay.example:3478"]}},
])
def test_camera_response_probe_accepts_known_payload_aliases(monkeypatch, payload):
    from io import BytesIO
    import json
    monkeypatch.setattr(onboarding_shared.request, "urlopen", lambda *a, **kw: BytesIO(json.dumps(payload).encode()))
    _ACTUAL_CAMERA_RESPONSE_PROBE(label="https://vac.cc/fwapi/createca", expected_host="relay.example", expected_port=3478)


def test_camera_response_probe_rejects_wrong_service_without_logging_credentials(monkeypatch):
    from io import BytesIO
    monkeypatch.setattr(onboarding_shared.request, "urlopen", lambda *a, **kw: BytesIO(b'{"ok":true}'))
    with pytest.raises(RuntimeError, match="verify proxy routing"):
        _ACTUAL_CAMERA_RESPONSE_PROBE(label="https://vac.cc/fwapi/createca", expected_host="relay.example", expected_port=3478)


class _FakeApi:
    def __init__(self, status_payload: dict) -> None:
        self.status_payload = status_payload
        self.login_calls = 0
        self.status_calls = 0

    def login(self) -> None:
        self.login_calls += 1

    def get_status(self) -> dict:
        self.status_calls += 1
        return self.status_payload


def test_preflight_validates_api_services_and_mqtt_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, int, bool, str]] = []

    def fake_probe(*, host: str, port: int, allow_insecure_tls: bool, label: str) -> None:
        calls.append((host, port, allow_insecure_tls, label))

    monkeypatch.setattr(onboarding_shared, "_probe_tls_endpoint", fake_probe)
    api = _FakeApi(
        {
            "health": {
                "services": [
                    {"name": "https_server", "running": True, "enabled": True, "detail": "tls:0.0.0.0:555"},
                    {"name": "mqtt_tls_proxy", "running": True, "enabled": True, "detail": "tls:0.0.0.0:1881"},
                    {"name": "mqtt_backend_broker", "running": True, "enabled": True, "detail": "embedded:127.0.0.1:18830"},
                ]
            }
        }
    )
    output = StringIO()

    onboarding_shared.perform_onboarding_preflight(
        api=api,
        api_base_url="https://api-roborock.example.com:555",
        allow_insecure_tls=False,
        output=output,
    )

    assert api.login_calls == 1
    assert api.status_calls == 1
    assert calls == [
        ("api-roborock.example.com", 555, False, "https://api-roborock.example.com:555"),
        ("api-roborock.example.com", 1881, False, "ssl://api-roborock.example.com:1881"),
    ]
    text = output.getvalue()
    assert "Admin API login succeeded." in text
    assert "Required services are running" in text
    assert "TLS certificate is valid and listener is reachable" in text


def test_preflight_rejects_missing_or_stopped_required_service() -> None:
    api = _FakeApi(
        {
            "health": {
                "services": [
                    {"name": "https_server", "running": True, "enabled": True, "detail": "tls:0.0.0.0:555"},
                    {"name": "mqtt_tls_proxy", "running": False, "enabled": True, "detail": "tls:0.0.0.0:8881"},
                    {"name": "mqtt_backend_broker", "running": True, "enabled": True, "detail": "embedded:127.0.0.1:18830"},
                ]
            }
        }
    )

    with pytest.raises(RuntimeError, match="mqtt_tls_proxy is not running"):
        onboarding_shared.perform_onboarding_preflight(
            api=api,
            api_base_url="https://api-roborock.example.com:555",
            allow_insecure_tls=False,
            output=StringIO(),
        )


def test_preflight_reports_when_tls_verification_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(onboarding_shared, "_probe_tls_endpoint", lambda **kwargs: None)
    api = _FakeApi(
        {
            "health": {
                "services": [
                    {"name": "https_server", "running": True, "enabled": True, "detail": "tls:0.0.0.0:555"},
                    {"name": "mqtt_tls_proxy", "running": True, "enabled": True, "detail": "tls:0.0.0.0:8881"},
                    {"name": "mqtt_backend_broker", "running": True, "enabled": True, "detail": "embedded:127.0.0.1:18830"},
                ]
            }
        }
    )
    output = StringIO()

    onboarding_shared.perform_onboarding_preflight(
        api=api,
        api_base_url="https://api-roborock.example.com:555",
        allow_insecure_tls=True,
        output=output,
    )

    assert "certificate verification skipped" in output.getvalue()
