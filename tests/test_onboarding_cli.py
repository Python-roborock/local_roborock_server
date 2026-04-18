from __future__ import annotations

from io import StringIO

import pytest

from start_onboarding import (
    ApiReachabilityError,
    GuidedOnboardingConfig,
    RemoteOnboardingApi,
    normalize_api_base_url,
    poll_session_until_progress,
    run_guided_onboarding,
    sanitize_stack_server,
)


class FakeApi:
    def __init__(self, *, devices: list[dict], baseline_statuses: list[dict]) -> None:
        self.devices = list(devices)
        self.baseline_statuses = list(baseline_statuses)
        self.login_called = 0
        self.started_duids: list[str] = []
        self.deleted_sessions: list[str] = []
        self.session_id = "sess-1"

    def login(self) -> None:
        self.login_called += 1

    def list_devices(self) -> list[dict]:
        return list(self.devices)

    def start_session(self, *, duid: str) -> dict:
        self.started_duids.append(duid)
        return {
            "session_id": self.session_id,
            "target": {
                "duid": duid,
                "name": next((item["name"] for item in self.devices if item["duid"] == duid), duid),
                "did": "",
                "connected": False,
                "last_ip": "",
            },
        }

    def get_session(self, *, session_id: str) -> dict:
        assert session_id == self.session_id
        if self.baseline_statuses:
            status = self.baseline_statuses.pop(0)
            self._last_status = dict(status)
            return dict(status)
        return dict(getattr(self, "_last_status", {"session_id": session_id}))

    def delete_session(self, *, session_id: str) -> dict:
        self.deleted_sessions.append(session_id)
        return {"ok": True}


class _RecordingResponse:
    def __enter__(self) -> "_RecordingResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def read(self) -> bytes:
        return b"{}"


class _RecordingOpener:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def open(self, request, timeout=None, context=None):
        _ = timeout, context
        self.urls.append(request.full_url)
        return _RecordingResponse()


@pytest.fixture
def config() -> GuidedOnboardingConfig:
    return GuidedOnboardingConfig(
        api_base_url="https://api-roborock.example.com",
        stack_server="roborock.example.com/",
        admin_password="secret",
        ssid="Home Wifi",
        password="Password123",
        timezone="America/New_York",
        cst="EST5EDT,M3.2.0,M11.1.0",
        country_domain="us",
    )


def test_guided_onboarding_happy_path(monkeypatch: pytest.MonkeyPatch, config: GuidedOnboardingConfig) -> None:
    api = FakeApi(
        devices=[
            {
                "duid": "cloud-q7-a",
                "name": "Q7 Upstairs",
                "connected": False,
                "onboarding": {"has_public_key": False, "key_state": {"query_samples": 0}},
            }
        ],
        baseline_statuses=[
            {"session_id": "sess-1", "query_samples": 0, "has_public_key": False, "connected": False},
        ],
    )
    output = StringIO()
    sent: list[str] = []
    poll_results = iter(
        [
            (
                "connected",
                {
                    "session_id": "sess-1",
                    "query_samples": 2,
                    "has_public_key": True,
                    "public_key_state": "ready",
                    "connected": True,
                    "guidance": "Device paired and connected.",
                    "target": {"name": "Q7 Upstairs", "duid": "cloud-q7-a", "did": "1103821560705"},
                },
            )
        ]
    )
    answers = iter(["1", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(
        "start_onboarding.poll_session_until_progress",
        lambda *args, **kwargs: next(poll_results),
    )

    result = run_guided_onboarding(
        config=config,
        api=api,
        send_onboarding=lambda cfg, out: sent.append(cfg.ssid) is None or True,
        output=output,
        sleep_fn=lambda _seconds: None,
    )

    assert result == 0
    assert api.started_duids == ["cloud-q7-a"]
    assert api.deleted_sessions == ["sess-1"]
    assert sent == ["Home Wifi"]
    assert "The vacuum is connected to the local server." in output.getvalue()


def test_guided_onboarding_handles_extra_cycles(monkeypatch: pytest.MonkeyPatch, config: GuidedOnboardingConfig) -> None:
    api = FakeApi(
        devices=[
            {
                "duid": "cloud-q7-a",
                "name": "Q7 Upstairs",
                "connected": False,
                "onboarding": {"has_public_key": False, "key_state": {"query_samples": 0}},
            }
        ],
        baseline_statuses=[
            {"session_id": "sess-1", "query_samples": 0, "has_public_key": False, "connected": False},
            {"session_id": "sess-1", "query_samples": 1, "has_public_key": False, "connected": False},
            {"session_id": "sess-1", "query_samples": 2, "has_public_key": True, "connected": False},
        ],
    )
    output = StringIO()
    send_count = {"value": 0}
    poll_results = iter(
        [
            (
                "sample_increased",
                {
                    "session_id": "sess-1",
                    "query_samples": 1,
                    "has_public_key": False,
                    "public_key_state": "collecting",
                    "connected": False,
                    "guidance": "Need more samples.",
                    "target": {"name": "Q7 Upstairs", "duid": "cloud-q7-a", "did": "1103821560705"},
                },
            ),
            (
                "public_key_ready",
                {
                    "session_id": "sess-1",
                    "query_samples": 2,
                    "has_public_key": True,
                    "public_key_state": "ready",
                    "connected": False,
                    "guidance": "Public key ready.",
                    "target": {"name": "Q7 Upstairs", "duid": "cloud-q7-a", "did": "1103821560705"},
                },
            ),
            (
                "connected",
                {
                    "session_id": "sess-1",
                    "query_samples": 2,
                    "has_public_key": True,
                    "public_key_state": "ready",
                    "connected": True,
                    "guidance": "Device paired and connected.",
                    "target": {"name": "Q7 Upstairs", "duid": "cloud-q7-a", "did": "1103821560705"},
                },
            ),
        ]
    )
    answers = iter(["1", "", "", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(
        "start_onboarding.poll_session_until_progress",
        lambda *args, **kwargs: next(poll_results),
    )

    result = run_guided_onboarding(
        config=config,
        api=api,
        send_onboarding=lambda cfg, out: not send_count.__setitem__("value", send_count["value"] + 1),
        output=output,
        sleep_fn=lambda _seconds: None,
    )

    assert result == 0
    assert send_count["value"] == 3
    output_text = output.getvalue()
    assert "The sample count increased." in output_text
    assert "The public key is ready." in output_text


def test_guided_onboarding_timeout_can_retry_without_restart(
    monkeypatch: pytest.MonkeyPatch,
    config: GuidedOnboardingConfig,
) -> None:
    api = FakeApi(
        devices=[
            {
                "duid": "cloud-q7-a",
                "name": "Q7 Upstairs",
                "connected": False,
                "onboarding": {"has_public_key": False, "key_state": {"query_samples": 0}},
            }
        ],
        baseline_statuses=[
            {"session_id": "sess-1", "query_samples": 0, "has_public_key": False, "connected": False},
            {"session_id": "sess-1", "query_samples": 0, "has_public_key": False, "connected": False},
        ],
    )
    output = StringIO()
    send_count = {"value": 0}
    poll_results = iter(
        [
            (
                "timeout",
                {
                    "session_id": "sess-1",
                    "query_samples": 0,
                    "has_public_key": False,
                    "public_key_state": "missing",
                    "connected": False,
                    "guidance": "Still waiting.",
                    "target": {"name": "Q7 Upstairs", "duid": "cloud-q7-a", "did": ""},
                },
            ),
            (
                "connected",
                {
                    "session_id": "sess-1",
                    "query_samples": 2,
                    "has_public_key": True,
                    "public_key_state": "ready",
                    "connected": True,
                    "guidance": "Device paired and connected.",
                    "target": {"name": "Q7 Upstairs", "duid": "cloud-q7-a", "did": "1103821560705"},
                },
            ),
        ]
    )
    answers = iter(["1", "", "retry", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(
        "start_onboarding.poll_session_until_progress",
        lambda *args, **kwargs: next(poll_results),
    )

    result = run_guided_onboarding(
        config=config,
        api=api,
        send_onboarding=lambda cfg, out: not send_count.__setitem__("value", send_count["value"] + 1),
        output=output,
        sleep_fn=lambda _seconds: None,
    )

    assert result == 0
    assert send_count["value"] == 2
    assert "Choose: [retry] [refresh] [reselect] [quit]:" not in output.getvalue()


def test_guided_onboarding_duplicate_names_still_selects_requested_device(
    monkeypatch: pytest.MonkeyPatch,
    config: GuidedOnboardingConfig,
) -> None:
    api = FakeApi(
        devices=[
            {
                "duid": "cloud-q7-a",
                "name": "Qrevo MaxV",
                "connected": False,
                "onboarding": {"has_public_key": False, "key_state": {"query_samples": 0}},
            },
            {
                "duid": "cloud-q7-b",
                "name": "Qrevo MaxV",
                "connected": False,
                "onboarding": {"has_public_key": True, "key_state": {"query_samples": 2}},
            },
        ],
        baseline_statuses=[
            {"session_id": "sess-1", "query_samples": 2, "has_public_key": True, "connected": False},
        ],
    )
    output = StringIO()
    poll_results = iter(
        [
            (
                "connected",
                {
                    "session_id": "sess-1",
                    "query_samples": 2,
                    "has_public_key": True,
                    "public_key_state": "ready",
                    "connected": True,
                    "guidance": "Device paired and connected.",
                    "target": {"name": "Qrevo MaxV", "duid": "cloud-q7-b", "did": "1103821560706"},
                },
            )
        ]
    )
    answers = iter(["2", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(
        "start_onboarding.poll_session_until_progress",
        lambda *args, **kwargs: next(poll_results),
    )

    result = run_guided_onboarding(
        config=config,
        api=api,
        send_onboarding=lambda cfg, out: True,
        output=output,
        sleep_fn=lambda _seconds: None,
    )

    assert result == 0
    assert api.started_duids == ["cloud-q7-b"]
    assert "cloud-q7-a" in output.getvalue()
    assert "cloud-q7-b" in output.getvalue()


def test_poll_session_retries_while_machine_reconnects_to_normal_wifi() -> None:
    class FlakyApi:
        def __init__(self) -> None:
            self.calls = 0

        def get_session(self, *, session_id: str) -> dict:
            assert session_id == "sess-1"
            self.calls += 1
            if self.calls <= 2:
                raise ApiReachabilityError(
                    "Unable to reach https://api-roborock.example.com: [Errno -2] Name or service not known"
                )
            return {
                "session_id": session_id,
                "query_samples": 2,
                "has_public_key": True,
                "public_key_state": "ready",
                "connected": True,
                "guidance": "Device paired and connected.",
                "target": {"name": "Q7 Upstairs", "duid": "cloud-q7-a", "did": "1103821560705"},
            }

    api = FlakyApi()
    output = StringIO()
    sleeps: list[float] = []

    result, status = poll_session_until_progress(
        api,
        session_id="sess-1",
        baseline_samples=0,
        baseline_status={
            "session_id": "sess-1",
            "query_samples": 0,
            "has_public_key": False,
            "public_key_state": "missing",
            "connected": False,
            "target": {"name": "Q7 Upstairs", "duid": "cloud-q7-a", "did": ""},
        },
        output=output,
        poll_interval_seconds=5.0,
        timeout_seconds=20.0,
        sleep_fn=sleeps.append,
    )

    assert result == "connected"
    assert status["connected"] is True
    assert sleeps == [5.0, 5.0]
    assert "The main server is not reachable yet from this machine." in output.getvalue()
    assert "Still waiting for this machine to reach the main server again..." in output.getvalue()


def test_onboarding_server_normalization_preserves_custom_ports() -> None:
    assert normalize_api_base_url("api-roborock.example.com:8443") == "https://api-roborock.example.com:8443"
    assert sanitize_stack_server("https://api-roborock.example.com:8443") == "roborock.example.com:8443/"


def test_remote_onboarding_api_uses_custom_port_base_url() -> None:
    opener = _RecordingOpener()
    api = RemoteOnboardingApi(
        base_url="https://api-roborock.example.com:8443",
        admin_password="secret",
        opener=opener,
    )

    api.login()
    api.list_devices()

    assert opener.urls == [
        "https://api-roborock.example.com:8443/admin/api/login",
        "https://api-roborock.example.com:8443/admin/api/onboarding/devices",
    ]
