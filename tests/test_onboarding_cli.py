from __future__ import annotations

import argparse
from io import StringIO

import pytest

from start_onboarding import (
    _IANA_TO_COUNTRY,
    ApiReachabilityError,
    GuidedOnboardingConfig,
    RemoteOnboardingApi,
    choose_device,
    country_from_iana,
    normalize_api_base_url,
    poll_session_until_progress,
    posix_tz_from_iana,
    prompt_for_config,
    run_guided_onboarding,
    sanitize_stack_server,
)



class FakeApi:
    def __init__(self, *, devices: list[dict], baseline_statuses: list[dict]) -> None:
        self.devices = list(devices)
        self.baseline_statuses = list(baseline_statuses)
        self.login_called = 0
        self.started_duids: list[str] = []
        self.started_new_vacuum: list[bool] = []
        self.deleted_sessions: list[str] = []
        self.session_id = "sess-1"

    def login(self) -> None:
        self.login_called += 1

    def list_devices(self) -> list[dict]:
        return list(self.devices)

    def start_session(
        self,
        *,
        duid: str = "",
        new_vacuum: bool = False,
        name: str = "",
        model: str = "",
        **kwargs: object,
    ) -> dict:
        self.started_duids.append(duid)
        self.started_new_vacuum.append(new_vacuum)
        resolved_name = name or next((item["name"] for item in self.devices if item["duid"] == duid), duid)
        return {
            "session_id": self.session_id,
            "target": {
                "duid": duid,
                "name": resolved_name,
                "model": model,
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


def test_choose_device_empty_list_offers_new_vacuum(monkeypatch: pytest.MonkeyPatch) -> None:
    output = StringIO()
    answers = iter(["new"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    selected = choose_device([], output=output)

    assert selected is not None
    assert selected.get("new_vacuum") is True
    assert "New vacuum" in output.getvalue()


def test_choose_device_new_vacuum_by_number(monkeypatch: pytest.MonkeyPatch) -> None:
    output = StringIO()
    devices = [{"duid": "cloud-q7-a", "name": "Q7 Upstairs", "onboarding": {}}]
    # The "new vacuum" option is numbered one past the listed devices.
    answers = iter(["2"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))

    selected = choose_device(devices, output=output)

    assert selected is not None
    assert selected.get("new_vacuum") is True


def test_guided_onboarding_new_vacuum(
    monkeypatch: pytest.MonkeyPatch, config: GuidedOnboardingConfig
) -> None:
    api = FakeApi(
        devices=[],
        baseline_statuses=[
            {"session_id": "sess-1", "query_samples": 0, "has_public_key": False, "connected": False},
        ],
    )
    output = StringIO()
    poll_results = iter(
        [
            (
                "connected",
                {
                    "session_id": "sess-1",
                    "query_samples": 1,
                    "has_public_key": True,
                    "connected": True,
                    "guidance": "Device paired and connected.",
                    "target": {"name": "New vacuum", "duid": "1103835404427", "did": "1103835404427"},
                },
            )
        ]
    )
    # Select "new" vacuum, then press Enter to send the onboarding packet.
    answers = iter(["new", ""])
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
    assert api.started_new_vacuum == [True]
    assert api.started_duids == [""]
    assert api.deleted_sessions == ["sess-1"]


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


def test_poll_session_final_cycle_waits_for_connection_when_public_key_already_ready() -> None:
    class FinalCycleApi:
        def __init__(self) -> None:
            self.calls = 0

        def get_session(self, *, session_id: str) -> dict:
            assert session_id == "sess-1"
            self.calls += 1
            if self.calls == 1:
                return {
                    "session_id": session_id,
                    "query_samples": 2,
                    "has_public_key": True,
                    "public_key_state": "ready",
                    "connected": False,
                    "guidance": "Public key is ready.",
                    "target": {"name": "Q7 Upstairs", "duid": "cloud-q7-a", "did": "1103821560705"},
                }
            return {
                "session_id": session_id,
                "query_samples": 2,
                "has_public_key": True,
                "public_key_state": "ready",
                "connected": True,
                "guidance": "Device paired and connected.",
                "target": {"name": "Q7 Upstairs", "duid": "cloud-q7-a", "did": "1103821560705"},
            }

    output = StringIO()
    sleeps: list[float] = []

    result, status = poll_session_until_progress(
        FinalCycleApi(),
        session_id="sess-1",
        baseline_samples=2,
        baseline_status={
            "session_id": "sess-1",
            "query_samples": 2,
            "has_public_key": True,
            "public_key_state": "ready",
            "connected": False,
            "target": {"name": "Q7 Upstairs", "duid": "cloud-q7-a", "did": "1103821560705"},
        },
        output=output,
        poll_interval_seconds=5.0,
        timeout_seconds=20.0,
        sleep_fn=sleeps.append,
    )

    assert result == "connected"
    assert status["connected"] is True
    assert sleeps == [5.0]
    assert "Waiting for the server to observe new onboarding traffic..." in output.getvalue()


def test_poll_session_returns_unsupported_without_waiting() -> None:
    class UnsupportedApi:
        def get_session(self, *, session_id: str) -> dict:
            assert session_id == "sess-1"
            return {
                "session_id": session_id,
                "query_samples": 0,
                "has_public_key": False,
                "connected": False,
                "unsupported": True,
                "unsupported_reason": "region_v2",
                "guidance": "This vacuum uses the v2 /region onboarding flow.",
            }

    sleeps: list[float] = []
    result, status = poll_session_until_progress(
        UnsupportedApi(),
        session_id="sess-1",
        baseline_samples=0,
        baseline_status={"session_id": "sess-1", "query_samples": 0, "has_public_key": False},
        output=StringIO(),
        poll_interval_seconds=5.0,
        timeout_seconds=20.0,
        sleep_fn=sleeps.append,
    )

    assert result == "unsupported"
    assert status["unsupported"] is True
    assert sleeps == []


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


def test_onboarding_server_normalization_defaults_to_port_555() -> None:
    assert normalize_api_base_url("api-roborock.example.com") == "https://api-roborock.example.com:555"
    assert sanitize_stack_server("https://api-roborock.example.com") == "roborock.example.com:555/"


def test_onboarding_server_normalization_enforces_32_char_limit() -> None:
    assert sanitize_stack_server("abcdefghijklmno.example.com:555") == "abcdefghijklmno.example.com:555/"
    with pytest.raises(ValueError, match="token.r must be at most 32 characters, got 33"):
        sanitize_stack_server("abcdefghijklmnop.example.com:555")


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


class _SequenceApi:
    def __init__(self, statuses: list[dict]) -> None:
        self._statuses = list(statuses)

    def get_session(self, *, session_id: str) -> dict:
        assert session_id == "sess-1"
        return {"session_id": session_id, **self._statuses.pop(0)}


def test_poll_session_waits_while_public_key_is_calculating() -> None:
    api = _SequenceApi(
        [
            {"query_samples": 3, "has_public_key": False, "public_key_state": "recovering"},
            {"query_samples": 3, "has_public_key": False, "public_key_state": "recovering"},
            {"query_samples": 3, "has_public_key": True, "public_key_state": "ready"},
        ]
    )
    output = StringIO()
    sleeps: list[float] = []

    result, status = poll_session_until_progress(
        api,
        session_id="sess-1",
        baseline_samples=2,
        baseline_status={"session_id": "sess-1", "query_samples": 2, "has_public_key": False},
        output=output,
        poll_interval_seconds=5.0,
        timeout_seconds=20.0,
        sleep_fn=sleeps.append,
    )

    # The sample count rose, but the user is not told to send another cycle until the key is ready.
    assert result == "public_key_ready"
    assert status["has_public_key"] is True
    assert sleeps == [5.0, 5.0]
    assert output.getvalue().count("Calculating public key... please wait") == 2
    assert "Do not start the next pairing cycle yet." in output.getvalue()


def test_poll_session_asks_for_another_cycle_when_key_calculation_fails() -> None:
    api = _SequenceApi(
        [
            {"query_samples": 3, "has_public_key": False, "public_key_state": "recovering"},
            {"query_samples": 3, "has_public_key": False, "public_key_state": "collecting"},
        ]
    )
    sleeps: list[float] = []

    result, _status = poll_session_until_progress(
        api,
        session_id="sess-1",
        baseline_samples=2,
        baseline_status={"session_id": "sess-1", "query_samples": 2, "has_public_key": False},
        output=StringIO(),
        poll_interval_seconds=5.0,
        timeout_seconds=20.0,
        sleep_fn=sleeps.append,
    )

    assert result == "sample_increased"
    assert sleeps == [5.0]


@pytest.mark.parametrize(
    "tz",
    [
        "Europe/London",
        "Europe/Berlin",
        "Europe/Paris",
        "Europe/Amsterdam",
        "Europe/Vienna",
        "Europe/Rome",
        "Europe/Madrid",
        "Europe/Warsaw",
        "Europe/Stockholm",
        "Europe/Zurich",
        "Europe/Brussels",
    ],
)
def test_country_from_iana_european_timezones_map_to_eu(tz: str) -> None:
    assert _IANA_TO_COUNTRY[tz] == "eu"
    assert country_from_iana(tz) == "eu"
    assert country_from_iana(f"  {tz}  ") == "eu"


def test_country_from_iana_russian_timezones_map_to_ru() -> None:
    assert _IANA_TO_COUNTRY["Europe/Moscow"] == "ru"
    assert country_from_iana("Europe/Moscow") == "ru"
    assert country_from_iana("Europe/Kaliningrad") == "ru"


def test_country_from_iana_global_regions() -> None:
    assert country_from_iana("America/New_York") == "us"
    assert country_from_iana("Asia/Shanghai") == "cn"


def test_country_from_iana_unknown_and_fallback() -> None:
    # Unmapped European timezone falls back to 'eu'
    assert country_from_iana("Europe/Helsinki") == "eu"
    # Unknown timezone returns empty string
    assert country_from_iana("Unknown/Region") == ""
    assert country_from_iana("") == ""


def test_posix_tz_from_iana_supports_extended_european_timezones() -> None:
    assert posix_tz_from_iana("Europe/Vienna") == "CET-1CEST,M3.5.0,M10.5.0/3"
    assert posix_tz_from_iana("Europe/Rome") == "CET-1CEST,M3.5.0,M10.5.0/3"
    assert posix_tz_from_iana("Europe/Moscow") == "MSK-3"


def test_prompt_for_config_camera_domain_formats_and_validates() -> None:
    args = argparse.Namespace(
        server="api-roborock.example.com",
        admin_password="pw",
        ssid="my-wifi",
        password="pw",
        timezone="America/New_York",
        cst="EST5EDT",
        country_domain="",
        camera_domain="myvac.cc",
        allow_insecure_tls=False,
    )
    cfg = prompt_for_config(args)
    assert cfg.country_domain == "myvac.cc/"

    args_too_long = argparse.Namespace(
        server="api-roborock.example.com",
        admin_password="pw",
        ssid="my-wifi",
        password="pw",
        timezone="America/New_York",
        cst="EST5EDT",
        country_domain="",
        camera_domain="way-too-long-domain.example.com",
        allow_insecure_tls=False,
    )
    with pytest.raises(ValueError, match="exceeds the 14-character limit"):
        prompt_for_config(args_too_long)

    for invalid_val, expected_err in [
        ("https://myvac.cc", "Camera domain must be a hostname without a scheme"),
        ("myvac.cc:3478", "Camera domain must be a hostname without a port"),
        ("myvac.cc/path", "Camera domain must be a hostname without a path"),
        ("my vac.cc", "must be a valid hostname"),
    ]:
        args_invalid = argparse.Namespace(
            server="api-roborock.example.com",
            admin_password="pw",
            ssid="my-wifi",
            password="pw",
            timezone="America/New_York",
            cst="EST5EDT",
            country_domain="",
            camera_domain=invalid_val,
            allow_insecure_tls=False,
        )
        with pytest.raises(ValueError, match=expected_err):
            prompt_for_config(args_invalid)



def test_prompt_for_config_long_country_domain_warns_but_succeeds() -> None:
    output = StringIO()
    args = argparse.Namespace(
        server="api-roborock.example.com",
        admin_password="pw",
        ssid="my-wifi",
        password="pw",
        timezone="America/New_York",
        cst="EST5EDT",
        country_domain="custom-region-longer-than-limit",
        camera_domain="",
        allow_insecure_tls=False,
    )
    cfg = prompt_for_config(args, output=output)
    assert cfg.country_domain == "custom-region-longer-than-limit"
    text = output.getvalue()
    assert "Notice: Region 'custom-region-longer-than-limit' is longer than 14 characters" in text
    assert "local camera streaming (TURN) will not be available" in text
    assert "Standard vacuum control is unaffected" in text




