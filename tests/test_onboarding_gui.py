from __future__ import annotations

import pytest

from start_onboarding_gui import (
    _IANA_TO_COUNTRY,
    _build_config_from_payload,
    _log,
    _poll_until_progress,
    country_from_iana,
    normalize_api_base_url,
    posix_tz_from_iana,
    sanitize_stack_server,
)




@pytest.mark.parametrize(
    ("server", "expected_api_base", "expected_stack_server"),
    [
        (
            "api-roborock.example.com",
            "https://api-roborock.example.com:555",
            "roborock.example.com:555/",
        ),
        (
            "api-roborock.example.com:8443",
            "https://api-roborock.example.com:8443",
            "roborock.example.com:8443/",
        ),
        (
            "https://roborock.example.com:8443/",
            "https://api-roborock.example.com:8443",
            "roborock.example.com:8443/",
        ),
    ],
)
def test_gui_server_normalization_supports_default_and_custom_ports(
    server: str,
    expected_api_base: str,
    expected_stack_server: str,
) -> None:
    assert normalize_api_base_url(server) == expected_api_base
    assert sanitize_stack_server(server) == expected_stack_server


def test_gui_server_normalization_rejects_non_numeric_port() -> None:
    with pytest.raises(ValueError, match="Server port must be numeric."):
        normalize_api_base_url("api-roborock.example.com:not-a-port")


def test_gui_server_normalization_enforces_32_char_limit() -> None:
    assert sanitize_stack_server("abcdefghijklmno.example.com:555") == "abcdefghijklmno.example.com:555/"
    with pytest.raises(ValueError, match="token.r must be at most 32 characters, got 33"):
        sanitize_stack_server("abcdefghijklmnop.example.com:555")


def test_gui_poll_final_cycle_waits_for_connection_when_public_key_already_ready(monkeypatch: pytest.MonkeyPatch) -> None:
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
                }
            return {
                "session_id": session_id,
                "query_samples": 2,
                "has_public_key": True,
                "public_key_state": "ready",
                "connected": True,
            }

    waits: list[float] = []
    monkeypatch.setattr("start_onboarding_gui.POLL_TIMEOUT_SECONDS", 20.0)
    monkeypatch.setattr("start_onboarding_gui.POLL_INTERVAL_SECONDS", 5.0)

    class _ImmediateCond:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def wait(self, timeout=None):
            waits.append(timeout)
            return None

    monkeypatch.setattr("start_onboarding_gui._state_cond", _ImmediateCond())

    outcome, latest = _poll_until_progress(
        FinalCycleApi(),
        "sess-1",
        2,
        baseline_has_public_key=True,
    )

    assert outcome == "connected"
    assert latest["connected"] is True
    assert waits == [5.0]


def test_gui_poll_returns_unsupported_without_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
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
            }

    waits: list[float] = []
    monkeypatch.setattr("start_onboarding_gui.POLL_TIMEOUT_SECONDS", 20.0)
    monkeypatch.setattr("start_onboarding_gui.POLL_INTERVAL_SECONDS", 5.0)

    class _ImmediateCond:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def wait(self, timeout=None):
            waits.append(timeout)
            return None

    monkeypatch.setattr("start_onboarding_gui._state_cond", _ImmediateCond())

    outcome, latest = _poll_until_progress(
        UnsupportedApi(),
        "sess-1",
        0,
        baseline_has_public_key=False,
    )

    assert outcome == "unsupported"
    assert latest["unsupported"] is True
    assert waits == []


def test_gui_poll_shows_key_calculation_until_public_key_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    statuses = [
        {"query_samples": 3, "has_public_key": False, "public_key_state": "recovering", "connected": False},
        {"query_samples": 3, "has_public_key": True, "public_key_state": "ready", "connected": False},
    ]

    class RecoveringApi:
        def get_session(self, *, session_id: str) -> dict:
            assert session_id == "sess-1"
            return {"session_id": session_id, **statuses.pop(0)}

    waits: list[float] = []
    phases: list[tuple[str, dict]] = []
    monkeypatch.setattr("start_onboarding_gui.POLL_TIMEOUT_SECONDS", 20.0)
    monkeypatch.setattr("start_onboarding_gui.POLL_INTERVAL_SECONDS", 5.0)
    monkeypatch.setattr("start_onboarding_gui._set_phase", lambda phase, **fields: phases.append((phase, fields)))

    class _ImmediateCond:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def wait(self, timeout=None):
            waits.append(timeout)
            return None

    monkeypatch.setattr("start_onboarding_gui._state_cond", _ImmediateCond())

    outcome, latest = _poll_until_progress(RecoveringApi(), "sess-1", 2, baseline_has_public_key=False)

    assert outcome == "public_key_ready"
    assert latest["has_public_key"] is True
    assert waits == [5.0]
    assert [phase for phase, _fields in phases] == ["recovering_key"]
    assert phases[0][1]["key_recovery_seconds"] == 0


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
def test_gui_country_from_iana_european_timezones_map_to_eu(tz: str) -> None:
    assert _IANA_TO_COUNTRY[tz] == "eu"
    assert country_from_iana(tz) == "eu"
    assert country_from_iana(f"  {tz}  ") == "eu"


def test_gui_country_from_iana_russian_timezones_map_to_ru() -> None:
    assert _IANA_TO_COUNTRY["Europe/Moscow"] == "ru"
    assert country_from_iana("Europe/Moscow") == "ru"
    assert country_from_iana("Europe/Kaliningrad") == "ru"


def test_gui_country_from_iana_unknown_or_fallback() -> None:
    assert country_from_iana("Europe/Dublin") == "eu"
    assert country_from_iana("Unknown/Region") == ""
    assert country_from_iana("") == ""


def test_gui_posix_tz_from_iana_supports_extended_timezones() -> None:
    assert posix_tz_from_iana("Europe/Vienna") == "CET-1CEST,M3.5.0,M10.5.0/3"
    assert posix_tz_from_iana("Europe/Moscow") == "MSK-3"


def test_build_config_from_payload_camera_domain_formats_and_validates() -> None:
    payload = {
        "server": "api-roborock.example.com",
        "admin_password": "pw",
        "ssid": "my-wifi",
        "wifi_password": "pw",
        "camera_domain": "myvac.cc",
    }
    cfg = _build_config_from_payload(payload)
    assert cfg.country_domain == "myvac.cc/"

    payload_too_long = {
        "server": "api-roborock.example.com",
        "admin_password": "pw",
        "ssid": "my-wifi",
        "wifi_password": "pw",
        "camera_domain": "way-too-long-domain.example.com",
    }
    with pytest.raises(ValueError, match="exceeds the 14-character limit"):
        _build_config_from_payload(payload_too_long)

    for invalid_val, expected_err in [
        ("https://myvac.cc", "Camera domain must be a hostname without a scheme"),
        ("myvac.cc:3478", "Camera domain must be a hostname without a port"),
        ("myvac.cc/path", "Camera domain must be a hostname without a path"),
        ("my vac.cc", "must be a valid hostname"),
    ]:
        payload_invalid = {
            "server": "api-roborock.example.com",
            "admin_password": "pw",
            "ssid": "my-wifi",
            "wifi_password": "pw",
            "camera_domain": invalid_val,
        }
        with pytest.raises(ValueError, match=expected_err):
            _build_config_from_payload(payload_invalid)



def test_build_config_from_payload_long_country_domain_warns_and_succeeds() -> None:
    payload = {
        "server": "api-roborock.example.com",
        "admin_password": "pw",
        "ssid": "my-wifi",
        "wifi_password": "pw",
        "country_domain": "custom-region-longer-than-limit",
    }
    cfg = _build_config_from_payload(payload)
    assert cfg.country_domain == "custom-region-longer-than-limit"
    assert any("is longer than 14 characters" in entry["msg"] for entry in _log.snapshot())



