from __future__ import annotations

import pytest

from start_onboarding_gui import _poll_until_progress, normalize_api_base_url, sanitize_stack_server


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
