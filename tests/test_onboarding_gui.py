from __future__ import annotations

import pytest

from start_onboarding_gui import normalize_api_base_url, sanitize_stack_server


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
    assert sanitize_stack_server("roborockss.luke-lashley.com:555") == "roborockss.luke-lashley.com:555/"
    with pytest.raises(ValueError, match="token.r must be at most 32 characters, got 33"):
        sanitize_stack_server("roborocksss.luke-lashley.com:555")
