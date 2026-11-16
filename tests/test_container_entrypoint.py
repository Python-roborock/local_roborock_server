from __future__ import annotations

from pathlib import Path

import pytest

from roborock_local_server import container_entrypoint


def test_run_entrypoint_prefers_home_assistant_options_over_stale_data_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compose_config = tmp_path / "app-config.toml"
    data_config = tmp_path / "data-config.toml"
    addon_options = tmp_path / "options.json"
    data_config.write_text("stale = true\n", encoding="utf-8")
    addon_options.write_text("{}", encoding="utf-8")

    calls: list[tuple[str, Path]] = []

    monkeypatch.setattr(
        container_entrypoint,
        "write_config_from_home_assistant_options",
        lambda *, options_path, config_path: calls.append(("write", config_path)),
    )
    monkeypatch.setattr(
        container_entrypoint,
        "_exec_server",
        lambda config_path: calls.append(("exec", config_path)),
    )

    container_entrypoint._run_entrypoint(
        compose_config=compose_config,
        data_config=data_config,
        addon_options=addon_options,
    )

    assert calls == [("write", data_config), ("exec", data_config)]


def test_run_entrypoint_prefers_compose_config_when_present(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compose_config = tmp_path / "app-config.toml"
    data_config = tmp_path / "data-config.toml"
    addon_options = tmp_path / "options.json"
    compose_config.write_text("compose = true\n", encoding="utf-8")
    data_config.write_text("stale = true\n", encoding="utf-8")
    addon_options.write_text("{}", encoding="utf-8")

    calls: list[Path] = []

    monkeypatch.setattr(
        container_entrypoint,
        "_exec_server",
        lambda config_path: calls.append(config_path),
    )

    container_entrypoint._run_entrypoint(
        compose_config=compose_config,
        data_config=data_config,
        addon_options=addon_options,
    )

    assert calls == [compose_config]


def test_run_entrypoint_prefers_existing_data_config_over_env_vars(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compose_config = tmp_path / "app-config.toml"
    data_config = tmp_path / "data-config.toml"
    addon_options = tmp_path / "options.json"
    data_config.write_text("existing = true\n", encoding="utf-8")

    monkeypatch.setenv("ROBOROCK_SERVER_STACK_FQDN", "api-roborock.example.com")
    calls: list[Path] = []
    monkeypatch.setattr(
        container_entrypoint,
        "_exec_server",
        lambda config_path: calls.append(config_path),
    )
    monkeypatch.setattr(
        container_entrypoint,
        "write_config_from_env",
        lambda *args, **kwargs: pytest.fail("should not regenerate an existing config.toml"),
    )

    container_entrypoint._run_entrypoint(
        compose_config=compose_config,
        data_config=data_config,
        addon_options=addon_options,
    )

    assert calls == [data_config]


def test_run_entrypoint_generates_config_from_env_vars(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compose_config = tmp_path / "app-config.toml"
    data_config = tmp_path / "data-config.toml"
    addon_options = tmp_path / "options.json"

    monkeypatch.setenv("ROBOROCK_SERVER_STACK_FQDN", "api-roborock.example.com")
    calls: list[tuple[str, Path]] = []
    monkeypatch.setattr(
        container_entrypoint,
        "write_config_from_env",
        lambda env, *, config_path: calls.append(("write", config_path)),
    )
    monkeypatch.setattr(
        container_entrypoint,
        "_exec_server",
        lambda config_path: calls.append(("exec", config_path)),
    )

    container_entrypoint._run_entrypoint(
        compose_config=compose_config,
        data_config=data_config,
        addon_options=addon_options,
    )

    assert calls == [("write", data_config), ("exec", data_config)]


def test_run_entrypoint_falls_back_to_wizard_when_env_config_is_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # STACK_FQDN alone triggers has_env_config(), but the rest of the
    # required vars for the default tls_mode may not be set. That must fall
    # through into the Setup Wizard, not crash the container.
    compose_config = tmp_path / "app-config.toml"
    data_config = tmp_path / "data-config.toml"
    addon_options = tmp_path / "options.json"
    monkeypatch.setenv("ROBOROCK_SERVER_STACK_FQDN", "api-roborock.example.com")

    def fake_write_config_from_env(env, *, config_path):
        raise ValueError("ROBOROCK_SERVER_TLS_BASE_DOMAIN is required")

    monkeypatch.setattr(container_entrypoint, "write_config_from_env", fake_write_config_from_env)
    calls: list[Path] = []
    monkeypatch.setattr(
        container_entrypoint,
        "_exec_server",
        lambda config_path: calls.append(config_path),
    )

    container_entrypoint._run_entrypoint(
        compose_config=compose_config,
        data_config=data_config,
        addon_options=addon_options,
    )

    assert calls == [data_config]
    assert data_config.exists() is False


def test_run_entrypoint_execs_server_even_without_any_config_present(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No config source at all, and no ROBOROCK_SERVER_* env vars either: the
    # entrypoint no longer errors out here, since `serve` now falls into the
    # Setup Wizard for exactly this case.
    compose_config = tmp_path / "app-config.toml"
    data_config = tmp_path / "data-config.toml"
    addon_options = tmp_path / "options.json"
    monkeypatch.delenv("ROBOROCK_SERVER_STACK_FQDN", raising=False)

    calls: list[Path] = []
    monkeypatch.setattr(
        container_entrypoint,
        "_exec_server",
        lambda config_path: calls.append(config_path),
    )

    container_entrypoint._run_entrypoint(
        compose_config=compose_config,
        data_config=data_config,
        addon_options=addon_options,
    )

    assert calls == [data_config]


def test_an_existing_data_config_follows_the_environment_and_nothing_else(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_config = tmp_path / "data-config.toml"
    data_config.write_text('[network]\nstack_fqdn = "api-rr.example.com"\nhttps_port = 555\n\n[turn]\nmode = "provided"\n', encoding="utf-8")
    monkeypatch.setenv("ROBOROCK_SERVER_HTTPS_PORT", "443")
    calls: list[Path] = []
    monkeypatch.setattr(container_entrypoint, "_exec_server", lambda config_path: calls.append(config_path))

    container_entrypoint._run_entrypoint(
        compose_config=tmp_path / "missing.toml", data_config=data_config, addon_options=tmp_path / "missing.json",
    )

    text = data_config.read_text(encoding="utf-8")
    assert "https_port = 443" in text and 'stack_fqdn = "api-rr.example.com"' in text and '[turn]\nmode = "provided"' in text
    assert calls == [data_config]
    assert "network.https_port: 555 -> 443" in capsys.readouterr().err


def test_a_mounted_config_is_never_written_but_the_ignored_variable_is_reported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    compose_config = tmp_path / "app-config.toml"
    compose_config.write_text("[network]\nhttps_port = 555\n", encoding="utf-8")
    monkeypatch.setenv("ROBOROCK_SERVER_HTTPS_PORT", "443")
    monkeypatch.setattr(container_entrypoint, "_exec_server", lambda config_path: None)

    container_entrypoint._run_entrypoint(
        compose_config=compose_config, data_config=tmp_path / "data.toml", addon_options=tmp_path / "missing.json",
    )

    assert compose_config.read_text(encoding="utf-8") == "[network]\nhttps_port = 555\n"
    assert "mounted, not changed" in capsys.readouterr().err
