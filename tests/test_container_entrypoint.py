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
