"""Container entrypoint that supports compose and Home Assistant apps."""

from __future__ import annotations

import os
from pathlib import Path

from .ha_addon import write_config_from_home_assistant_options


def _exec_server(config_path: Path) -> None:
    os.execvp(
        "roborock-local-server",
        ["roborock-local-server", "serve", "--config", str(config_path)],
    )


def _run_entrypoint(*, compose_config: Path, data_config: Path, addon_options: Path) -> None:
    if compose_config.exists():
        _exec_server(compose_config)
        return

    if addon_options.exists():
        write_config_from_home_assistant_options(
            options_path=addon_options,
            config_path=data_config,
        )
        _exec_server(data_config)
        return

    if data_config.exists():
        _exec_server(data_config)
        return

    raise SystemExit(
        "No config file found. Expected /app/config.toml, /data/config.toml, or /data/options.json."
    )


def main() -> int:
    _run_entrypoint(
        compose_config=Path("/app/config.toml"),
        data_config=Path("/data/config.toml"),
        addon_options=Path("/data/options.json"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
