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


def main() -> int:
    compose_config = Path("/app/config.toml")
    if compose_config.exists():
        _exec_server(compose_config)

    data_config = Path("/data/config.toml")
    if data_config.exists():
        _exec_server(data_config)

    addon_options = Path("/data/options.json")
    if addon_options.exists():
        write_config_from_home_assistant_options(
            options_path=addon_options,
            config_path=data_config,
        )
        _exec_server(data_config)

    raise SystemExit(
        "No config file found. Expected /app/config.toml, /data/config.toml, or /data/options.json."
    )


if __name__ == "__main__":
    raise SystemExit(main())
