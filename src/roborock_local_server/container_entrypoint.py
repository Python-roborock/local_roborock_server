"""Container entrypoint that supports compose and Home Assistant apps."""

from __future__ import annotations

import os
from pathlib import Path
import sys

from .env_config import has_env_config, write_config_from_env
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

    if has_env_config(os.environ):
        try:
            write_config_from_env(os.environ, config_path=data_config)
        except ValueError as exc:
            print(
                f"ROBOROCK_SERVER_STACK_FQDN is set, but generating config.toml from "
                f"ROBOROCK_SERVER_* env vars failed: {exc}. Falling back to the Setup Wizard "
                "at /admin to finish configuration - set the remaining env vars instead if you "
                "want a fully headless boot.",
                file=sys.stderr,
            )
        else:
            _exec_server(data_config)
            return

    # No usable config anywhere yet. `serve` itself now handles this: it
    # serves the Setup Wizard at /admin until /data/config.toml exists, then
    # a container restart (Docker's restart policy) picks up the full stack
    # once the wizard writes it.
    _exec_server(data_config)


def main() -> int:
    _run_entrypoint(
        compose_config=Path("/app/config.toml"),
        data_config=Path("/data/config.toml"),
        addon_options=Path("/data/options.json"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
