from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from roborock_local_server import __version__


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = REPO_ROOT / "dist" / "home_assistant_dev_addon_repo"
DEFAULT_ADDON_SLUG = "roborock_local_server_dev"
DEFAULT_ADDON_NAME = "Roborock Local Server Dev"

REPOSITORY_YAML = """name: Roborock Local Server Dev Apps
url: "https://github.com/Python-roborock/local_roborock_server"
maintainer: Luke Lashley
"""

def _addon_config_yaml(*, addon_name: str, addon_slug: str) -> str:
    return f"""name: {addon_name}
version: "{__version__}"
slug: {addon_slug}
description: Local-build development app for testing unpublished Roborock Local Server changes in Home Assistant.
url: "https://github.com/Python-roborock/local_roborock_server"
startup: services
boot: auto
init: false
arch:
  - amd64
  - aarch64
ports:
  555/tcp: 555
  8881/tcp: 8881
ports_description:
  555/tcp: Roborock HTTPS API
  8881/tcp: Roborock MQTT TLS proxy
map:
  - ssl:ro
  - addon_config:rw
  - all_addon_configs:ro
webui: "https://[HOST]:[PORT:555]/admin"
options:
  stack_fqdn: "api-roborock.example.com"
  https_port: 555
  mqtt_tls_port: 8881
  region: "us"
  tls_mode: "provided"
  tls_base_domain: ""
  tls_email: ""
  cloudflare_token: ""
  cert_file: "/ssl/fullchain.pem"
  key_file: "/ssl/privkey.pem"
  admin_password: ""
  protocol_login_email: ""
  protocol_login_pin: ""
schema:
  stack_fqdn: str
  https_port: port
  mqtt_tls_port: port
  region: list(us|eu|cn|ru)
  tls_mode: list(provided|cloudflare_acme)
  tls_base_domain: str
  tls_email: str
  cloudflare_token: str
  cert_file: str
  key_file: str
  admin_password: password
  protocol_login_email: email
  protocol_login_pin: password
"""

def _addon_docs_md(*, addon_name: str) -> str:
    return f"""# {addon_name}

This local-build Home Assistant app is exported from your current working tree so you can test unpublished changes on a real Home Assistant instance.

It publishes two TLS ports directly: `555/tcp` for the Roborock HTTPS API and `8881/tcp` for the Roborock MQTT TLS proxy.

## Install

1. Run `uv run python scripts/export_home_assistant_dev_addon.py`.
2. Copy the generated repository folder to your Home Assistant host under `/addons/local_roborock_server_dev_repo/`.
3. In Home Assistant, open **Settings -> Add-ons -> App Store** and refresh.
4. Open the **Local add-ons** repository and install **{addon_name}**.
5. Set `stack_fqdn`, `admin_password`, `protocol_login_email`, `protocol_login_pin`, and your TLS settings.
6. Start the app and open `https://<your-ha-host>:555/admin`.

This app does not auto-edit Home Assistant's Roborock config entry. Update `config/.storage/core.config_entries` so Home Assistant points to your local stack URLs.
"""

ADDON_CHANGELOG_MD = f"""# Changelog

## {__version__}

- Exported from the current local working tree for Home Assistant dev testing.
"""

ADDON_DOCKERFILE = """FROM python:3.11-slim

RUN apt-get update \\
  && apt-get install -y --no-install-recommends \\
    ca-certificates \\
    curl \\
    mosquitto \\
    openssl \\
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/acme.sh \\
  && curl -fsSL https://github.com/acmesh-official/acme.sh/archive/refs/heads/master.tar.gz \\
  | tar -xz --strip-components=1 -C /opt/acme.sh \\
  && chmod +x /opt/acme.sh/acme.sh \\
  && ln -sf /opt/acme.sh/acme.sh /usr/local/bin/acme.sh

WORKDIR /app

COPY app/pyproject.toml app/README.md /app/
COPY app/src /app/src

RUN pip install --no-cache-dir /app

EXPOSE 555 8881

CMD ["python", "-m", "roborock_local_server.container_entrypoint"]
"""

ADDON_DOCKERIGNORE = """__pycache__/
*.pyc
*.pyo
*.pyd
"""


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def export_repository(output_dir: Path, *, addon_slug: str = DEFAULT_ADDON_SLUG, addon_name: str = DEFAULT_ADDON_NAME) -> Path:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    addon_dir = output_dir / addon_slug
    app_dir = addon_dir / "app"
    app_dir.mkdir(parents=True, exist_ok=True)

    _write_text(output_dir / "repository.yaml", REPOSITORY_YAML)
    _write_text(addon_dir / "config.yaml", _addon_config_yaml(addon_name=addon_name, addon_slug=addon_slug))
    _write_text(addon_dir / "DOCS.md", _addon_docs_md(addon_name=addon_name))
    _write_text(addon_dir / "CHANGELOG.md", ADDON_CHANGELOG_MD)
    _write_text(addon_dir / "Dockerfile", ADDON_DOCKERFILE)
    _write_text(addon_dir / ".dockerignore", ADDON_DOCKERIGNORE)

    shutil.copy2(REPO_ROOT / "pyproject.toml", app_dir / "pyproject.toml")
    shutil.copy2(REPO_ROOT / "README.md", app_dir / "README.md")
    shutil.copytree(REPO_ROOT / "src", app_dir / "src")

    return output_dir


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export a self-contained Home Assistant local add-on repo from the current working tree."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for the generated local add-on repository. Default: {DEFAULT_OUTPUT_DIR}",
    )
    parser.add_argument(
        "--addon-slug",
        default=DEFAULT_ADDON_SLUG,
        help=f"Addon slug/folder name to export. Default: {DEFAULT_ADDON_SLUG}",
    )
    parser.add_argument(
        "--addon-name",
        default=DEFAULT_ADDON_NAME,
        help=f"Addon display name to export. Default: {DEFAULT_ADDON_NAME}",
    )
    args = parser.parse_args()
    output_dir = args.output_dir.resolve()
    export_repository(output_dir, addon_slug=args.addon_slug, addon_name=args.addon_name)
    print(output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
