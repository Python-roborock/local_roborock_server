from __future__ import annotations

from pathlib import Path

from roborock_local_server import __version__

from scripts.export_home_assistant_dev_addon import export_repository


def test_export_repository_writes_local_dev_addon(tmp_path: Path) -> None:
    output_dir = export_repository(tmp_path / "ha-addon")

    repository_yaml = output_dir / "repository.yaml"
    addon_dir = output_dir / "roborock_local_server_dev"
    config_yaml = addon_dir / "config.yaml"
    dockerfile = addon_dir / "Dockerfile"
    exported_init = addon_dir / "app" / "src" / "roborock_local_server" / "__init__.py"

    assert repository_yaml.exists()
    assert config_yaml.exists()
    assert dockerfile.exists()
    assert exported_init.exists()

    config_text = config_yaml.read_text(encoding="utf-8")
    assert f'version: "{__version__}"' in config_text
    assert "slug: roborock_local_server_dev" in config_text
    assert 'image: "ghcr.io/python-roborock/local_roborock_server"' not in config_text

    init_text = exported_init.read_text(encoding="utf-8")
    assert f'__version__ = "{__version__}"' in init_text
