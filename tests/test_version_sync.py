import re
import tomllib
from pathlib import Path

from packaging.version import Version
import yaml

from roborock_local_server import __version__


def test_package_version_matches_pyproject() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == __version__


def test_init_module_exports_single_version_literal() -> None:
    init_text = Path("src/roborock_local_server/__init__.py").read_text(encoding="utf-8")
    matches = re.findall(r'__version__\s*=\s*"([^"]+)"', init_text)
    assert matches == [__version__]


def test_home_assistant_addon_version_matches_package_version() -> None:
    # Prereleases update only the opt-in Beta add-on. Stable keeps its last release.
    directory = (
        "roborock_local_server_beta_addon"
        if Version(__version__).is_prerelease
        else "roborock_local_server_addon"
    )
    addon = yaml.safe_load(Path(directory, "config.yaml").read_text(encoding="utf-8"))
    assert addon["version"] == __version__


def test_stable_addon_never_selects_a_prerelease_image() -> None:
    addon = yaml.safe_load(Path("roborock_local_server_addon/config.yaml").read_text(encoding="utf-8"))
    version = Version(addon["version"])
    assert not version.is_prerelease and not version.is_devrelease
    assert addon["slug"] == "roborock_local_server"
    assert addon["image"] == "ghcr.io/python-roborock/local_roborock_server"


def test_beta_addon_requires_a_separate_opt_in_installation() -> None:
    stable = yaml.safe_load(Path("roborock_local_server_addon/config.yaml").read_text(encoding="utf-8"))
    beta = yaml.safe_load(Path("roborock_local_server_beta_addon/config.yaml").read_text(encoding="utf-8"))
    assert beta["slug"] != stable["slug"]
    assert beta["name"] != stable["name"]
    assert beta["stage"] == "experimental"
    assert beta["boot"] == "manual"
    assert Version(beta["version"]).is_prerelease
