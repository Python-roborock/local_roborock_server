import re
import tomllib
from pathlib import Path

from roborock_local_server import __version__


def test_package_version_matches_pyproject() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == __version__


def test_init_module_exports_single_version_literal() -> None:
    init_text = Path("src/roborock_local_server/__init__.py").read_text(encoding="utf-8")
    matches = re.findall(r'__version__\s*=\s*"([^"]+)"', init_text)
    assert matches == [__version__]
