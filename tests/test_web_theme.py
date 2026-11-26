from __future__ import annotations

import re

from roborock_local_server.web_theme import HEAD_ASSETS, SCRIPT_ASSETS


def test_materialize_assets_carry_sri_hashes() -> None:
    script = re.search(r"<script[^>]*>", SCRIPT_ASSETS)
    stylesheet = re.search(r'<link[^>]*materialize\.min\.css[^>]*>', HEAD_ASSETS)

    for tag in (script, stylesheet):
        assert tag is not None
        assert re.search(r'integrity="sha384-[A-Za-z0-9+/]{64}"', tag.group(0))
        assert 'crossorigin="anonymous"' in tag.group(0)
