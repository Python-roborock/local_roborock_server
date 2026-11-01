"""Render the real dashboard and cache its external styles for isolated browser tests."""
from pathlib import Path
import re
from urllib.request import urlopen

from roborock_local_server.standalone_admin import _admin_dashboard_html, _admin_login_html
from roborock_local_server.web_theme import STYLE_CSS, MATERIALIZE_CSS_URL, MATERIALIZE_JS_URL, MATERIAL_ICONS_URL

output = Path(__file__).parent / "artifacts" / "fixtures"
output.mkdir(parents=True, exist_ok=True)
support = {
    "title": "Support This Project",
    "text": "Help keep local control open and accessible.",
    "links": [
        {"label": "Buy Me a Coffee", "url": "https://buymeacoffee.com/lashl"},
        {"label": "PayPal", "url": "https://paypal.me/LLashley304"},
        {"label": "Roborock Store", "url": "https://us.roborock.com/"},
    ],
}
(output / "dashboard.html").write_text(_admin_dashboard_html(support), encoding="utf-8")
(output / "login.html").write_text(_admin_login_html(), encoding="utf-8")
(output / "style.css").write_text(STYLE_CSS, encoding="utf-8")
with urlopen(MATERIALIZE_CSS_URL, timeout=30) as response:
    (output / "materialize.min.css").write_bytes(response.read())
with urlopen(MATERIALIZE_JS_URL, timeout=30) as response:
    (output / "materialize.min.js").write_bytes(response.read())
with urlopen(MATERIAL_ICONS_URL, timeout=30) as response:
    icon_css = response.read().decode("utf-8")
font_url = re.search(r"src:\s*url\((https://fonts\.gstatic\.com/[^)]+)\)", icon_css).group(1)
with urlopen(font_url, timeout=30) as response:
    (output / "material-icons.woff2").write_bytes(response.read())
print("Rendered shared dashboard/login and cached Materialize CSS/JavaScript and icon font.")
