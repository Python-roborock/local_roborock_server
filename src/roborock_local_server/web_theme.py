"""Shared visual theme for /admin (the Setup Wizard and the real dashboard).

Same recipe as rethink's own management panel: Materialize CSS/JS and Google
Fonts loaded from CDN (no build step, no npm - this project has neither and
isn't taking one on for this), plus one small theme stylesheet on top for
branding, dark mode, and a couple of Materialize defaults that need
overriding. Both create_management_app() and register_standalone_admin_routes()
mount the same /admin/static/style.css route so there's one theme, not two.
"""

from __future__ import annotations

from textwrap import dedent

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

MATERIALIZE_CSS_URL = "https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css"
MATERIALIZE_JS_URL = "https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js"
GOOGLE_FONTS_URL = "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap"
MATERIAL_ICONS_URL = "https://fonts.googleapis.com/icon?family=Material+Icons"
STYLE_CSS_PATH = "/admin/static/style.css"

HEAD_ASSETS = dedent(
    f"""\
    <link rel="stylesheet" href="{GOOGLE_FONTS_URL}">
    <link rel="stylesheet" href="{MATERIAL_ICONS_URL}">
    <link rel="stylesheet" href="{MATERIALIZE_CSS_URL}">
    <link rel="stylesheet" href="{STYLE_CSS_PATH}">
    """
)

SCRIPT_ASSETS = f'<script src="{MATERIALIZE_JS_URL}"></script>'

NAV_HTML = dedent(
    """\
    <nav>
      <div class="nav-wrapper container">
        <a href="#" class="brand-logo"><i class="material-icons">smart_toy</i>Roborock Local Server</a>
      </div>
    </nav>
    """
)

STYLE_CSS = dedent(
    """\
    :root {
        --rls-bg: #f3f5f8;
        --rls-surface: #ffffff;
        --rls-nav: #12263a;
        --rls-accent: #2f6fed;
        --rls-accent-dark: #1c4fc4;
        --rls-text: #1a1f29;
        --rls-text-muted: #5a6572;
        --rls-border: #e2e6ea;
        --rls-danger-bg: #fdeced;
        --rls-danger-text: #8a1620;
        --rls-danger-border: #f5c2c7;
        --rls-success-bg: #e8f8ee;
        --rls-success-text: #0f5a33;
        --rls-success-border: #b7e4c7;
        --rls-warn-bg: #fff7ed;
        --rls-warn-text: #7c2d12;
        --rls-warn-border: #fdd8ab;
        color-scheme: light;
    }

    @media (prefers-color-scheme: dark) {
        :root {
            --rls-bg: #12161d;
            --rls-surface: #1a1f28;
            --rls-nav: #0c1520;
            --rls-accent: #6d9bff;
            --rls-accent-dark: #8fb1ff;
            --rls-text: #e6e9ef;
            --rls-text-muted: #93a0b3;
            --rls-border: #2a303c;
            --rls-danger-bg: #3a1a1e;
            --rls-danger-text: #ff9aa4;
            --rls-danger-border: #5c2830;
            --rls-success-bg: #16301f;
            --rls-success-text: #7fe0a4;
            --rls-success-border: #285c3a;
            --rls-warn-bg: #3a2a1a;
            --rls-warn-text: #ffb066;
            --rls-warn-border: #5c4222;
            color-scheme: dark;
        }

        .modal, .modal .modal-footer, .dropdown-content { background-color: var(--rls-surface); }
        .dropdown-content li:hover, .dropdown-content li.active { background-color: var(--rls-border); }
        .input-field input[type="text"]:not(.valid),
        .input-field input[type="password"]:not(.valid),
        .input-field input[type="email"]:not(.valid),
        .input-field input[type="number"]:not(.valid) {
            border-bottom-color: var(--rls-border);
            color: var(--rls-text);
        }
        .card, .card-panel { background-color: var(--rls-surface); color: var(--rls-text); }
        label { color: var(--rls-text-muted); }
    }

    body {
        background: var(--rls-bg);
        color: var(--rls-text);
        font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }

    /* Materialize's nav is a fixed 56px and never grows for a real title - see rethink's own
       style.css for the same fix (verified against Materialize 1.0.0's actual CSS). */
    nav {
        background: var(--rls-nav) !important;
        box-shadow: 0 2px 8px rgba(18, 38, 58, .25);
        height: auto;
        min-height: 56px;
    }
    .nav-wrapper { height: auto; min-height: 56px; }
    nav .brand-logo {
        position: static; left: auto; transform: none;
        display: flex; align-items: center; flex-wrap: wrap; gap: .4em;
        font-weight: 600; font-size: 1.25rem; letter-spacing: .01em; padding: .6em 0;
    }
    nav .brand-logo .material-icons { color: var(--rls-accent); }

    .container:not(.nav-wrapper) {
        background: var(--rls-surface);
        border: 1px solid var(--rls-border);
        border-radius: 10px;
        padding: 1.25em 1.5em;
        margin-top: 1.25em;
        margin-bottom: 1.25em;
        box-shadow: 0 1px 3px rgba(26, 31, 41, .06);
    }

    .header.orange-text, h4.header {
        color: var(--rls-accent-dark) !important;
        font-weight: 600;
        font-size: 1.2rem;
        letter-spacing: .01em;
    }

    .btn, .btn-large, .btn-small {
        background-color: var(--rls-accent);
        border-radius: 7px;
        box-shadow: none;
        text-transform: none;
        font-weight: 500;
    }
    .btn:hover, .btn-large:hover, .btn-small:hover {
        background-color: var(--rls-accent-dark);
        box-shadow: 0 2px 6px rgba(28, 79, 196, .35);
    }
    .btn:focus-visible, .btn-large:focus-visible, .btn-small:focus-visible, .btn-flat:focus-visible {
        outline: 2px solid var(--rls-accent);
        outline-offset: 2px;
    }
    .btn-flat { color: var(--rls-accent-dark); }

    .input-field input:focus + label,
    .input-field input.valid:focus { color: var(--rls-accent-dark) !important; }
    .input-field input:focus {
        border-bottom: 1px solid var(--rls-accent-dark) !important;
        box-shadow: 0 1px 0 0 var(--rls-accent-dark) !important;
    }
    .switch label input[type="checkbox"]:checked + .lever { background-color: rgba(47, 111, 237, .5); }
    .switch label input[type="checkbox"]:checked + .lever:after { background-color: var(--rls-accent-dark); }

    table.highlight { border-collapse: collapse; }
    table.highlight thead th {
        color: var(--rls-text-muted); font-size: .78rem; text-transform: uppercase;
        letter-spacing: .04em; border-bottom: 2px solid var(--rls-border);
    }
    table.highlight tbody tr { border-bottom: 1px solid var(--rls-border); }
    table.highlight tbody tr:hover { background: rgba(47, 111, 237, .06); }

    .alert-banner {
        border-radius: 8px;
        padding: .7em .9em;
        margin-top: .9em;
        font-size: .92em;
        line-height: 1.5;
        white-space: pre-wrap;
        display: none;
    }
    .alert-banner.shown { display: block; }
    .alert-banner.error { color: var(--rls-danger-text); background: var(--rls-danger-bg); border: 1px solid var(--rls-danger-border); }
    .alert-banner.success { color: var(--rls-success-text); background: var(--rls-success-bg); border: 1px solid var(--rls-success-border); }

    .rls-muted { color: var(--rls-text-muted); }
    .rls-card-empty { color: var(--rls-text-muted); }
    .rls-badge {
        display: inline-block; text-transform: uppercase; font-size: .68rem; font-weight: 600;
        letter-spacing: .03em; border-radius: 4px; padding: .15em .5em;
    }
    .rls-badge.mqtt { background: #e4ecff; color: #2a4d8f; }
    .rls-badge.http { background: #eef0f3; color: #3d4a5c; }
    .rls-badge.mitm { background: #fdece0; color: #a2540f; }
    @media (prefers-color-scheme: dark) {
        .rls-badge.mqtt { background: #1c2a4a; color: #9db8f5; }
        .rls-badge.http { background: #262c36; color: #b7c0cc; }
        .rls-badge.mitm { background: #3a2a1a; color: #ffb066; }
    }

    .rls-activity-list { max-height: 26em; overflow-y: auto; }
    .rls-activity-entry {
        display: flex; align-items: baseline; gap: .6em; padding: .35em 0;
        border-bottom: 1px solid var(--rls-border); font-size: .85em; flex-wrap: wrap;
    }
    .rls-activity-entry:last-child { border-bottom: none; }
    .rls-activity-time { color: var(--rls-text-muted); flex-shrink: 0; font-family: monospace; font-size: .92em; }
    .rls-activity-detail { word-break: break-word; }
    .rls-activity-raw { width: 100%; margin: .3em 0 0; font-family: monospace; font-size: .85em; white-space: pre-wrap; }

    .rls-pre {
        background: var(--rls-bg); border: 1px solid var(--rls-border); border-radius: 8px;
        padding: .8em 1em; font-family: monospace; font-size: .85em; white-space: pre-wrap;
        word-break: break-word; max-height: 22em; overflow: auto; color: var(--rls-text);
    }

    @media (max-width: 480px) {
        .container:not(.nav-wrapper) { padding: 1em; margin-top: .75em; margin-bottom: .75em; }
    }
    """
)


def register_theme_routes(app: FastAPI) -> None:
    @app.get(STYLE_CSS_PATH)
    async def admin_style_css() -> PlainTextResponse:
        return PlainTextResponse(STYLE_CSS, media_type="text/css")
