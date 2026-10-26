# Developing dashboard schedule and MQTT recovery tools

The standalone dashboard is rendered by `standalone_admin.py`. The setup wizard
remains in `management_app.py`; both use `web_theme.py` for Materialize assets and
the light/dark theme. The schedule and credential components live in
`admin_ui/schedule_sections.html`, `schedules.js`, and `schedules.css`.

The dashboard's vacuum chips and URL hash own selection. It emits
`rls:vacuum-selected` with the selected vacuum, or `null` for the Server view.
The tools preserve schedule drafts while selection changes. Credential mutations
invalidate older dashboard snapshots, and completed actions request a refresh
with `rls:refresh`.

The components use the existing authenticated admin APIs and the schedule store.
They do not introduce a separate login, theme, scheduler, or runtime dependency.
Only the two CSS/JavaScript component assets are served directly; the HTML
fragment is rendered inside the authenticated dashboard.

## Python and browser validation

From the repository root:

```sh
uv sync --locked --extra dev
uv run pytest -q
uv run python tests/browser/render_pages.py
npm install --no-save --no-package-lock playwright@1.62.1
npx playwright install --with-deps chromium
node --test tests/browser/admin-ui.test.cjs
```

The renderer produces the actual dashboard/login HTML and shared stylesheet. It
also downloads the Materialize stylesheet, script and icon font referenced by the
shared theme. Browser tests then use those local fixtures and fictional API responses;
they do not connect to robots or cloud APIs. Preview images are written under
`tests/browser/artifacts/`, which is ignored by Git.

Coverage includes preservation of native jobs and unknown settings, verified
native enablement, stale revisions and room catalogs, one-time schedules, dirty
forms, sorting, per-vacuum selection, credential reset races, mobile layouts and
dark mode. Python tests retain the setup wizard, environment configuration,
activity filtering and backend reset/scheduler coverage.

A passing suite does not establish scheduled execution on hardware. Follow the
[hardware test sequence](admin-schedule-editor.md#hardware-test-sequence) against
the intended server build before release.
