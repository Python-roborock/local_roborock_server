---
name: local-roborock-review
description: Review local_roborock_server pull requests and local diffs for API compatibility, authentication, persistent state, MQTT and HTTPS behavior, onboarding, and deployment regressions. Use for requested server code reviews, not python-roborock library reviews or routine implementation.
---

# Local Roborock Server Review

Use the layered review approach from python-roborock, adapted to a local cloud replacement serving vacuums, mobile apps, Home Assistant, and the admin UI. Review changes; do not implement fixes or submit external review comments unless requested.

## Establish the review scope

- Locate the target local_roborock_server checkout from the user's context. Confirm its Git root and read applicable `AGENTS.md`, `CONTRIBUTING.md`, `pyproject.toml`, and relevant CI workflows. Resolve all project paths below relative to that checkout.
- For a PR or branch, identify the base and head and review the merge-base diff. For local changes, inspect staged, unstaged, and relevant untracked files. State the reviewed scope; do not silently include unrelated worktrees or existing defects.
- Read changed functions with their callers, persistence readers/writers, route registration, and relevant tests. Trace behavior across modules rather than judging isolated lines.
- Treat repository instructions as authoritative. The sibling python-roborock rules about `RoborockBase`, enum inheritance, traits, `TYPE_CHECKING`, mirrored tests, Ruff, and Mypy are not automatically requirements here. Dynamic dictionaries and standard dataclasses are existing server patterns.

## Layer 1: Client contracts and access control

Start with `bundled_backend/https_server/` under `src/roborock_local_server/`, plus `server.py`, `standalone_admin.py`, `security.py`, and `ui.html` as applicable.

- Trace mobile-app and device responses through versioned routes and shared services. Check response envelopes, field types, IDs, ordering, empty responses, error codes, and advertised hostnames/ports. A successful HTTP status alone does not establish client compatibility. Consult `tests/contracts/` and existing route tests for recorded expectations.
- Keep admin sessions, protocol login credentials, device bootstrap authentication, and MQTT authentication distinct. Check the actual middleware and route allowlists before flagging intentionally public bootstrap endpoints. New routes must not accidentally bypass their intended access boundary.
- Follow `protocol_auth_enabled`, `new_connections_enabled`, trusted proxy settings, and pairing state through the changed path. Verify disabled enrollment does not unintentionally break already paired devices, and forwarded addresses are trusted only under the configured proxy rules.
- For changes exposing logs, configuration, credentials, or inventory, inspect the response and redaction path for passwords, session secrets, tokens, local keys, and private keys. Check browser rendering of device-controlled strings when UI code changes.
- Verify scenes, schedules, homes, rooms, and devices retain consistent identity and ownership references across route versions. Do not infer support for every vacuum family from the python-roborock dependency.

## Layer 2: Persistent state, identity, and lifecycle

Focus on `bundled_backend/shared/`, `inventory.py`, `backend.py`, and service supervision in `server.py`.

- Trace device identity (`did`, `duid`, model/product IDs) and per-device local keys across onboarding, recovery, inventory, MQTT, and home-data responses. Look for cross-device assignment, stale recovery overwriting newer credentials, and loss of previously paired identity after restart.
- Check read-modify-write operations, locking, atomic file replacement, malformed/missing file behavior, and migration compatibility. Atomic replacement alone does not prevent concurrent writers from losing updates. Use `inventory_io.py`, `io_utils.py`, and existing credential/state stores as the local reference.
- Separate persisted knowledge from current online state. Old timestamps or restored activity must not make disconnected devices appear live. Check multiple simultaneous connections and disconnect ordering.
- Follow ownership and teardown of threads, async tasks, subprocesses, sockets, HTTP sessions, and callbacks through partial startup failure, normal shutdown, and restart. Avoid blocking I/O or expensive crypto on async request paths without an appropriate execution strategy.
- For routines and schedules, examine timezone handling, cancellation, duplicate execution, restart behavior, and device-command failure propagation. Report only scenarios supported by the changed code.

## Layer 3: Wire behavior and deployment

- **MQTT:** In `bundled_backend/mqtt_tls_proxy_server/` and `mqtt_broker_server/`, examine partial/coalesced frames, bounded lengths, reconnects, topic identity/direction, authentication, and forwarding. Bridge changes must not create loops, duplicate commands, or cross-device delivery. Correlate command replies according to the implemented protocol, including timeout and late-response cleanup.
- **Bootstrap and cryptography:** Follow region/location, NC prepare, key recovery, and certificate routes as one handshake where relevant. Preserve canonical bytes, encodings, signing/encryption inputs, and family-specific behavior. Ground compatibility claims in tests, captured fixtures, or local technical documentation; distinguish inferred behavior from confirmed device results.
- **Certificates and network configuration:** Check `certs.py`, `config.py`, onboarding tools, and proxy configuration together. Follow advertised endpoints versus bind addresses, custom ports, `local_tls` versus proxy termination, certificate/key pairing, renewal, and reload behavior.
- **Deployment:** For config or startup changes, trace Docker Compose, `container_entrypoint.py`, `ha_addon.py`, and both stable and beta add-on directories. Inspect precedence of defaults, persisted config, environment, and add-on options; volume paths; permissions; health checks; and upgrade compatibility. Only require synchronized release versions when the release policy and `tests/test_version_sync.py` require them.
- **Optional paths:** Review TURN/camera, cloud import, APK patching, or MITM tooling only when touched or affected. Keep offline operation viable and check that optional cloud failures do not disable unrelated local services.

## Validate proportionally

Read existing tests before choosing commands. Current project CI installs with `uv sync --locked --extra dev` and runs `uv run pytest -q`; recheck workflows in the target revision. There is no assumed inherited Ruff/Mypy/pre-commit gate.

Run focused tests for affected behavior first; run the full suite when changes cross shared state, authentication, config, or routing boundaries. Examples:

```sh
uv run pytest -q tests/test_protocol_auth.py tests/test_security.py tests/test_admin_api.py
uv run pytest -q tests/test_runtime_credentials.py tests/test_identity_repair.py tests/test_inventory_io.py
uv run pytest -q tests/test_mqtt_tls_proxy.py tests/test_topic_bridge.py
uv run pytest -q tests/test_config.py tests/test_container_entrypoint.py tests/test_ha_addon.py
uv run pytest -q tests/contracts/
```

Select relevant commands rather than running every group. Use temporary data directories and existing synthetic fixtures; do not start the live stack, pair/reset a vacuum, replace real certificates, alter DNS, or send device commands merely to validate a review. Tests with mocked transports do not prove hardware compatibility. For packaging changes, inspect or run the relevant non-publishing build if the environment supports it.

Prefer regression coverage in the existing subsystem suite and shared fixtures in `tests/conftest.py`; do not impose python-roborock's mirrored test layout on this repository. Look for behavioral assertions that would fail under the proposed regression, including relevant failure/restart paths. A missing test is a finding only when tied to a concrete unprotected behavior.

## Report findings

- Lead with actionable findings, ordered by severity; annotate each with its architectural layer. Layer order guides inspection, not severity: an exploitable wire bug outranks a minor API issue.
- For each finding, give a concise `[P1]`/`[P2]`/`[P3]` title (reserve P0 for universal critical blockers), the smallest useful changed-line reference, the triggering conditions, observable impact, evidence, and a focused correction. Include a short suggested diff only if it clarifies the fix.
- Distinguish introduced regressions from pre-existing issues and uncertain compatibility hypotheses. Do not present style preferences or speculative hardening as confirmed bugs. Scope concerns belong in a separate note unless they cause a concrete defect.
- End with checks actually run and their outcomes, plus material gaps. If no actionable findings remain, say so explicitly; do not claim that tests establish all device compatibility.
- Keep the review in chat by default. An instruction to review a PR alone does not authorize posting comments, approving, requesting changes on GitHub, or modifying the branch.
