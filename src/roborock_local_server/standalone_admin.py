"""Standalone admin/dashboard adapter routes."""

from __future__ import annotations

import json
from textwrap import dedent
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .security import verify_password
from .web_theme import HEAD_ASSETS, NAV_HTML, SCRIPT_ASSETS, register_theme_routes


def _admin_login_html() -> str:
    return (
        dedent(
            """\
            <!doctype html><html><head><meta charset="utf-8">
            <title>Roborock Local Server</title>
            """
        )
        + HEAD_ASSETS
        + dedent(
            """\
            </head><body>
            """
        )
        + NAV_HTML
        + dedent(
            """\
            <div class="container" style="max-width:420px">
              <p class="rls-muted">Sign in to manage the stack.</p>
              <div class="row">
                <div class="input-field col s12">
                  <input id="password" type="password">
                  <label for="password">Admin password</label>
                </div>
              </div>
              <button id="login" class="btn waves-effect waves-light" style="width:100%">
                Sign In<i class="material-icons right">login</i>
              </button>
              <div id="result" class="alert-banner error"></div>
            </div>
            """
        )
        + SCRIPT_ASSETS
        + dedent(
            """\
            <script>
            const resultEl = document.getElementById("result");
            document.getElementById("login").addEventListener("click", async () => {
              const response = await fetch("/admin/api/login", {
                method: "POST",
                headers: {"Content-Type":"application/json"},
                body: JSON.stringify({password: document.getElementById("password").value})
              });
              const payload = await response.json().catch(() => ({error: "Invalid response"}));
              if (!response.ok) {
                resultEl.textContent = payload.error || "Sign-in failed";
                resultEl.classList.add("shown");
                return;
              }
              window.location.reload();
            });
            </script></body></html>
            """
        )
    )


def _admin_dashboard_html(project_support: dict[str, Any]) -> str:
    support_payload = json.dumps(project_support)
    return dedent(
        f"""\
        <!doctype html><html><head><meta charset="utf-8">
        <title>Roborock Local Server</title>
        {HEAD_ASSETS}
        </head><body>
        <nav>
          <div class="nav-wrapper container">
            <a href="#" class="brand-logo"><i class="material-icons">smart_toy</i>Roborock Local Server</a>
            <span style="flex:1"></span>
            <span id="overall" style="color:#fff;margin-right:16px">Loading</span>
            <button id="logout" class="btn-flat" style="color:#fff">Sign Out<i class="material-icons right">logout</i></button>
          </div>
        </nav>

        <div class="container">
          <h4 class="header rls-heading">Vacuums</h4>
          <div id="vacuumSummary" style="display:grid;gap:12px">Loading vacuums...</div>
        </div>

        <div class="container">
          <h4 id="supportTitle" class="header rls-heading"></h4>
          <p id="supportText" class="rls-muted"></p>
          <div id="supportLinks" style="display:flex;gap:12px;flex-wrap:wrap"></div>
        </div>

        <div class="container">
          <h4 class="header rls-heading">Cloud Import</h4>
          <div class="row" style="margin-bottom:0">
            <div class="input-field col s12 m6">
              <input id="email" type="email">
              <label for="email">Roborock account email</label>
            </div>
            <div class="input-field col s12 m6">
              <button id="sendCode" class="btn waves-effect waves-light">Send Code</button>
            </div>
          </div>
          <div class="row">
            <div class="input-field col s12 m6">
              <input id="code" type="text">
              <label for="code">Email code</label>
            </div>
            <div class="input-field col s12 m6">
              <button id="fetchData" class="btn waves-effect waves-light">Fetch Data</button>
            </div>
          </div>
          <pre id="cloudResult" class="rls-pre">No cloud request yet.</pre>
        </div>

        <div class="container">
          <h4 class="header rls-heading">New Connections</h4>
          <p>
            <label><input id="newConnectionsEnabled" type="checkbox" /><span>Allow new app logins, onboarding, and first-time vacuum connections</span></label>
          </p>
          <button id="saveConnections" class="btn waves-effect waves-light">Save</button>
          <div id="authMeta" class="rls-muted" style="margin-top:10px">Loading connection state...</div>
          <div style="margin-top:18px">
            <div style="font-weight:600">Protocol Sync Secret</div>
            <div class="row" style="margin-top:6px;margin-bottom:0">
              <div class="input-field col s12 m9">
                <input id="adminSessionSecret" readonly>
              </div>
              <div class="input-field col s12 m3">
                <button id="copySessionSecret" class="btn-flat waves-effect">Copy<i class="material-icons right">content_copy</i></button>
              </div>
            </div>
            <div id="syncSecretMeta" class="rls-muted">Use this with <code>mitm_redirect.py --local-api YOUR_SERVER_HOST --sync-secret &lt;secret above&gt; --activity-sync</code>.</div>
          </div>
          <div id="pendingRecovery" class="rls-muted" style="margin-top:10px"></div>
          <div style="margin-top:16px;font-weight:600">Protocol Sessions</div>
          <div id="sessionList" style="display:grid;gap:8px;margin-top:12px">Loading sessions...</div>
        </div>

        <div class="container">
          <h4 class="header rls-heading">Activity</h4>
          <div id="activityMeta" class="rls-muted" style="margin-bottom:10px"></div>
          <div id="activityList" class="rls-activity-list"></div>
        </div>

        <div class="container">
          <h4 class="header rls-heading">Health</h4>
          <pre id="health" class="rls-pre"></pre>
        </div>
        <div class="container">
          <h4 class="header rls-heading">Vacuums (raw)</h4>
          <pre id="vacuums" class="rls-pre"></pre>
        </div>
        {SCRIPT_ASSETS}
        <script>
        const support = {support_payload};
        let cloudSessionId = "";
        document.getElementById("supportTitle").textContent = support.title || "Support This Project";
        document.getElementById("supportText").textContent = support.text || "";
        const supportLinks = document.getElementById("supportLinks");
        for (const link of (support.links || [])) {{
          const anchor = document.createElement("a");
          anchor.href = link.url;
          anchor.target = "_blank";
          anchor.rel = "noreferrer";
          anchor.textContent = link.label || link.url;
          anchor.style.display = "inline-block";
          anchor.style.padding = "8px 12px";
          anchor.style.border = "1px solid var(--rls-border)";
          anchor.style.borderRadius = "7px";
          anchor.style.textDecoration = "none";
          anchor.style.color = "inherit";
          supportLinks.appendChild(anchor);
        }}
        async function fetchJson(url, options) {{
          const response = await fetch(url, options);
          const raw = await response.text();
          const payload = raw ? JSON.parse(raw) : {{}};
          if (!response.ok) throw new Error(payload.error || `HTTP ${{response.status}}`);
          return payload;
        }}
        function yesNo(value) {{
          return value ? "Yes" : "No";
        }}
        function renderVacuumSummary(vacuums) {{
          const container = document.getElementById("vacuumSummary");
          container.innerHTML = "";
          const items = Array.isArray(vacuums) ? vacuums : [];
          if (!items.length) {{
            const empty = document.createElement("div");
            empty.textContent = "No vacuums yet.";
            empty.style.color = "var(--rls-text-muted)";
            container.appendChild(empty);
            return;
          }}
          const addField = (parent, label, value) => {{
            const line = document.createElement("div");
            line.textContent = `${{label}}: ${{value}}`;
            line.style.marginTop = "4px";
            parent.appendChild(line);
          }};
          for (const vacuum of items) {{
            const card = document.createElement("div");
            card.style.border = "1px solid var(--rls-border)";
            card.style.borderRadius = "8px";
            card.style.padding = "12px";
            card.style.background = "var(--rls-bg)";

            const name = document.createElement("div");
            name.textContent = vacuum.name || vacuum.did || vacuum.duid || "Unknown vacuum";
            name.style.fontWeight = "600";
            name.style.marginBottom = "8px";
            card.appendChild(name);

            const onboarding = vacuum.onboarding || {{}};
            const keyState = onboarding.key_state || {{}};
            addField(card, "Num query samples", Number(keyState.query_samples || 0));
            addField(card, "Public Key determined", yesNo(Boolean(onboarding.has_public_key)));
            addField(card, "Mqtt connected", yesNo(Boolean(vacuum.connected)));
            if (onboarding.unsupported) {{
              const alert = document.createElement("div");
              alert.textContent = onboarding.guidance || "This vacuum is not supported by the current onboarding flow.";
              alert.style.marginTop = "10px";
              alert.style.padding = "8px";
              alert.style.borderRadius = "6px";
              alert.style.border = "1px solid var(--rls-warn-border)";
              alert.style.background = "var(--rls-warn-bg)";
              alert.style.color = "var(--rls-warn-text)";
              card.appendChild(alert);
            }}
            container.appendChild(card);
          }}
        }}
        function renderAuth(auth) {{
          const enabled = Boolean(auth.new_connections_enabled);
          document.getElementById("newConnectionsEnabled").checked = enabled;
          document.getElementById("authMeta").textContent =
            `New connections: ${{enabled ? "Allowed" : "Blocked"}}. Persisted sessions: ${{Number(auth.protocol_session_count || 0)}}.`;
          const sessionSecret = String(auth.admin_session_secret || "");
          document.getElementById("adminSessionSecret").value = sessionSecret;
          document.getElementById("syncSecretMeta").textContent = sessionSecret
            ? `Use this with mitm_redirect.py --local-api YOUR_SERVER_HOST --sync-secret ${{sessionSecret}} --activity-sync`
            : "No protocol sync secret is configured.";

          const pendingContainer = document.getElementById("pendingRecovery");
          const pendingItems = Array.isArray(auth.pending_device_mqtt_recovery) ? auth.pending_device_mqtt_recovery : [];
          if (!pendingItems.length) {{
            pendingContainer.textContent = "No devices are waiting for MQTT password recovery.";
          }} else {{
            pendingContainer.textContent =
              "Devices waiting for first reconnect MQTT password recovery: " +
              pendingItems.map((item) => item.name || item.duid || item.did || item.device_mqtt_usr).join(", ");
          }}

          const sessionList = document.getElementById("sessionList");
          sessionList.innerHTML = "";
          const sessions = Array.isArray(auth.protocol_sessions) ? auth.protocol_sessions : [];
          if (!sessions.length) {{
            const empty = document.createElement("div");
            empty.textContent = "No persisted protocol sessions.";
            empty.style.color = "var(--rls-text-muted)";
            sessionList.appendChild(empty);
            return;
          }}
          for (const session of sessions) {{
            const card = document.createElement("div");
            card.style.border = "1px solid var(--rls-border)";
            card.style.borderRadius = "8px";
            card.style.padding = "10px";
            card.style.background = "var(--rls-bg)";
            const label = document.createElement("div");
            label.textContent = session.rruid || session.hawk_id || "Protocol session";
            label.style.fontWeight = "600";
            card.appendChild(label);

            const detail = document.createElement("div");
            detail.textContent = `source=${{session.source || "unknown"}} updated=${{session.updated_at_utc || "unknown"}} hawk_id=${{session.hawk_id || ""}}`;
            detail.style.marginTop = "6px";
            detail.style.fontSize = "12px";
            card.appendChild(detail);

            const remove = document.createElement("button");
            remove.textContent = "Remove";
            remove.className = "btn-flat waves-effect";
            remove.style.marginTop = "8px";
            remove.style.padding = "0 8px";
            remove.addEventListener("click", async () => {{
              try {{
                await fetchJson(
                  `/admin/api/auth/sessions/${{encodeURIComponent(session.hawk_id || "")}}/${{encodeURIComponent(session.hawk_session || "")}}`,
                  {{method: "DELETE"}}
                );
                await refresh();
              }} catch (error) {{
                document.getElementById("authMeta").textContent = error.message;
              }}
            }});
            card.appendChild(remove);
            sessionList.appendChild(card);
          }}
        }}

        function renderActivity(payload) {{
          document.getElementById("activityMeta").textContent = payload.raw
            ? "Showing full raw entries (ROBOROCK_SERVER_ACTIVITY_RAW is enabled) - headers/bodies/payloads are not redacted."
            : "Showing redacted summaries. Set ROBOROCK_SERVER_ACTIVITY_RAW=1 to see full raw entries.";
          const list = document.getElementById("activityList");
          list.innerHTML = "";
          const entries = Array.isArray(payload.entries) ? payload.entries : [];
          if (!entries.length) {{
            const empty = document.createElement("div");
            empty.textContent = "No recent activity.";
            empty.style.color = "var(--rls-text-muted)";
            list.appendChild(empty);
            return;
          }}
          const makeBadge = (source) => {{
            const span = document.createElement("span");
            span.className = `rls-badge ${{source}}`;
            span.textContent = source;
            return span;
          }};
          const appendText = (parent, text) => {{
            parent.appendChild(document.createTextNode(text));
          }};
          for (const entry of entries) {{
            const row = document.createElement("div");
            row.className = "rls-activity-entry";
            const time = document.createElement("span");
            time.className = "rls-activity-time";
            time.textContent = entry.time || "";
            row.appendChild(time);
            const detail = document.createElement("span");
            detail.className = "rls-activity-detail";
            if (payload.raw) {{
              detail.appendChild(makeBadge(entry.source || "http"));
              row.appendChild(detail);
              const pre = document.createElement("pre");
              pre.className = "rls-activity-raw";
              pre.textContent = JSON.stringify(entry, null, 2);
              row.appendChild(pre);
            }} else if (entry.source === "mqtt") {{
              const methods = (entry.rpc_methods || []).join(", ");
              detail.appendChild(makeBadge("mqtt"));
              appendText(detail, ` ${{entry.direction || ""}} ${{entry.topic || ""}}` + (methods ? ` - ${{methods}}` : ""));
              row.appendChild(detail);
            }} else if (entry.source === "mitm") {{
              detail.appendChild(makeBadge("mitm"));
              appendText(
                detail,
                ` ${{entry.method || ""}} ${{entry.host || ""}}${{entry.path || ""}}` +
                  (entry.status ? ` -> ${{entry.status}}` : "") +
                  (entry.rewritten ? " (rewritten to local)" : "")
              );
              row.appendChild(detail);
            }} else {{
              detail.appendChild(makeBadge("http"));
              appendText(detail, ` ${{entry.method || ""}} ${{entry.path || ""}}` + (entry.route ? ` (${{entry.route}})` : ""));
              row.appendChild(detail);
            }}
            list.appendChild(row);
          }}
        }}

        async function refresh() {{
          const status = await fetchJson("/admin/api/status");
          document.getElementById("overall").textContent = status.health.overall_ok ? "Healthy" : "Needs Attention";
          document.getElementById("health").textContent = JSON.stringify(status.health, null, 2);
          renderAuth(await fetchJson("/admin/api/auth"));
          const vacuums = await fetchJson("/admin/api/vacuums");
          renderVacuumSummary(vacuums.vacuums);
          document.getElementById("vacuums").textContent = JSON.stringify(vacuums.vacuums, null, 2);
          renderActivity(await fetchJson("/admin/api/activity"));
        }}
        document.getElementById("sendCode").addEventListener("click", async () => {{
          try {{
            const payload = await fetchJson("/admin/api/cloud/request-code", {{
              method: "POST",
              headers: {{"Content-Type":"application/json"}},
              body: JSON.stringify({{email: document.getElementById("email").value}})
            }});
            cloudSessionId = payload.session_id || "";
            document.getElementById("cloudResult").textContent = JSON.stringify(payload, null, 2);
          }} catch (error) {{
            document.getElementById("cloudResult").textContent = error.message;
          }}
        }});
        document.getElementById("fetchData").addEventListener("click", async () => {{
          try {{
            const payload = await fetchJson("/admin/api/cloud/submit-code", {{
              method: "POST",
              headers: {{"Content-Type":"application/json"}},
              body: JSON.stringify({{session_id: cloudSessionId, code: document.getElementById("code").value}})
            }});
            cloudSessionId = "";
            document.getElementById("cloudResult").textContent = JSON.stringify(payload, null, 2);
            await refresh();
          }} catch (error) {{
            document.getElementById("cloudResult").textContent = error.message;
          }}
        }});
        document.getElementById("saveConnections").addEventListener("click", async () => {{
          try {{
            const payload = await fetchJson("/admin/api/auth", {{
              method: "POST",
              headers: {{"Content-Type":"application/json"}},
              body: JSON.stringify({{
                new_connections_enabled: document.getElementById("newConnectionsEnabled").checked
              }})
            }});
            renderAuth(payload);
            await refresh();
          }} catch (error) {{
            document.getElementById("authMeta").textContent = error.message;
          }}
        }});
        document.getElementById("copySessionSecret").addEventListener("click", async () => {{
          const input = document.getElementById("adminSessionSecret");
          if (!input.value) {{
            document.getElementById("syncSecretMeta").textContent = "No protocol sync secret is configured.";
            return;
          }}
          try {{
            if (navigator.clipboard && navigator.clipboard.writeText) {{
              await navigator.clipboard.writeText(input.value);
            }} else {{
              input.focus();
              input.select();
              document.execCommand("copy");
            }}
            document.getElementById("syncSecretMeta").textContent = "Copied protocol sync secret.";
          }} catch (error) {{
            document.getElementById("syncSecretMeta").textContent = "Copy failed. Select the field and copy it manually.";
          }}
        }});

        document.getElementById("logout").addEventListener("click", async () => {{
          await fetch("/admin/api/logout", {{method:"POST"}});
          window.location.reload();
        }});
        refresh().catch((error) => document.getElementById("overall").textContent = error.message);
        setInterval(() => refresh().catch(() => {{}}), 2000);
        </script></body></html>
        """
    )


def register_standalone_admin_routes(
    *,
    app: FastAPI,
    supervisor: Any,
    project_support: dict[str, Any],
) -> None:
    register_theme_routes(app)

    @app.get("/admin", response_class=HTMLResponse)
    async def admin_page(request: Request) -> HTMLResponse:
        if not supervisor._authenticated(request):
            return HTMLResponse(_admin_login_html())
        return HTMLResponse(_admin_dashboard_html(project_support))

    @app.post("/admin/api/login")
    async def admin_login(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except json.JSONDecodeError:
            body = {}
        password = str((body or {}).get("password") or "")
        if not verify_password(password, supervisor.config.admin.password_hash):
            return JSONResponse({"error": "Invalid password"}, status_code=401)
        response = JSONResponse({"ok": True})
        response.set_cookie(
            supervisor.session_manager.cookie_name,
            supervisor.session_manager.issue(),
            httponly=True,
            secure=supervisor.cookie_secure(request),
            samesite="lax",
            max_age=supervisor.config.admin.session_ttl_seconds,
            path="/",
        )
        return response

    @app.post("/admin/api/logout")
    async def admin_logout() -> JSONResponse:
        response = JSONResponse({"ok": True})
        response.delete_cookie(supervisor.session_manager.cookie_name, path="/")
        return response

    @app.get("/admin/api/status")
    async def admin_status(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        return JSONResponse(supervisor._status_payload())

    @app.get("/admin/api/vacuums")
    async def admin_vacuums(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        return JSONResponse(supervisor._vacuums_payload())

    @app.get("/admin/api/auth")
    async def admin_auth(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        return JSONResponse(supervisor._auth_payload())

    @app.get("/admin/api/activity")
    async def admin_activity(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        raw_limit = request.query_params.get("limit")
        try:
            limit = int(raw_limit) if raw_limit else 200
        except ValueError:
            return JSONResponse({"error": "limit must be an integer"}, status_code=400)
        limit = max(1, min(limit, 500))
        return JSONResponse(supervisor._activity_payload(limit=limit))

    @app.post("/admin/api/auth")
    async def admin_auth_update(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "JSON body must be an object"}, status_code=400)
        if "new_connections_enabled" in body:
            new_connections_enabled = body.get("new_connections_enabled")
            if not isinstance(new_connections_enabled, bool):
                return JSONResponse({"error": "new_connections_enabled must be a boolean"}, status_code=400)
            try:
                payload = supervisor.set_new_connections_enabled(new_connections_enabled)
            except Exception as exc:  # noqa: BLE001
                return JSONResponse({"error": str(exc)}, status_code=500)
            return JSONResponse(payload)
        if "protocol_auth_enabled" in body:
            protocol_auth_enabled = body.get("protocol_auth_enabled")
            if not isinstance(protocol_auth_enabled, bool):
                return JSONResponse({"error": "protocol_auth_enabled must be a boolean"}, status_code=400)
            try:
                payload = supervisor.set_protocol_auth_enabled(protocol_auth_enabled)
            except Exception as exc:  # noqa: BLE001
                return JSONResponse({"error": str(exc)}, status_code=500)
            return JSONResponse(payload)
        return JSONResponse(
            {"error": "new_connections_enabled or protocol_auth_enabled is required"},
            status_code=400,
        )

    @app.delete("/admin/api/auth/sessions/{hawk_id}/{hawk_session}")
    async def admin_auth_delete_session(hawk_id: str, hawk_session: str, request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        if not supervisor.remove_protocol_session(hawk_id=hawk_id, hawk_session=hawk_session):
            return JSONResponse({"error": "Protocol session not found"}, status_code=404)
        return JSONResponse({"ok": True, "auth": supervisor._auth_payload()})

    @app.get("/admin/api/onboarding/devices")
    async def admin_onboarding_devices(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        return JSONResponse(supervisor._onboarding_devices_payload())

    @app.post("/admin/api/onboarding/sessions")
    async def admin_onboarding_start(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        try:
            body = await request.json()
        except json.JSONDecodeError:
            body = {}
        duid = str((body or {}).get("duid") or "").strip()
        new_vacuum = bool((body or {}).get("new_vacuum"))
        name = str((body or {}).get("name") or "").strip()
        model = str((body or {}).get("model") or "").strip()
        try:
            payload = supervisor.start_onboarding_session(
                duid=duid,
                new_vacuum=new_vacuum,
                name=name,
                model=model,
            )
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        except KeyError:
            return JSONResponse({"error": "Unknown onboarding device"}, status_code=404)
        return JSONResponse(payload)

    @app.get("/admin/api/onboarding/sessions/{session_id}")
    async def admin_onboarding_status(session_id: str, request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        try:
            payload = supervisor.onboarding_session_snapshot(session_id=session_id)
        except KeyError:
            return JSONResponse({"error": "Onboarding session not found"}, status_code=404)
        return JSONResponse(payload)

    @app.delete("/admin/api/onboarding/sessions/{session_id}")
    async def admin_onboarding_delete(session_id: str, request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        try:
            payload = supervisor.clear_onboarding_session(session_id=session_id)
        except KeyError:
            return JSONResponse({"error": "Onboarding session not found"}, status_code=404)
        return JSONResponse(payload)


    @app.post("/admin/api/cloud/request-code")
    async def admin_cloud_request_code(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        try:
            body = await request.json()
        except json.JSONDecodeError:
            body = {}
        try:
            result = await supervisor.cloud_manager.request_code(
                email=str((body or {}).get("email") or ""),
                base_url=str((body or {}).get("base_url") or ""),
            )
        except Exception as exc:  # noqa: BLE001
            result = {"success": False, "step": "code_request_failed", "error": str(exc)}
        supervisor.runtime_state.record_cloud_request(result)
        return JSONResponse(result, status_code=200 if result.get("success") else 400)

    @app.post("/admin/api/cloud/submit-code")
    async def admin_cloud_submit_code(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        try:
            body = await request.json()
        except json.JSONDecodeError:
            body = {}
        try:
            result = await supervisor.cloud_manager.submit_code(
                session_id=str((body or {}).get("session_id") or ""),
                code=str((body or {}).get("code") or ""),
            )
            supervisor.refresh_inventory_state()
        except Exception as exc:  # noqa: BLE001
            result = {"success": False, "step": "code_submit_failed", "error": str(exc)}
        supervisor.runtime_state.record_cloud_request(result)
        return JSONResponse(result, status_code=200 if result.get("success") else 400)
