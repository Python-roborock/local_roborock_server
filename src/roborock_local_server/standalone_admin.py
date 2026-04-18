"""Standalone admin/dashboard adapter routes."""

from __future__ import annotations

import json
from textwrap import dedent
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .security import verify_password


def _admin_login_html() -> str:
    return dedent(
        """\
        <!doctype html><html><body style="font-family:Segoe UI,sans-serif;max-width:420px;margin:12vh auto">
        <h1>Roborock Local Server</h1>
        <p>Sign in to manage the stack.</p>
        <input id="password" type="password" placeholder="Admin password" style="width:100%;padding:10px" />
        <button id="login" style="width:100%;padding:10px;margin-top:8px">Sign In</button>
        <pre id="result"></pre>
        <script>
        document.getElementById("login").addEventListener("click", async () => {
          const response = await fetch("/admin/api/login", {
            method: "POST",
            headers: {"Content-Type":"application/json"},
            body: JSON.stringify({password: document.getElementById("password").value})
          });
          const payload = await response.json().catch(() => ({error: "Invalid response"}));
          if (!response.ok) {
            document.getElementById("result").textContent = payload.error || "Sign-in failed";
            return;
          }
          window.location.reload();
        });
        </script></body></html>
        """
    )


def _admin_dashboard_html(project_support: dict[str, Any]) -> str:
    support_payload = json.dumps(project_support)
    return dedent(
        f"""\
        <!doctype html><html><body style="font-family:Segoe UI,sans-serif;max-width:1100px;margin:20px auto;padding:0 12px">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <h1>Roborock Local Server</h1>
          <div><span id="overall">Loading</span> <button id="logout">Sign Out</button></div>
        </div>
        <section><h2>Vacuums</h2><div id="vacuumSummary" style="display:grid;gap:12px">Loading vacuums...</div></section>
        <section><h2 id="supportTitle"></h2><p id="supportText"></p><div id="supportLinks" style="display:flex;gap:12px;flex-wrap:wrap"></div></section>
        <section><h2>Cloud Import</h2>
          <input id="email" placeholder="email@example.com" />
          <button id="sendCode">Send Code</button>
          <input id="code" placeholder="Email code" style="margin-top:8px" />
          <button id="fetchData">Fetch Data</button>
          <pre id="cloudResult">No cloud request yet.</pre>
        </section>
        <section><h2>Protocol Auth</h2>
          <label><input id="protocolAuthEnabled" type="checkbox" /> Require token/Hawk auth on protocol API routes</label>
          <button id="saveAuth" style="margin-left:8px">Save</button>
          <div id="authMeta" style="margin-top:8px;color:#333">Loading auth state...</div>
          <div id="pendingRecovery" style="margin-top:8px"></div>
          <div id="sessionList" style="display:grid;gap:8px;margin-top:12px">Loading sessions...</div>
        </section>

        <section><h2>Health</h2><pre id="health"></pre></section>
        <section><h2>Vacuums</h2><pre id="vacuums"></pre></section>
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
          anchor.style.border = "1px solid #999";
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
            empty.style.color = "#555";
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
            card.style.border = "1px solid #ddd";
            card.style.borderRadius = "6px";
            card.style.padding = "12px";
            card.style.background = "#fafafa";

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
            container.appendChild(card);
          }}
        }}
        function renderAuth(auth) {{
          const enabled = Boolean(auth.protocol_auth_enabled);
          document.getElementById("protocolAuthEnabled").checked = enabled;
          document.getElementById("authMeta").textContent =
            `Protocol auth: ${{enabled ? "Enabled" : "Disabled"}}. Persisted sessions: ${{Number(auth.protocol_session_count || 0)}}.`;

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
            empty.style.color = "#555";
            sessionList.appendChild(empty);
            return;
          }}
          for (const session of sessions) {{
            const card = document.createElement("div");
            card.style.border = "1px solid #ddd";
            card.style.borderRadius = "6px";
            card.style.padding = "10px";
            card.style.background = "#fafafa";
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
            remove.style.marginTop = "8px";
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

        async function refresh() {{
          const status = await fetchJson("/admin/api/status");
          document.getElementById("overall").textContent = status.health.overall_ok ? "Healthy" : "Needs Attention";
          document.getElementById("health").textContent = JSON.stringify(status.health, null, 2);
          renderAuth(await fetchJson("/admin/api/auth"));
          const vacuums = await fetchJson("/admin/api/vacuums");
          renderVacuumSummary(vacuums.vacuums);
          document.getElementById("vacuums").textContent = JSON.stringify(vacuums.vacuums, null, 2);
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
        document.getElementById("saveAuth").addEventListener("click", async () => {{
          try {{
            const payload = await fetchJson("/admin/api/auth", {{
              method: "POST",
              headers: {{"Content-Type":"application/json"}},
              body: JSON.stringify({{
                protocol_auth_enabled: document.getElementById("protocolAuthEnabled").checked
              }})
            }});
            renderAuth(payload);
            await refresh();
          }} catch (error) {{
            document.getElementById("authMeta").textContent = error.message;
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
            secure=request.url.scheme == "https",
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

    @app.post("/admin/api/auth")
    async def admin_auth_update(request: Request) -> JSONResponse:
        supervisor._require_admin(request)
        try:
            body = await request.json()
        except json.JSONDecodeError:
            body = {}
        if "protocol_auth_enabled" not in (body or {}):
            return JSONResponse({"error": "protocol_auth_enabled is required"}, status_code=400)
        try:
            payload = supervisor.set_protocol_auth_enabled(bool((body or {}).get("protocol_auth_enabled")))
        except Exception as exc:  # noqa: BLE001
            return JSONResponse({"error": str(exc)}, status_code=500)
        return JSONResponse(payload)

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
        try:
            payload = supervisor.start_onboarding_session(duid=duid)
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
