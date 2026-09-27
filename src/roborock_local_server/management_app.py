"""Bootstrap /admin app, served before config.toml exists.

There's only one admin surface, at /admin. Before setup, this app serves the
Setup Wizard in plain HTTP on the same https_port the real stack will use
once configured (it can't depend on anything that requires a config -  TLS
certs, ReleaseSupervisor, admin auth). Once the wizard writes config.toml,
the process restarts and ReleaseSupervisor's own /admin (standalone_admin.py,
with TLS if local_tls) takes over that same port for good.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import json
from pathlib import Path
import secrets
from textwrap import dedent
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .config import diagnose_config
from .configure import (
    ConfigureAnswers,
    _normalize_acme_server,
    _normalize_hostname,
    _validate_protocol_login_pin,
    hash_password,
    write_config_setup,
)

DEFAULT_BOOTSTRAP_HTTPS_PORT = 555
_ENV_HTTPS_PORT = "ROBOROCK_SERVER_HTTPS_PORT"


def bootstrap_port_from_env(env: Mapping[str, str]) -> int:
    """The port the setup wizard listens on, before config.toml sets https_port.

    Reuses ROBOROCK_SERVER_HTTPS_PORT, the same env var already used for the
    Docker Compose port mapping, so there's one port/one env var either way.
    """
    raw_value = str(env.get(_ENV_HTTPS_PORT, "") or "").strip()
    if not raw_value:
        return DEFAULT_BOOTSTRAP_HTTPS_PORT
    try:
        port = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{_ENV_HTTPS_PORT} must be an integer") from exc
    if not (1 <= port <= 65535):
        raise ValueError(f"{_ENV_HTTPS_PORT} must be between 1 and 65535")
    return port


def _as_port(value: Any, *, field_name: str, default: int) -> int:
    if value in (None, ""):
        return default
    try:
        candidate = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if not (1 <= candidate <= 65535):
        raise ValueError(f"{field_name} must be between 1 and 65535")
    return candidate


def _answers_from_payload(body: Mapping[str, Any]) -> ConfigureAnswers:
    def s(key: str, default: str = "") -> str:
        return str(body.get(key, default) or "").strip()

    stack_fqdn = _normalize_hostname(s("stack_fqdn"), field_name="stack_fqdn", require_api_prefix=True)
    https_port = _as_port(body.get("https_port"), field_name="https_port", default=555)
    mqtt_tls_port = _as_port(body.get("mqtt_tls_port"), field_name="mqtt_tls_port", default=8881)

    broker_mode = s("broker_mode", "embedded").lower()
    if broker_mode not in {"embedded", "external"}:
        raise ValueError("broker_mode must be 'embedded' or 'external'")
    broker_host = s("broker_host")
    if broker_mode == "external" and not broker_host:
        raise ValueError("broker_host is required when broker_mode is 'external'")

    tls_mode = s("tls_mode", "cloudflare_acme").lower()
    if tls_mode not in {"cloudflare_acme", "provided"}:
        raise ValueError("tls_mode must be 'cloudflare_acme' or 'provided'")

    base_domain = ""
    email = ""
    acme_server = "zerossl"
    acme_eab_kid = ""
    acme_eab_hmac_key = ""
    cloudflare_token = ""
    if tls_mode == "cloudflare_acme":
        base_domain = _normalize_hostname(s("base_domain"), field_name="base_domain")
        email = s("email")
        if not email:
            raise ValueError("email is required")
        acme_server = _normalize_acme_server(s("acme_server", "zerossl"))
        cloudflare_token = s("cloudflare_token")
        if not cloudflare_token:
            raise ValueError("cloudflare_token is required")
        if acme_server == "actalis":
            acme_eab_kid = s("acme_eab_kid")
            acme_eab_hmac_key = s("acme_eab_hmac_key")
            if not acme_eab_kid or not acme_eab_hmac_key:
                raise ValueError("Actalis requires both acme_eab_kid and acme_eab_hmac_key")

    admin_password = s("admin_password")
    if not admin_password:
        raise ValueError("admin_password is required")
    protocol_login_email = s("protocol_login_email")
    if "@" not in protocol_login_email:
        raise ValueError("protocol_login_email must be an email address")
    protocol_login_pin = _validate_protocol_login_pin(s("protocol_login_pin"))

    return ConfigureAnswers(
        stack_fqdn=stack_fqdn,
        https_port=https_port,
        mqtt_tls_port=mqtt_tls_port,
        broker_mode=broker_mode,
        broker_host=broker_host,
        tls_mode=tls_mode,
        base_domain=base_domain,
        email=email,
        acme_server=acme_server,
        acme_eab_kid=acme_eab_kid,
        acme_eab_hmac_key=acme_eab_hmac_key,
        cloudflare_token=cloudflare_token,
        password_hash=hash_password(admin_password),
        session_secret=secrets.token_urlsafe(32),
        protocol_login_email=protocol_login_email,
        protocol_login_pin_hash=hash_password(protocol_login_pin),
    )


def _toml_string(value: str) -> str:
    return json.dumps(value)


def _admin_fields_from_payload(body: Mapping[str, Any]) -> tuple[str, str, str]:
    def s(key: str, default: str = "") -> str:
        return str(body.get(key, default) or "").strip()

    admin_password = s("admin_password")
    if not admin_password:
        raise ValueError("admin_password is required")
    protocol_login_email = s("protocol_login_email")
    if "@" not in protocol_login_email:
        raise ValueError("protocol_login_email must be an email address")
    protocol_login_pin = _validate_protocol_login_pin(s("protocol_login_pin"))
    return admin_password, protocol_login_email, protocol_login_pin


def complete_admin_section(
    *,
    config_file: Path,
    admin_password: str,
    protocol_login_email: str,
    protocol_login_pin: str,
) -> None:
    """Append [admin] to a partial config.toml (network/broker/storage/tls
    already written, e.g. by env_config.py) that's only missing credentials.

    Appending is safe here because env_config.py never writes an [admin]
    section itself when these vars are unset - there's nothing to collide
    with or overwrite.
    """
    admin_block = "\n".join(
        [
            "",
            "[admin]",
            f"password_hash = {_toml_string(hash_password(admin_password))}",
            f"session_secret = {_toml_string(secrets.token_urlsafe(32))}",
            "session_ttl_seconds = 86400",
            "protocol_auth_enabled = true",
            "new_connections_enabled = true",
            f"protocol_login_email = {_toml_string(protocol_login_email)}",
            f"protocol_login_pin_hash = {_toml_string(hash_password(protocol_login_pin))}",
            "",
        ]
    )
    with config_file.open("a", encoding="utf-8") as handle:
        handle.write(admin_block)


def _status_html() -> str:
    return dedent(
        """\
        <!doctype html><html><body style="font-family:Segoe UI,sans-serif;max-width:520px;margin:12vh auto">
        <h1>Roborock Local Server</h1>
        <p>Setup is complete. The stack is restarting into the full dashboard at this same address -
        reload in a few seconds.</p>
        </body></html>
        """
    )


def _setup_wizard_html() -> str:
    return dedent(
        """\
        <!doctype html><html><head><meta charset="utf-8">
        <title>Roborock Local Server Setup</title>
        <style>
          body{font-family:Segoe UI,sans-serif;max-width:640px;margin:4vh auto;padding:0 16px}
          fieldset{margin-bottom:16px;border:1px solid #ccc;border-radius:6px}
          label{display:block;margin-top:8px}
          input,select{width:100%;padding:8px;box-sizing:border-box}
          .row{display:flex;gap:12px}
          .row>div{flex:1}
          button{padding:10px 16px;margin-top:16px}
          #result{white-space:pre-wrap;color:#b00020}
          #success{white-space:pre-wrap;color:#0a7a2c}
          .hidden{display:none}
        </style>
        </head><body>
        <h1>Roborock Local Server Setup</h1>
        <p>This runs once, the first time the stack boots without a config.toml. Fill this in, submit, and the
        container will restart into the full HTTPS/MQTT stack.</p>
        <form id="setup">
          <fieldset>
            <legend>Network</legend>
            <label>Stack FQDN (must start with <code>api-</code>)
              <input name="stack_fqdn" placeholder="api-roborock.example.com" required>
            </label>
            <div class="row">
              <div><label>HTTPS port<input name="https_port" type="number" value="555" required></label></div>
              <div><label>MQTT TLS port<input name="mqtt_tls_port" type="number" value="8881" required></label></div>
            </div>
          </fieldset>

          <fieldset>
            <legend>MQTT Broker</legend>
            <label><input type="radio" name="broker_mode" value="embedded" checked> Embedded (recommended)</label>
            <label><input type="radio" name="broker_mode" value="external"> Use my own broker</label>
            <div id="broker_external" class="hidden">
              <label>Broker host<input name="broker_host" placeholder="mqtt.internal"></label>
            </div>
          </fieldset>

          <fieldset>
            <legend>Certificates</legend>
            <label><input type="radio" name="tls_mode" value="cloudflare_acme" checked> Cloudflare DNS-01 auto-renew</label>
            <label><input type="radio" name="tls_mode" value="provided"> Bring my own certificate</label>
            <div id="tls_cloudflare">
              <label>Base domain / DNS zone<input name="base_domain" placeholder="example.com"></label>
              <label>ACME account email<input name="email" placeholder="acme@example.com"></label>
              <label>Cloudflare API token<input name="cloudflare_token" type="password"></label>
              <label>Certificate authority
                <select name="acme_server">
                  <option value="zerossl" selected>ZeroSSL (recommended)</option>
                  <option value="actalis">Actalis</option>
                </select>
              </label>
              <div id="acme_actalis" class="hidden">
                <label>Actalis EAB KID<input name="acme_eab_kid"></label>
                <label>Actalis EAB HMAC key<input name="acme_eab_hmac_key" type="password"></label>
              </div>
            </div>
            <div id="tls_provided" class="hidden">
              <p>Place your certificate at <code>data/certs/fullchain.pem</code> and key at
              <code>data/certs/privkey.pem</code> (relative to the compose file) before starting the stack.</p>
            </div>
          </fieldset>

          <fieldset>
            <legend>Admin Access</legend>
            <label>Admin password<input name="admin_password" type="password" required></label>
            <label>Confirm admin password<input name="admin_password_confirm" type="password" required></label>
          </fieldset>

          <fieldset>
            <legend>App / Home Assistant Login</legend>
            <label>Protocol login email<input name="protocol_login_email" placeholder="user@example.com" required></label>
            <label>Protocol login PIN (6 digits)<input name="protocol_login_pin" inputmode="numeric" maxlength="6" required></label>
            <label>Confirm PIN<input name="protocol_login_pin_confirm" inputmode="numeric" maxlength="6" required></label>
          </fieldset>

          <button type="submit">Save and start the stack</button>
        </form>
        <pre id="result"></pre>
        <pre id="success" class="hidden"></pre>
        <script>
        const form = document.getElementById("setup");
        const resultEl = document.getElementById("result");
        const successEl = document.getElementById("success");

        function toggle(radioName, mapping) {
          for (const radio of document.getElementsByName(radioName)) {
            radio.addEventListener("change", () => {
              for (const [value, elementId] of Object.entries(mapping)) {
                document.getElementById(elementId).classList.toggle("hidden", radio.value !== value && radio.checked);
              }
              for (const other of document.getElementsByName(radioName)) {
                if (other.checked) {
                  for (const [value, elementId] of Object.entries(mapping)) {
                    document.getElementById(elementId).classList.toggle("hidden", other.value !== value);
                  }
                }
              }
            });
          }
        }
        toggle("broker_mode", {external: "broker_external"});
        toggle("tls_mode", {cloudflare_acme: "tls_cloudflare", provided: "tls_provided"});
        document.querySelector('select[name="acme_server"]').addEventListener("change", (event) => {
          document.getElementById("acme_actalis").classList.toggle("hidden", event.target.value !== "actalis");
        });

        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          resultEl.textContent = "";
          successEl.classList.add("hidden");

          const data = Object.fromEntries(new FormData(form).entries());
          if (data.admin_password !== data.admin_password_confirm) {
            resultEl.textContent = "Admin password and confirmation do not match.";
            return;
          }
          if (data.protocol_login_pin !== data.protocol_login_pin_confirm) {
            resultEl.textContent = "PIN and confirmation do not match.";
            return;
          }

          const response = await fetch("/admin/api/setup", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(data),
          });
          const payload = await response.json().catch(() => ({error: "Invalid response"}));
          if (!response.ok) {
            resultEl.textContent = payload.error || "Setup failed.";
            return;
          }
          form.classList.add("hidden");
          successEl.classList.remove("hidden");
          successEl.textContent = "Saved. The stack is restarting into the full HTTPS/MQTT service - " +
            "give it a minute, then reload this page.";
        });
        </script>
        </body></html>
        """
    )


def _admin_only_wizard_html() -> str:
    return dedent(
        """\
        <!doctype html><html><head><meta charset="utf-8">
        <title>Roborock Local Server Setup</title>
        <style>
          body{font-family:Segoe UI,sans-serif;max-width:640px;margin:4vh auto;padding:0 16px}
          fieldset{margin-bottom:16px;border:1px solid #ccc;border-radius:6px}
          label{display:block;margin-top:8px}
          input{width:100%;padding:8px;box-sizing:border-box}
          button{padding:10px 16px;margin-top:16px}
          #result{white-space:pre-wrap;color:#b00020}
          #success{white-space:pre-wrap;color:#0a7a2c}
          .hidden{display:none}
        </style>
        </head><body>
        <h1>Roborock Local Server Setup</h1>
        <p>Network, broker, and certificate settings are already set (from environment variables).
        Just add admin credentials to finish setup.</p>
        <form id="setup">
          <fieldset>
            <legend>Admin Access</legend>
            <label>Admin password<input name="admin_password" type="password" required></label>
            <label>Confirm admin password<input name="admin_password_confirm" type="password" required></label>
          </fieldset>

          <fieldset>
            <legend>App / Home Assistant Login</legend>
            <label>Protocol login email<input name="protocol_login_email" placeholder="user@example.com" required></label>
            <label>Protocol login PIN (6 digits)<input name="protocol_login_pin" inputmode="numeric" maxlength="6" required></label>
            <label>Confirm PIN<input name="protocol_login_pin_confirm" inputmode="numeric" maxlength="6" required></label>
          </fieldset>

          <button type="submit">Save and start the stack</button>
        </form>
        <pre id="result"></pre>
        <pre id="success" class="hidden"></pre>
        <script>
        const form = document.getElementById("setup");
        const resultEl = document.getElementById("result");
        const successEl = document.getElementById("success");

        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          resultEl.textContent = "";
          successEl.classList.add("hidden");

          const data = Object.fromEntries(new FormData(form).entries());
          if (data.admin_password !== data.admin_password_confirm) {
            resultEl.textContent = "Admin password and confirmation do not match.";
            return;
          }
          if (data.protocol_login_pin !== data.protocol_login_pin_confirm) {
            resultEl.textContent = "PIN and confirmation do not match.";
            return;
          }

          const response = await fetch("/admin/api/setup", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(data),
          });
          const payload = await response.json().catch(() => ({error: "Invalid response"}));
          if (!response.ok) {
            resultEl.textContent = payload.error || "Setup failed.";
            return;
          }
          form.classList.add("hidden");
          successEl.classList.remove("hidden");
          successEl.textContent = "Saved. The stack is restarting into the full HTTPS/MQTT service - " +
            "give it a minute, then reload this page.";
        });
        </script>
        </body></html>
        """
    )


def create_management_app(
    *,
    config_file: Path,
    on_configured: Callable[[], None] | None = None,
) -> FastAPI:
    app = FastAPI(title="Roborock Local Server Setup", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/", response_class=HTMLResponse)
    @app.get("/admin", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        status = diagnose_config(config_file)
        if status == "ok":
            return HTMLResponse(_status_html())
        if status == "missing_admin":
            return HTMLResponse(_admin_only_wizard_html())
        return HTMLResponse(_setup_wizard_html())

    @app.get("/admin/api/setup/status")
    async def setup_status() -> JSONResponse:
        return JSONResponse({"status": diagnose_config(config_file)})

    @app.post("/admin/api/setup")
    async def submit_setup(request: Request) -> JSONResponse:
        status = diagnose_config(config_file)
        if status == "ok":
            return JSONResponse({"error": "Already configured."}, status_code=409)

        try:
            raw_body = await request.body()
            body = json.loads(raw_body or b"{}")
            if not isinstance(body, dict):
                raise ValueError("Request body must be a JSON object.")

            if status == "missing_admin":
                admin_password, protocol_login_email, protocol_login_pin = _admin_fields_from_payload(body)
                complete_admin_section(
                    config_file=config_file,
                    admin_password=admin_password,
                    protocol_login_email=protocol_login_email,
                    protocol_login_pin=protocol_login_pin,
                )
                result_config_file = config_file
            else:
                answers = _answers_from_payload(body)
                result_config_file = write_config_setup(config_file=config_file, answers=answers).config_file
        except (ValueError, FileExistsError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        if on_configured is not None:
            on_configured()
        return JSONResponse({"ok": True, "config_file": str(result_config_file)})

    return app
