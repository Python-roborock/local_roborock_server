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
from .web_theme import HEAD_ASSETS, NAV_HTML, SCRIPT_ASSETS, register_theme_routes

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
            <div class="container">
              <h4 class="header orange-text">Setup is complete</h4>
              <p>The stack is restarting into the full dashboard at this same address - reload in a few
              seconds.</p>
            </div>
            """
        )
        + SCRIPT_ASSETS
        + "\n</body></html>\n"
    )


_WIZARD_SCRIPT_HEAD = dedent(
    """\
    <script>
    const form = document.getElementById("setup");
    const resultEl = document.getElementById("result");
    const successEl = document.getElementById("success");

    function showResult(text) {
      resultEl.textContent = text;
      resultEl.classList.toggle("shown", Boolean(text));
    }
    function showSuccess(text) {
      successEl.textContent = text;
      successEl.classList.toggle("shown", Boolean(text));
    }
    """
)

_WIZARD_SCRIPT_SUBMIT_COMMON = dedent(
    """\
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      showResult("");
      showSuccess("");

      const data = Object.fromEntries(new FormData(form).entries());
      if (data.admin_password !== data.admin_password_confirm) {
        showResult("Admin password and confirmation do not match.");
        return;
      }
      if (data.protocol_login_pin !== data.protocol_login_pin_confirm) {
        showResult("PIN and confirmation do not match.");
        return;
      }

      const response = await fetch("/admin/api/setup", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(data),
      });
      const payload = await response.json().catch(() => ({error: "Invalid response"}));
      if (!response.ok) {
        showResult(payload.error || "Setup failed.");
        return;
      }
      form.classList.add("hidden");
      showSuccess("Saved. The stack is restarting into the full HTTPS/MQTT service - " +
        "give it a minute, then reload this page.");
    });
    </script>
    """
)


def _setup_wizard_html() -> str:
    return (
        dedent(
            """\
            <!doctype html><html><head><meta charset="utf-8">
            <title>Roborock Local Server Setup</title>
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
            <div class="container">
            <p class="rls-muted">This runs once, the first time the stack boots without a config.toml. Fill
            this in, submit, and the container will restart into the full HTTPS/MQTT stack.</p>
            <form id="setup">
              <h5 class="header orange-text">Network</h5>
              <div class="row">
                <div class="input-field col s12">
                  <input id="stack_fqdn" name="stack_fqdn" type="text" required>
                  <label for="stack_fqdn">Stack FQDN (must start with api-)</label>
                </div>
              </div>
              <div class="row">
                <div class="input-field col s6">
                  <input id="https_port" name="https_port" type="number" value="555" required>
                  <label for="https_port" class="active">HTTPS port</label>
                </div>
                <div class="input-field col s6">
                  <input id="mqtt_tls_port" name="mqtt_tls_port" type="number" value="8881" required>
                  <label for="mqtt_tls_port" class="active">MQTT TLS port</label>
                </div>
              </div>
              <div class="divider"></div>

              <h5 class="header orange-text">MQTT Broker</h5>
              <p>
                <label><input class="with-gap" name="broker_mode" type="radio" value="embedded" checked /><span>Embedded (recommended)</span></label>
              </p>
              <p>
                <label><input class="with-gap" name="broker_mode" type="radio" value="external" /><span>Use my own broker</span></label>
              </p>
              <div id="broker_external" class="row hidden">
                <div class="input-field col s12">
                  <input id="broker_host" name="broker_host" type="text">
                  <label for="broker_host">Broker host</label>
                </div>
              </div>
              <div class="divider"></div>

              <h5 class="header orange-text">Certificates</h5>
              <p>
                <label><input class="with-gap" name="tls_mode" type="radio" value="cloudflare_acme" checked /><span>Cloudflare DNS-01 auto-renew</span></label>
              </p>
              <p>
                <label><input class="with-gap" name="tls_mode" type="radio" value="provided" /><span>Bring my own certificate</span></label>
              </p>
              <div id="tls_cloudflare">
                <div class="row">
                  <div class="input-field col s12">
                    <input id="base_domain" name="base_domain" type="text">
                    <label for="base_domain">Base domain / DNS zone</label>
                  </div>
                </div>
                <div class="row">
                  <div class="input-field col s6">
                    <input id="email" name="email" type="email">
                    <label for="email">ACME account email</label>
                  </div>
                  <div class="input-field col s6">
                    <input id="cloudflare_token" name="cloudflare_token" type="password">
                    <label for="cloudflare_token">Cloudflare API token</label>
                  </div>
                </div>
                <div class="row">
                  <div class="input-field col s12">
                    <select name="acme_server" id="acme_server">
                      <option value="zerossl" selected>ZeroSSL (recommended)</option>
                      <option value="actalis">Actalis</option>
                    </select>
                    <label>Certificate authority</label>
                  </div>
                </div>
                <div id="acme_actalis" class="row hidden">
                  <div class="input-field col s6">
                    <input id="acme_eab_kid" name="acme_eab_kid" type="text">
                    <label for="acme_eab_kid">Actalis EAB KID</label>
                  </div>
                  <div class="input-field col s6">
                    <input id="acme_eab_hmac_key" name="acme_eab_hmac_key" type="password">
                    <label for="acme_eab_hmac_key">Actalis EAB HMAC key</label>
                  </div>
                </div>
              </div>
              <p id="tls_provided" class="hidden rls-muted">
                Place your certificate at <code>data/certs/fullchain.pem</code> and key at
                <code>data/certs/privkey.pem</code> (relative to the compose file) before starting the stack.
              </p>
              <div class="divider"></div>

              <h5 class="header orange-text">Admin Access</h5>
              <div class="row">
                <div class="input-field col s6">
                  <input id="admin_password" name="admin_password" type="password" required>
                  <label for="admin_password">Admin password</label>
                </div>
                <div class="input-field col s6">
                  <input id="admin_password_confirm" name="admin_password_confirm" type="password" required>
                  <label for="admin_password_confirm">Confirm admin password</label>
                </div>
              </div>
              <div class="divider"></div>

              <h5 class="header orange-text">App / Home Assistant Login</h5>
              <div class="row">
                <div class="input-field col s12">
                  <input id="protocol_login_email" name="protocol_login_email" type="email" required>
                  <label for="protocol_login_email">Protocol login email</label>
                </div>
              </div>
              <div class="row">
                <div class="input-field col s6">
                  <input id="protocol_login_pin" name="protocol_login_pin" type="text" inputmode="numeric" maxlength="6" required>
                  <label for="protocol_login_pin">Protocol login PIN (6 digits)</label>
                </div>
                <div class="input-field col s6">
                  <input id="protocol_login_pin_confirm" name="protocol_login_pin_confirm" type="text" inputmode="numeric" maxlength="6" required>
                  <label for="protocol_login_pin_confirm">Confirm PIN</label>
                </div>
              </div>

              <button class="btn waves-effect waves-light" type="submit">
                Save and start the stack<i class="material-icons right">rocket_launch</i>
              </button>
            </form>
            <div id="result" class="alert-banner error"></div>
            <div id="success" class="alert-banner success"></div>
            </div>
            """
        )
        + SCRIPT_ASSETS
        + "\n"
        + _WIZARD_SCRIPT_HEAD
        + dedent(
            """\
            document.addEventListener("DOMContentLoaded", () => {
              M.FormSelect.init(document.querySelectorAll("select"));
              M.updateTextFields();
            });

            function toggle(radioName, mapping) {
              for (const radio of document.getElementsByName(radioName)) {
                radio.addEventListener("change", () => {
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
            document.getElementById("acme_server").addEventListener("change", (event) => {
              document.getElementById("acme_actalis").classList.toggle("hidden", event.target.value !== "actalis");
            });

            """
        )
        + _WIZARD_SCRIPT_SUBMIT_COMMON
        + "</body></html>\n"
    )


def _admin_only_wizard_html() -> str:
    return (
        dedent(
            """\
            <!doctype html><html><head><meta charset="utf-8">
            <title>Roborock Local Server Setup</title>
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
            <div class="container">
            <p class="rls-muted">Network, broker, and certificate settings are already set (from environment
            variables). Just add admin credentials to finish setup.</p>
            <form id="setup">
              <h5 class="header orange-text">Admin Access</h5>
              <div class="row">
                <div class="input-field col s6">
                  <input id="admin_password" name="admin_password" type="password" required>
                  <label for="admin_password">Admin password</label>
                </div>
                <div class="input-field col s6">
                  <input id="admin_password_confirm" name="admin_password_confirm" type="password" required>
                  <label for="admin_password_confirm">Confirm admin password</label>
                </div>
              </div>
              <div class="divider"></div>

              <h5 class="header orange-text">App / Home Assistant Login</h5>
              <div class="row">
                <div class="input-field col s12">
                  <input id="protocol_login_email" name="protocol_login_email" type="email" required>
                  <label for="protocol_login_email">Protocol login email</label>
                </div>
              </div>
              <div class="row">
                <div class="input-field col s6">
                  <input id="protocol_login_pin" name="protocol_login_pin" type="text" inputmode="numeric" maxlength="6" required>
                  <label for="protocol_login_pin">Protocol login PIN (6 digits)</label>
                </div>
                <div class="input-field col s6">
                  <input id="protocol_login_pin_confirm" name="protocol_login_pin_confirm" type="text" inputmode="numeric" maxlength="6" required>
                  <label for="protocol_login_pin_confirm">Confirm PIN</label>
                </div>
              </div>

              <button class="btn waves-effect waves-light" type="submit">
                Save and start the stack<i class="material-icons right">rocket_launch</i>
              </button>
            </form>
            <div id="result" class="alert-banner error"></div>
            <div id="success" class="alert-banner success"></div>
            </div>
            """
        )
        + SCRIPT_ASSETS
        + "\n"
        + _WIZARD_SCRIPT_HEAD
        + _WIZARD_SCRIPT_SUBMIT_COMMON
        + "</body></html>\n"
    )


def create_management_app(
    *,
    config_file: Path,
    on_configured: Callable[[], None] | None = None,
) -> FastAPI:
    app = FastAPI(title="Roborock Local Server Setup", docs_url=None, redoc_url=None, openapi_url=None)
    register_theme_routes(app)

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
