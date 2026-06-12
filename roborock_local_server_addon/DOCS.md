# Roborock Local Server

This add-on runs the same `ghcr.io/python-roborock/local_roborock_server` image used for Docker installs.

It publishes two TLS ports directly:

- `555/tcp` for the Roborock HTTPS API
- `8881/tcp` for the Roborock MQTT TLS proxy

## Setup

1. Set `stack_fqdn` to your `api-...` hostname.
2. Set `admin_password`, `protocol_login_email`, and `protocol_login_pin` (6 digits).
3. Choose TLS mode:
   - `provided`: set `cert_file` and `key_file`
   - `cloudflare_acme`: set `tls_base_domain`, `tls_email`, `cloudflare_token`
4. Start the add-on.

Before choosing the TLS mode, check the tested-vacuum certificate guidance in `docs/tested_vacuums.md`. Different models may need `zerossl`, `actalis`, or your own certificate chain. For most users, prefer `zerossl`. Use `actalis` mainly for older vacuums or when your model is already known to need it.

The add-on always runs the embedded MQTT broker and keeps the topic bridge enabled.

Then open `https://api-roborock.example.com:555/admin` using your configured `stack_fqdn` and HTTPS port.

After the dashboard opens:

1. Use the admin dashboard cloud import to fetch your Roborock account data.
2. Confirm the expected vacuum appears in the inventory.
3. Run onboarding from a second machine. If you copy the onboarding scripts to that machine, keep `start_onboarding_gui.py`, `ui.html`, and `onboarding_shared.py` together for the GUI flow, or keep `start_onboarding.py` and `onboarding_shared.py` together for the CLI flow.

This add-on does not auto-edit Home Assistant's Roborock config entry. You still need to update `.storage/core.config_entries` so Home Assistant points at your local stack.

Disable the Roborock integration before editing `.storage/core.config_entries`. Update `username`, `base_url`, `rriot.r.a`, `rriot.r.l`, and `rriot.r.m`, then restart home assistant and enable the integration.

Use **Reconfigure** on the Roborock integration after Home Assistant has loaded the local endpoint data. Enter `protocol_login_email` as the account and `protocol_login_pin` as the code. If **Reconfigure** is not available yet, restart Home Assistant and reopen the integration.

## Notes

- Local-only access is still the preferred setup. If you expose it for remote access, the server handles auth and can disable new devices from connecting, but any publicly accessible self-hosted service has risk.
- If you change `https_port` or `mqtt_tls_port`, update your DNS/clients to use those ports.
- The current server advertises the same hostname for HTTPS and MQTT/TLS, so Home Assistant's Roborock entry should normally use `ssl://api-roborock.example.com:8881`, not a separate `mqtt-...` hostname.
- If you already manage certificates in another Home Assistant add-on such as Nginx Proxy Manager, you can point `cert_file` and `key_file` at that add-on's certs through `/all_addon_configs/...`. Example: `/all_addon_configs/a0d7b954_nginxproxymanager/letsencrypt/live/npm-3/fullchain.pem`.
- If a reverse proxy exposes different public ports than the add-on listeners, keep `https_port`/`mqtt_tls_port` as the add-on listener ports and set `advertised_https_port`/`advertised_mqtt_tls_port` to the public ports. The proxy must preserve the original `Host` header, and MQTT/TLS still needs a reachable port or a TCP/stream proxy.
