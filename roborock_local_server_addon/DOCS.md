# Roborock Local Server

This app runs the same `ghcr.io/python-roborock/local_roborock_server` image used for Docker installs.

It publishes two TLS ports directly:

- `555/tcp` for the Roborock HTTPS API
- `8881/tcp` for the Roborock MQTT TLS proxy

## Setup

1. Set `stack_fqdn` to your `api-...` hostname.
2. Set `admin_password`, `protocol_login_email`, and `protocol_login_pin` (6 digits).
3. Choose TLS mode:
   - `provided`: set `cert_file` and `key_file` (defaults: `/ssl/fullchain.pem`, `/ssl/privkey.pem`)
   - `cloudflare_acme`: set `tls_base_domain`, `tls_email`, `cloudflare_token`
4. Start the app.

The add-on always runs the embedded MQTT broker and keeps the topic bridge enabled.

Then open `https://<home-assistant-host>:555/admin` (or your custom HTTPS port).

This app package does not auto-edit Home Assistant's Roborock config entry. You still need to update `config/.storage/core.config_entries` endpoint values to your local stack URLs.

## Notes

- This app expects internal LAN-only usage. Do not expose directly to the internet.
- If you change `https_port` or `mqtt_tls_port`, update your DNS/clients to use those ports.
- If you already manage certificates in another Home Assistant app such as Nginx Proxy Manager, you can point `cert_file` and `key_file` at that app's certs through `/all_addon_configs/...`. Example: `/all_addon_configs/a0d7b954_nginxproxymanager/letsencrypt/live/npm-3/fullchain.pem`.
