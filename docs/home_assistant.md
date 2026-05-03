# Home Assistant

Use this after [Installation](installation.md) and [Onboarding](onboarding.md) if you want Home Assistant to talk to your local stack.

## Testing unpublished changes on a real Home Assistant instance

If you want Home Assistant to build your current local branch instead of pulling the published GHCR image:

1. Export a self-contained local add-on repository:
   - `uv run python scripts/export_home_assistant_dev_addon.py`
2. Copy the generated folder `dist/home_assistant_dev_addon_repo/` to your Home Assistant host under:
   - `/addons/local_roborock_server_dev_repo/`
3. In Home Assistant, open **Settings -> Add-ons -> App Store** and refresh.
4. Open the **Local add-ons** repository and install **Roborock Local Server Dev**.
5. Fill the app options and start it.

This path is for unpublished development work. It bundles your current `src/` tree into the add-on so Home Assistant can build it locally on the real device.

## Option 1: Home Assistant App (same GHCR image)

This repository contains a Home Assistant app definition at `roborock_local_server_addon/` that uses:

- `ghcr.io/python-roborock/local_roborock_server`

To install it as a custom repository:

1. In Home Assistant, go to **Settings -> Apps -> App Store -> Repositories**.
2. Add this repository URL:
   - `https://github.com/Python-roborock/local_roborock_server`
3. Install **Roborock Local Server**.
4. Fill the app options (`stack_fqdn`, `admin_password`, `protocol_login_email`, `protocol_login_pin`, TLS settings).
5. Start the app.

Then open:

- `https://<your-home-assistant-host>:555/admin` (or your configured HTTPS port)

If you need the MITM protocol sync secret for the Roborock app flow, sign in to the admin page and open the **Protocol Auth** section. The dashboard now shows the active `admin.session_secret` with a copy button, so you do not need to inspect `/data/config.toml` manually.

Important: installing the Home Assistant app does not automatically rewrite your Roborock integration entry. You still need to update `config/.storage/core.config_entries` endpoint values as shown below so Home Assistant points at your local stack.

Notes:

- The add-on terminates TLS itself and publishes two ports: HTTPS on `https_port` and MQTT/TLS on `mqtt_tls_port`.
- If you use Home Assistant's Nginx Proxy Manager add-on for certificate issuance, this add-on can read those PEM files directly through `/all_addon_configs/a0d7b954_nginxproxymanager/letsencrypt/live/...`.

## Option 2: Existing Docker deployment

If you keep using Docker Compose, edit your Home Assistant Roborock config entry at:

- `config/.storage/core.config_entries`

Find `"roborock.com"` and replace endpoint values with your local stack URLs:

- `base_url` -> `https://api-roborock.example.com:555`
- `"a"` -> `https://api-roborock.example.com:555`
- `"l"` -> `https://api-roborock.example.com:555`
- `"m"` -> `ssl://mqtt-roborock.example.com:8881`

If you changed `network.https_port` or `network.mqtt_tls_port`, use those values instead.

## Related Docs

- [Installation](installation.md)
- [Onboarding](onboarding.md)
- [Using the Roborock App](roborock_app.md)
