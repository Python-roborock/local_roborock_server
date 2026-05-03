# Home Assistant

This page covers two separate Home Assistant tasks:

- installing the local stack as a Home Assistant add-on
- repointing Home Assistant's Roborock integration to a local stack that is already running

## Install As A Home Assistant Add-on

This is an installation method, not a post-install integration step. The add-on uses the same container image as the Docker deployment:

- `ghcr.io/python-roborock/local_roborock_server`

### Install Steps

1. Open the Home Assistant Add-on Store.
2. Add this repository under **Repositories**:

   - `https://github.com/Python-roborock/local_roborock_server`

3. Install **Roborock Local Server**.
4. Fill the add-on options:

   - `stack_fqdn`
   - `https_port`
   - `mqtt_tls_port`
   - `region`
   - `admin_password`
   - `protocol_login_email`
   - `protocol_login_pin`
   - TLS settings:
     - `tls_mode = provided` with `cert_file` and `key_file`
     - or `tls_mode = cloudflare_acme` with `tls_base_domain`, `tls_email`, and `cloudflare_token`

5. Start the add-on.

Then open the admin dashboard at your configured stack hostname, for example:

- `https://api-roborock.example.com:555/admin`

Do not use the Home Assistant UI hostname unless it is the same hostname covered by the TLS certificate you configured for `stack_fqdn`.

If you need the MITM protocol sync secret for the Roborock app flow, sign in to the admin page and open **Protocol Auth**. The dashboard shows the active `admin.session_secret`, so you do not need to inspect `/data/config.toml` manually.

### Add-on Behavior

- The add-on always runs the embedded MQTT broker and keeps the topic bridge enabled.
- The add-on terminates TLS itself and publishes two ports: HTTPS on `https_port` and MQTT/TLS on `mqtt_tls_port`.
- If you already manage certificates in another Home Assistant add-on such as Nginx Proxy Manager, you can point `cert_file` and `key_file` at those PEM files through `/all_addon_configs/...`.
- Installing the add-on does **not** automatically rewrite Home Assistant's Roborock integration entry.

## Repoint The Home Assistant Roborock Integration

This applies whether your local stack is running via Docker Compose or via the Home Assistant add-on.

1. Open your Home Assistant configuration directory and locate `.storage/core.config_entries`.

   On many Home Assistant systems this file is at `/config/.storage/core.config_entries`.

2. Find the Roborock entry and replace the endpoint values with your local stack URLs:

   - `base_url` -> `https://api-roborock.example.com:555`
   - `"a"` -> `https://api-roborock.example.com:555`
   - `"l"` -> `https://api-roborock.example.com:555`
   - `"m"` -> `ssl://api-roborock.example.com:8881`

   The current server advertises the same hostname for HTTPS and MQTT/TLS, so `"m"` should normally use the same `stack_fqdn`, not a separate `mqtt-...` hostname.

3. If you changed `https_port` or `mqtt_tls_port`, use those values instead.

4. Restart Home Assistant so the integration reloads the updated endpoints.

## Related Docs

- [Installation](installation.md)
- [Onboarding](onboarding.md)
- [Using the Roborock App](roborock_app.md)
