# Home Assistant

This page covers two separate Home Assistant tasks:

- installing the local stack as a Home Assistant add-on
- repointing Home Assistant's Roborock integration to a local stack that is already running

## Install As A Home Assistant Add-on

This is an installation method, not a post-install integration step. The add-on uses the same container image as the Docker deployment:

- `ghcr.io/python-roborock/local_roborock_server`

Before configuring the add-on, check [Tested Vacuums](tested_vacuums.md).

Different vacuums do not all trust the same certificate chains. Use that page to decide whether this install should use:

- `tls_mode = cloudflare_acme` with `acme_server = zerossl`
- `tls_mode = cloudflare_acme` with `acme_server = actalis`
- `tls_mode = provided` with your own `cert_file` and `key_file`

For most users, prefer `acme_server = zerossl`. Use `actalis` mainly for older vacuums or when the tested-vacuum guidance for your model specifically points to it.

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
     - `tls_mode = provided` with explicit `cert_file` and `key_file`
     - or `tls_mode = cloudflare_acme` with `tls_base_domain`, `tls_email`, and `cloudflare_token`
     - optional ACME CA selection with `acme_server` (`zerossl` is the preferred default for most users)
     - if `acme_server = actalis`, also set `acme_eab_kid` and `acme_eab_hmac_key`.

5. Start the add-on.

Then open the admin dashboard at your configured stack hostname, for example:

- `https://api-roborock.example.com:555/admin`

Do not use the Home Assistant UI hostname unless it is the same hostname covered by the TLS certificate you configured for `stack_fqdn`.

After the dashboard opens, complete the same post-start steps as the Docker install:

1. Use the admin dashboard cloud import to fetch your Roborock account data.
2. Confirm the expected vacuum appears in the inventory.
3. Run [Onboarding](onboarding.md) from a second machine to pair the vacuum to the local stack.

If you need the MITM protocol sync secret for the Roborock app flow, sign in to the admin page and open **Protocol Auth**. The dashboard shows the active `admin.session_secret`, so you do not need to inspect `/data/config.toml` manually.

### Add-on Behavior

- The add-on always runs the embedded MQTT broker and keeps the topic bridge enabled.
- The add-on terminates TLS itself and publishes two ports: HTTPS on `https_port` and MQTT/TLS on `mqtt_tls_port`.
- If you already manage certificates in another Home Assistant add-on such as Nginx Proxy Manager, you can point `cert_file` and `key_file` at those PEM files through `/all_addon_configs/...`.
- Installing the add-on does **not** automatically rewrite Home Assistant's Roborock integration entry.

## Repoint The Home Assistant Roborock Integration

This applies whether your local stack is running via Docker Compose or via the Home Assistant add-on.

### Existing Roborock Integration

Use this flow when the Roborock integration already exists in Home Assistant.

1. Make sure the local stack is running and has a cloud import snapshot from the same Roborock account used by the Home Assistant integration.

2. OPTIONAL but useful: confirm the local protocol login works from a shell on the Home Assistant host or another machine that can reach the stack:

   ```bash
   curl -sk -X POST "https://api-roborock.example.com:555/api/v5/auth/email/login/code" \
     -H "Content-Type: application/json" \
     -d '{"email":"you@example.com","code":"123456"}'
   ```

   Replace `you@example.com` with `protocol_login_email` and `123456` with `protocol_login_pin`. A successful response includes `data.rriot.r.a`, `data.rriot.r.l`, and `data.rriot.r.m` pointing at your local stack.

3. Disable the Roborock integration in Home Assistant.

   On many Home Assistant systems this file is at `/config/.storage/core.config_entries`. The file is rewritten while Home Assistant is running, so make the edit while the Roborock integration is stopped.

5. Find the Roborock entry and replace the endpoint values with your local stack URLs:

   - `username` -> the email configured as `protocol_login_email` (you likely don't need to change this)
   - `base_url` -> `https://api-roborock.example.com:555`
   - `"a"` -> `https://api-roborock.example.com:555`
   - `"l"` -> `https://api-roborock.example.com:555`
   - `"m"` -> `ssl://api-roborock.example.com:8881`

   The current server advertises the same hostname for HTTPS and MQTT/TLS, so `"m"` should normally use the same `stack_fqdn`, not a separate `mqtt-...` hostname.

6. If you changed `https_port` or `mqtt_tls_port`, use those values instead.

7. Restart Home Assistant (Or start it if you had it stopped).

8. Enable the Roborock integration.

9. Reconfigure the Roborock integration and complete the code login:

   - The account email must be the value configured as `protocol_login_email`.
   - Use the 6 digit `protocol_login_pin` as the code.

   Reauth updates the stored Roborock `user_data`, including the MQTT credentials derived from `rriot`.

The **Reconfigure** action may not appear until Home Assistant has loaded the edited local endpoint data. If you do not see it, check that the integration was stopped while editing `.storage/core.config_entries`, then restart Home Assistant and open the integration again.

### First Time Home Assistant Setup

Home Assistant currently creates a Roborock config entry through the official Roborock login flow. If you have never added the Roborock integration before:

1. Add the Roborock integration once with the official Roborock API.
2. Disable the integration.
3. Edit `.storage/core.config_entries` as described above.
4. Start Home Assistant, enable the integration, then run **Reconfigure** and enter your local PIN.

Home Assistant derives the MQTT username and password from `rriot.u`, `rriot.s`, and `rriot.k`; stale values commonly show up in the local server logs as:

```text
rejected MQTT CONNECT reason=invalid_mqtt_credentials
```

If you see that message after reauth, check that:

- the local server has a cloud import snapshot from the same Roborock account as the Home Assistant entry
- `base_url`, `rriot.r.a`, `rriot.r.l`, and `rriot.r.m` all point at the local stack
- Home Assistant was fully restarted after editing `.storage/core.config_entries`
- Reconfigure completed with `protocol_login_email` and `protocol_login_pin`

## Related Docs

- [Installation](installation.md)
- [Onboarding](onboarding.md)
- [Using the Roborock App](roborock_app.md)
