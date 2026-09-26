# Home Assistant

This page covers two separate Home Assistant tasks:

- installing the local stack as a Home Assistant add-on
- connecting or repointing Home Assistant's Roborock integration to a local stack that is already running

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

### Beta add-on

**Roborock Local Server Beta** is currently unused and remains on `1.1.0-rc2`.
Install **Roborock Local Server** for the stable `1.1.0` release.

Beta and stable keep separate data. See [switching from Beta to stable](updating.md#switching-from-beta-to-stable)
if you tested an RC using the Beta add-on.

### Add-on Behavior

- The add-on always runs the embedded MQTT broker and keeps the topic bridge enabled.
- The add-on terminates TLS itself and publishes two ports: HTTPS on `https_port` and MQTT/TLS on `mqtt_tls_port`.
- Installing the add-on does **not** automatically configure or rewrite Home Assistant's Roborock integration entry.

### Certificate Locations (When Using `tls_mode = provided`)

If you use `tls_mode = provided` with existing certificates managed in Home Assistant, the add-on container has access to mounted certificate directories:

- **Official Home Assistant Let's Encrypt Add-on**: Certificates are stored in `/ssl`. Point `cert_file` and `key_file` to the `/ssl` directory:
  - `cert_file = /ssl/fullchain.pem`
  - `key_file = /ssl/privkey.pem`
- **Third-Party Certificate Add-ons (e.g., Nginx Proxy Manager)**: Certificate files are available through `/all_addon_configs/...`:
  - `cert_file = /all_addon_configs/a0d7b954_nginxproxymanager/letsencrypt/live/npm-3/fullchain.pem`
  - `key_file = /all_addon_configs/a0d7b954_nginxproxymanager/letsencrypt/live/npm-3/privkey.pem`

> [!NOTE]
> Nginx Proxy Manager is mainly useful here as a certificate source or admin/API HTTPS convenience; it does not remove the need for a reachable MQTT/TLS port. See [Reverse Proxy](reverse_proxy.md). Always verify whether your vacuum model trusts Let's Encrypt certificates or requires ZeroSSL/Actalis in [Tested Vacuums](tested_vacuums.md).

## Connect Home Assistant to The Local Stack

This applies whether your local stack is running via Docker Compose or via the Home Assistant add-on.

The Home Assistant Roborock integration includes a native configuration flow with custom server support (`Region: Manual`), eliminating the need to manually edit `.storage/core.config_entries`.

### Prerequisites

1. Ensure the local stack is running and has completed a cloud import snapshot from the same Roborock account used by your vacuum.
2. (Optional but recommended) Confirm the local protocol login works from a shell on the Home Assistant host or another machine that can reach the stack:

   ```bash
   curl -sk -X POST "https://api-roborock.example.com:555/api/v5/auth/email/login/code" \
     -H "Content-Type: application/json" \
     -d '{"email":"you@example.com","code":"123456"}'
   ```

   Replace `you@example.com` with `protocol_login_email` and `123456` with `protocol_login_pin`. A successful response includes `data.rriot.r.a`, `data.rriot.r.l`, and `data.rriot.r.m` pointing at your local stack.

### New Integration Setup (First-Time Setup)

If you are setting up the Roborock integration for the first time:

1. In Home Assistant, open **Settings** > **Devices & services**.
2. Click **Add Integration** and search for **Roborock**.
3. In the region selection dropdown, select **Manual**.
4. Enter your custom local server URL (e.g. `https://api-roborock.example.com:555`).
5. Enter your configured `protocol_login_email`.
6. Enter your 6-digit `protocol_login_pin` as the verification code.
7. Submit the flow. Home Assistant will connect to your local server, populate your devices, and establish the local MQTT connection.

### Existing Roborock Integration (Repointing from Cloud)

If your Roborock integration is already installed and connected to the official Roborock cloud, Home Assistant does not currently support changing the region in the options flow. You have two options:

#### Option 1: Remove and Re-add (Easiest, Clean Slate)

If you do not mind re-adding the integration:

1. In Home Assistant, open **Settings** > **Devices & services**.
2. Find the **Roborock** integration, click the three dots menu, and select **Delete**.
3. Click **Add Integration** and search for **Roborock**.
4. In the region dropdown, select **Manual**.
5. Enter your local server URL (e.g. `https://api-roborock.example.com:555`).
6. Enter `protocol_login_email` and your 6-digit `protocol_login_pin` code.

> [!NOTE]
> This has the normal side effects of deleting a initegration.

#### Option 2: Edit `core.config_entries` (Preserves Entity IDs, Dashboards & History)

If you would like to avoid deleting the integration, you must update the URLs in Home Assistant's configuration entries file:

> [!WARNING]
> Manually editing `.storage/core.config_entries` carries risk if edited incorrectly while Home Assistant is running. **Always take a backup of Home Assistant before modifying files in `.storage`.**

1. Ensure the local stack is running and has completed a cloud import snapshot from the same Roborock account used by Home Assistant.
2. Disable the Roborock integration in Home Assistant (or stop Home Assistant completely). Home Assistant writes to `.storage/core.config_entries` periodically while running, so ensure the integration is stopped before editing.
3. Make a backup copy of `/config/.storage/core.config_entries`.
4. Open `/config/.storage/core.config_entries` in a text editor and locate the Roborock entry (`"domain": "roborock"`).
5. Update the endpoints to point to your local stack:
   - `base_url` -> `https://api-roborock.example.com:555`
   - `"a"` -> `https://api-roborock.example.com:555`
   - `"l"` -> `https://api-roborock.example.com:555`
   - `"m"` -> `ssl://api-roborock.example.com:8881`
   - `username` -> configured `protocol_login_email`
   *(If you customized `https_port` or `mqtt_tls_port`, use those port numbers instead.)*
6. Save the file and restart Home Assistant.
7. Re-enable the Roborock integration. If prompted to re-authenticate, enter your 6-digit `protocol_login_pin` as the code.

### Troubleshooting

#### Invalid MQTT Credentials

Home Assistant derives the MQTT username and password from `rriot.u`, `rriot.s`, and `rriot.k`. Stale credentials commonly show up in the local server logs as:

```text
rejected MQTT CONNECT reason=invalid_mqtt_credentials
```

If you see this message:
- Ensure the local server has a cloud import snapshot from the same Roborock account used in Home Assistant.
- Ensure `base_url`, `rriot.r.a`, `rriot.r.l`, and `rriot.r.m` all point to your local stack.
- Trigger reauth in Home Assistant and enter `protocol_login_pin` so Home Assistant fetches updated MQTT credentials from your local server.

## Related Docs

- [Installation](installation.md)
- [Onboarding](onboarding.md)
- [Mobile App Options](roborock_app.md)
