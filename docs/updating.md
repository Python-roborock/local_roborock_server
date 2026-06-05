# Updating

Use this page when moving an existing install to a newer stable release.

## Before Updating

1. Back up your config and data directory.

   For Docker Compose installs, this usually means `config.toml`, `secrets/`, and `data/`.

   For the Home Assistant add-on, take a Home Assistant backup or copy the add-on config and any certificate files you mounted through `/all_addon_configs/...`.

2. Check the release notes or changelog for the version you are installing.

3. Keep your current `stack_fqdn`, HTTPS port, MQTT/TLS port, certificate mode, and `protocol_login_email` stable unless you intentionally want to repoint clients again.

## Updating From A Stable Or RC Release

If you were already on a stable release such as `0.0.5`, `0.0.6`, `1.0.0`, or a late release candidate, updating should usually not require manual migration.

After updating:

1. Start the stack.
2. Open `/admin`.
3. Confirm the expected vacuums are still listed.
4. Confirm Home Assistant or the Roborock app can still connect.

If Home Assistant reports MQTT credential failures after the update, run **Reconfigure** on the Roborock integration and enter your local `protocol_login_pin` again.

## Updating From An Older Main-Branch Build

If you ran an early development build from `main`, compare your config with the current `config.example.toml` in the repository root. The stable stack expects the current config shape.

In particular, check that:

- `network.stack_fqdn` is your `api-...` hostname.
- `network.https_port` and `network.mqtt_tls_port` match the ports you publish.
- `broker.mode` is either `embedded` or `external`.
- `tls.mode` is either `cloudflare_acme` or `provided`.
- `admin.password_hash`, `admin.session_secret`, `admin.protocol_login_email`, and `admin.protocol_login_pin_hash` are present.

If your config is missing required fields, the safest path is to rerun:

```bash
uv run roborock-local-server configure
```

Then copy over only the settings you intentionally want to preserve, such as the hostname, ports, certificate mode, and data directory. But I would honestly recommend starting from scratch. (you may just want to copy over the signature samples to save yourself some time)

## Docker Compose

Pull the current image or rebuild from the updated checkout:

```bash
docker compose pull
docker compose up -d
```

If you build locally instead of pulling the published image:

```bash
git pull
docker compose up -d --build
```

## Home Assistant Add-on

Update the add-on from the Home Assistant Add-on Store, then restart the add-on.

The add-on does not automatically rewrite Home Assistant's Roborock integration entry. If you changed the stack hostname or ports during the update, repeat the endpoint edit in [Home Assistant](home_assistant.md).

## After Updating

Open the admin dashboard and check:

- the server health status
- certificate status
- known vacuums
- recent HTTP and MQTT activity

If routines with zones stop behaving as expected, re-save those routines in the Roborock app so the server refreshes the zone data.
