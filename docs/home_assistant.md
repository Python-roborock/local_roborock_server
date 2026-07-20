# Home Assistant

This page only covers the Home Assistant-specific parts. It is assumed you have already completed the shared setup steps in [Installation](installation.md).

This page covers two separate Home Assistant tasks:
- installing the local stack as a Home Assistant application (app or formerly known as add-on)
- repointing Home Assistant's Roborock integration to a local stack that is already running

## Install As A Home Assistant App

This is an installation method, not a post-install integration step. The app uses the same container image as the Docker deployment.

### Technical Details About The App
- Installing the app does **not** automatically rewrite Home Assistant's Roborock integration entry.
- Installing the app is not required to repoint Roborock integration to your local server
- The app always runs the embedded MQTT broker and keeps the topic bridge enabled.
- The app terminates TLS itself and publishes two ports: HTTPS on `https_port` and MQTT/TLS on `mqtt_tls_port`.
- If you already manage certificates in another Home Assistant app such as Nginx Proxy Manager, you can point `cert_file` and `key_file` at those PEM files through `/all_addon_configs/...`. Nginx Proxy Manager is mainly useful here as a certificate source or admin/API HTTPS convenience; it does not remove the need for a reachable MQTT/TLS port. See [Reverse Proxy](reverse_proxy.md) for more information about this setup.

### Install Steps
1. Open the Home Assistant setting, go to Apps section, click on `Install App`, then 3 dots in the top right corner, then `Repositories`.
2. Click `Add` and enter this repository:
   - `https://github.com/Python-roborock/local_roborock_server`
3. Go back to the app Store and search for **Roborock Local Server**. Install it, then click **Configuration**.
4. Fill the app options:
   - `stack_fqdn` - Domain you have set up in [Shared Setup](installation.md#network-setup)
   - `https_port` - Keep the default unless you have a specific reason to change it
   - `mqtt_tls_port` - Keep the default unless you have a specific reason to change it
   - `region` - Region to which your account is on linked (likely where you registered the Roborock app)
   - `admin_password` - Password you will later use to log in to the dashboard
   - `protocol_login_email` - Email you later use to link your Roborock device to Home Assistant
   - `protocol_login_pin` - PIN you later use to link your Roborock device to Home Assistant
   
   - TLS settings:
     - if you set `cloudflare_acme` you have to fill in:
         - `tls_base_domain`- Base domain for the certificate to be issued (the same domain you used for `stack_fqdn`)
         - `tls_email` - Any email you want to use for your ACME account registration
         - `cloudflare_token` - Cloudflare API token you created earlier 
      - if you set `provided` you have to fill in your own `cert_file` and `key_file`


   - ACME settings:
      - If you set ZeroSSL, you do not need to fill in any additional fields.
      - If you set Acatalis, you have to fill in:
         - `acme_eab_kid` - Your Actalis EAB KID
         - `acme_eab_hmac_key` - Your Actalis EAB HMAC key 

5. Go back to the **Info** tab and start the app.

If set up correctly, your local stack should be running shortly as a Home Assistant app! 
It is recomended to enable the app's **Start on boot** option so the server starts automatically after Home Assistant boots.

## Next Installation Steps
- [Installation - After the Stack Starts](installation.md#after-the-stack-starts) for post-start steps.

## Pointing The Home Assistant Roborock Integration
This applies whether your local stack is running via Docker Compose or via the Home Assistant app.

> To repoint the Roborock integration you must first link your vacuum to Home Assistant using the official Roborock login flow, without going through the local server.

1. Make sure the local stack is running and has a cloud import snapshot from the same Roborock account used by the Home Assistant integration.

2. Stop the Roborock integration in Home Assistant.
   > **Optional troubleshooting:** To confirm the local protocol login works, run this from a shell on the Home Assistant host or another machine that can reach the stack:
   > 
   > ```bash
   > curl -sk -X POST "https://api-roborock.example.com:555/api/v5/auth/email/login/code" \
   >   -H "Content-Type: application/json" \
   >   -d '{"email":"you@example.com","code":"123456"}'
   > ```
   > 
   > Replace `you@example.com` with `protocol_login_email` and `123456` with `protocol_login_pin`. A successful response includes `data.rriot.r.a`, `data.rriot.r.l`, and `data.rriot.r.m` pointing at your local stack.
   > On many Home Assistant systems this file is at `/config/.storage/core.config_entries`. The file is rewritten while Home Assistant integration is running, so make the edit while the Roborock integration is stopped.

3. Find the Roborock entry and replace the endpoint values with your local stack URLs:

   - `username` - the email configured as `protocol_login_email`
   - `base_url` - `https://api-roborock.example.com:555`
   - `"a"` - `https://api-roborock.example.com:555`
   - `"l"` - `https://api-roborock.example.com:555`
   - `"m"` - `ssl://api-roborock.example.com:8881`

   The current server advertises the same hostname for HTTPS and MQTT/TLS, so `"m"` should normally use the same `stack_fqdn`, not a separate `mqtt-...` hostname.

   > If you changed `https_port` or `mqtt_tls_port`, use those values instead.

4. Start the Roborock integration.

5. Reconfigure the Roborock integration and complete the code login:

   - The account email must be the value configured as `protocol_login_email`.
   - Use the 6 digit `protocol_login_pin` as the code.

> **Reconfigure** action should apear in the integrations section, but may not appear until Home Assistant has loaded the edited local endpoint data. If you do not see it, check that the integration was stopped while editing `.storage/core.config_entries`, then restart Home Assistant and open the integration again.

### Troubleshooting

Home Assistant derives the MQTT username and password from `rriot.u`, `rriot.s`, and `rriot.k`; stale values commonly show up in the local server logs as:

```text
rejected MQTT CONNECT reason=invalid_mqtt_credentials
```

If you see that message after reauth, try these steps:
- Check if the local server has a cloud import snapshot from the same Roborock account as the Home Assistant entry
- `base_url`, `rriot.r.a`, `rriot.r.l`, and `rriot.r.m` all point at the local stack
- Reconfigure completed with `protocol_login_email` and `protocol_login_pin`
- Lastly, try restarting Home Assistant editing `.storage/core.config_entries`


## Related Docs

- [Onboarding](onboarding.md)
- [Using the Roborock App](roborock_app.md)