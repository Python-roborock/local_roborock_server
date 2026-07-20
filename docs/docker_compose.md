# Docker Compose installation

This page only covers the Docker Compose-specific parts. It is assumed you have already completed the shared setup steps in [installation.md](installation.md) and have a working hostname and DNS.

> Advanced users can use the container image directly from:
`ghcr.io/python-roborock/local_roborock_server`

 ### Additional Requirements
- Docker with `docker compose`
- Python
- [uv](https://docs.astral.sh/uv/getting-started/installation/)

### Steps
1. Clone this repository:

   ```bash
   git clone https://github.com/Python-roborock/local_roborock_server
   cd local_roborock_server
   ```

2. Install the project dependencies:

   ```bash
   uv sync
   ```

3. Run the setup wizard:

   ```bash
   uv run roborock-local-server configure
   ```

 * The wizard asks for your:
   - `stack_fqdn` which you have set up in [Shared Setup](installation.md#network-setup)
   - HTTPS and MQTT TLS ports (it is recommended to keep the defaults unless you have a specific reason to change them)
   - Whether to use the embedded MQTT broker or your own (see [Custom MQTT](custom_mqtt.md))
   - Whether to use Cloudflare DNS-01 auto-renew
      If yes, the setup ask for:
      - The `ACME domain` (domain for the certificate to be issued) and `account email` (any email you want to use for ACME account registration)
      - Whether to use ZeroSSL or Actalis.
         - If you chose Actalis, the setup asks for your Actalis `EAB KID` and `EAB HMAC key`. 
      - Your `Cloudflare API token` you created earlier.
   - An admin password you will use to log in to the admin dashboard
   - A Home Assistant/app login email and 6-digit PIN which can be used to repoint Home Assistant or the Roborock app to your local server.

 The wizard then creates `config.toml`, generates `admin.password_hash` and `admin.session_secret`. Depending whether or not you chose Cloudflare it writes `secrets/cloudflare_token` and if you set your `acme_server = actalis`, it also writes `secrets/acme_eab_kid` and `secrets/acme_eab_hmac_key`.

> If you chose external MQTT, fill in `broker.host` in `config.toml` before starting the stack.

> If you skipped Cloudflare, put your certificate files in `data/certs/fullchain.pem` and `data/certs/privkey.pem`. This is the path to use when your vacuum works better with a certificate chain you manage yourself. See [Custom certificate management](custom_cert_management.md).

4. Starting the container:
   If you set your custom ports during the setup, set matching Docker Compose variables before you start the stack so the published ports stay aligned. For example:

   ```bash
   ROBOROCK_SERVER_HTTPS_PORT=8443
   ROBOROCK_SERVER_MQTT_TLS_PORT=9443
   ```

   In PowerShell:

   ```powershell
   $env:ROBOROCK_SERVER_HTTPS_PORT = "8443"
   $env:ROBOROCK_SERVER_MQTT_TLS_PORT = "9443"
   ```

   > In custom setups where decided to run a reverse proxy, keep `network.https_port` and `network.mqtt_tls_port` set to the backend listener ports and use `network.advertised_https_port` / `network.advertised_mqtt_tls_port` for the public ports.

After all is done, you can start the stack with:
 ```bash
   docker compose up -d --build
   ```

## Test your installation
To test your installation, open a browser and go to `https://api-roborock.example.com:555/admin` (or your custom HTTPS port). You should see the admin dashboard login page.

If you chose Cloudflare DNS-01 auto-renew, it may take a few minutes for the certificate to be issued. If the page does not load after a few minutes, check that the DNS resolves correctly and the stack is running: 

```bash
docker compose ps #check if the stack is running
docker compose logs -f roborock-local-server #check the logs for errors
``` 

## Next Steps
- [Installation - After the Stack Starts](installation.md#after-the-stack-starts) for post-start steps.

## Related Guides
- [Updating](updating.md) for upgrading an existing instal
- [Home Assistant](home_assistant.md#repoint-the-home-assistant-roborock-integration) if you want to repoint the Home Assistant Roborock integration to your local stack
- [Onboarding](onboarding.md) for pairing a new vacuum
- [Using the Roborock App](roborock_app.md) if you want to point the official app at your local stackl
- [Docs index](index.md) for the rest of the guides
