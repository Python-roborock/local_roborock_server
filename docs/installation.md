# Installation

Start here for a first-time setup. The project supports two installation methods:

- Docker Compose on your own Linux host or VM
- the Home Assistant add-on from this repository

After the stack is running, continue with [Onboarding](onboarding.md) to pair a vacuum.

## Shared Requirements

- A domain name that you own
- A place to run the stack on your LAN
- A second machine for onboarding later
- A network that can host the stack's HTTPS and MQTT TLS ports internally. The defaults are `555` and `8881`.
- A Cloudflare API token with DNS edit access for the zone if you want Cloudflare DNS-01 auto-renew. See [Cloudflare setup](cloudflare_setup.md).

## Network Setup

1. Pick a hostname for this application. It must be a subdomain of a domain you own, and it **must** start with `api-`.

   For example, if you own `example.com`, use `api-roborock.example.com`. Throughout the docs this is the **stack FQDN**.

2. Your network **must** handle its own DNS for the network the vacuum connects to. If it uses an external DNS server like `8.8.8.8`, this will not work.

3. Create a DNS record pointing your stack FQDN to the local IP of the machine running the stack.

   With the current server behavior, the same hostname is advertised for both HTTPS and MQTT/TLS, so you do not need a separate `mqtt-...` hostname unless you have built your own custom client routing around one.

## Method 1: Docker Compose

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

   The wizard asks for:

   - `stack_fqdn` (must start with `api-`)
   - HTTPS and MQTT TLS ports if you do not want the defaults `555` and `8881`
   - embedded MQTT or your own broker
   - whether to use Cloudflare DNS-01 auto-renew
   - your admin password
   - your Home Assistant/app login email and 6-digit PIN

   It then writes `config.toml`, generates `admin.password_hash` and `admin.session_secret`, and if you chose Cloudflare it also writes `secrets/cloudflare_token`. If you also chose `acme_server = actalis`, it writes `secrets/acme_eab_kid` and `secrets/acme_eab_hmac_key`.

4. If you chose external MQTT, fill in `broker.host` in `config.toml` before starting the stack. See [Custom MQTT](custom_mqtt.md).

5. If you skipped Cloudflare, put your certificate files in `data/certs/fullchain.pem` and `data/certs/privkey.pem`. See [Custom certificate management](custom_cert_management.md).

6. Start the container:

   ```bash
   docker compose up -d --build
   ```

   If you changed `network.https_port` or `network.mqtt_tls_port` in `config.toml`, set matching Docker Compose variables before you start the stack so the published ports stay aligned. For example:

   ```bash
   ROBOROCK_SERVER_HTTPS_PORT=8443
   ROBOROCK_SERVER_MQTT_TLS_PORT=9443
   docker compose up -d --build
   ```

## Method 2: Home Assistant Add-on

Use [Home Assistant](home_assistant.md) as the installation guide if you want to run the stack as a Home Assistant add-on instead of Docker Compose.

## After The Stack Starts

1. Open the admin dashboard at `https://api-roborock.example.com:555/admin` by default, or `https://api-roborock.example.com:YOUR_HTTPS_PORT/admin` if you chose a custom HTTPS port.

2. Import your data from the cloud so things like routines and rooms will work. Enter your email under cloud import, select **Send code**, then enter the returned code and select **Fetch data**.

3. For any routines that use zones, re-save them so the server stores the zone data correctly. In the Roborock app, open each routine that has zones, open the zone, tap **Edit**, open any **Zone Cleaning** entry, then tap **Save**. Repeat for each zone in the routine.

## Next Steps

- [Onboarding](onboarding.md) for pairing a new vacuum
- [Home Assistant](home_assistant.md) if you want to repoint Home Assistant's Roborock integration to your local stack
- [Using the Roborock App](roborock_app.md) if you want to point the official app at your local stack
- [Docs index](index.md) for the rest of the guides
