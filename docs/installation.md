# Installation

Start here for a first-time setup. After the stack is running, continue with [Onboarding](onboarding.md) to pair a vacuum.

## Requirements

- Docker with `docker compose`
- Python (I recommend installing [uv](https://docs.astral.sh/uv/getting-started/installation/))
- Two machines - one to run the server and one to do the onboarding
- A domain name that you own
- A machine that can host this with ports `443` and `8883` exposed internally on your network
- A Cloudflare API token with DNS edit access for the zone if you want Cloudflare DNS-01 auto-renew. See [Cloudflare setup](cloudflare_setup.md).

## Network Setup

1. Pick a URL for this application. It needs to be a subdomain of a domain you own, and it **must** start with `api-`. It does NOT need to be accessible outside your network - in fact, I strongly recommend you keep it internal only for now.

   For example, if you own `example.com`, I'd recommend `api-roborock.example.com`. Throughout the rest of the docs we'll refer to this as the **FQDN**. If you follow this format, you can just replace `example.com` with your real domain wherever you see it.

2. Your network **must** handle its own DNS for the network the vacuum connects to. If it uses an external DNS server like `8.8.8.8`, this will not work.

3. Create DNS records pointing to your server's local IP address for both `api-roborock.example.com` and `mqtt-roborock.example.com`.

## Docker Setup

1. Clone this repository:

`git clone https://github.com/Python-roborock/local_roborock_server`

2. Change into the project folder.

```bash
cd local_roborock_server
```

3. Install the project dependencies.

```bash
uv sync
```

4. Run the setup wizard.

```bash
uv run roborock-local-server configure
```

The wizard asks only for:

- your `stack_fqdn` (the URL for your server - must start with `api-`)
- embedded MQTT or your own broker
- whether to use Cloudflare DNS-01 auto-renew
- your admin password

It then writes `config.toml`, generates `admin.password_hash` and `admin.session_secret`, and if you chose Cloudflare it also writes `secrets/cloudflare_token`.

5. If you chose external MQTT, fill in `broker.host` in `config.toml` before starting the stack. See [Custom MQTT](custom_mqtt.md).

6. If you skipped Cloudflare, put your certificate files in `data/certs/fullchain.pem` and `data/certs/privkey.pem`. See [Custom certificate management](custom_cert_management.md).

7. Start the container:

   ```bash
   docker compose up -d --build
   ```

8. Go to the admin dashboard: https://api-roborock.example.com/admin (Replace with your real domain.)

9. Import your data from the cloud so things like routines and rooms will work. Enter your email in under cloud import, then hit send code. Once the code is returned enter the code and hit fetch data.

10. For any routines that use zones, you need to re-save them so the server stores the zone data correctly. In the Roborock app, open each routine that has zones, click on the zone, tap **Edit**, click on any **Zone Cleaning** entry, then tap **Save**. Repeat for each zone in the routine.

## Next Steps

- [Onboarding](onboarding.md) for pairing a new vacuum.
- [Home Assistant](home_assistant.md) if you want the local stack in Home Assistant.
- [Using the Roborock App](roborock_app.md) if you want to point the official app at your local stack.
- [Docs index](index.md) for the rest of the guides.
