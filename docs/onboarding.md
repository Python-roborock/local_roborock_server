# Onboarding

Before you start, finish [Installation](installation.md) and make sure the server is reachable on your `api-...` hostname. If you want a compatibility snapshot, also check [Tested vacuums](tested_vacuums.md).

If this is a brand new vacuum, it is still a good idea to set it up once in the official Roborock app first so the app can fetch the vacuum's current metadata and confirm the firmware is up to date.

## Guided Flow

Run onboarding from a second machine, not from the machine hosting the local server:

```bash
uv run start_onboarding --server api-roborock.example.com
```

`uv run onboarding.py --server api-roborock.example.com` still works as a compatibility wrapper.

The guided CLI will:

1. Log into the main server with your admin password.
2. Show the known vacuums that can be onboarded, with status lines such as `Qrevo MaxV [Public Key Determined] [Disconnected]`.
3. Prompt for any missing local Wi-Fi details on the second machine.
4. Ask you to reset the vacuum Wi-Fi, join the vacuum's Wi-Fi network, and press Enter when ready.
5. Send the cfgwifi onboarding packet.
6. Ask you to reconnect the second machine to your normal Wi-Fi.
7. Poll the main server every 5 seconds for up to 5 minutes to see whether query samples increased, the public key was recovered, or the vacuum connected.
8. Tell you whether to retry, wait, choose a different vacuum, or finish.

You do not need to watch the admin dashboard manually during the loop anymore.

## Prompts And Defaults

The only required CLI flag is `--server`. The script will prompt for anything missing:

- `admin password`
- `ssid`
- `password`
- `timezone`
- `cst`
- `country-domain`

You can still pass them explicitly if you prefer:

```bash
uv run start_onboarding --server api-roborock.example.com --ssid "My Wifi" --password "Password123" --timezone "America/New_York" --cst EST5EDT,M3.2.0,M11.1.0 --country-domain us
```

`server` should be your real stack hostname, usually the same `api-...` hostname you use for `/admin`.

## CST Examples

Eastern Time (US): `EST5EDT,M3.2.0,M11.1.0`

Central Time (US): `CST6CDT,M3.2.0,M11.1.0`

Mountain Time (US - with DST): `MST7MDT,M3.2.0,M11.1.0`

Mountain Time (Arizona - no DST): `MST7`

Pacific Time (US): `PST8PDT,M3.2.0,M11.1.0`

London (UK): `GMT0BST,M3.5.0,M10.5.0`

Central Europe (Paris/Berlin): `CET-1CEST,M3.5.0,M10.5.0`

India (No DST): `IST-5:30`

Japan (No DST): `JST-9`

## What To Expect

- The first successful attempt usually increases the query sample count.
- If the sample count increases but the public key is still missing, run another cycle.
- Once the public key is ready, the script will tell you to do one final pairing cycle so the vacuum connects fully.
- Some vacuums need 2-4 cycles total.
- If something goes wrong, the CLI lets you `retry`, `refresh`, `reselect`, or `quit`.

You still need to reset the vacuum's Wi-Fi manually. On many Roborock models that means holding the two buttons on the dock or the left and right buttons on the vacuum for 3-5 seconds until you hear the Wi-Fi reset prompt. If you are unsure, search for your exact model's Wi-Fi reset steps.

Congrats! Once the script reports that the vacuum is connected to the local server, the onboarding flow is complete.

## Related Docs

- [Installation](installation.md)
- [Tested vacuums](tested_vacuums.md)
- [Home Assistant](home_assistant.md)
- [Using the Roborock App](roborock_app.md)
