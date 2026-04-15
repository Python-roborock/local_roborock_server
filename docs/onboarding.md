# Onboarding

Before you start, finish [Installation](installation.md) and make sure the server is reachable on your `api-...` hostname. If you want a compatibility snapshot, also check [Tested vacuums](tested_vacuums.md).

If this is a brand new vacuum, it is still a good idea to set it up once in the official Roborock app first so the app can fetch the vacuum's current metadata and confirm the firmware is up to date.

## Guided Flow

Run onboarding from a second machine, not from the machine hosting the local server:

```bash
uv run start_onboarding.py --server api-roborock.example.com
```

This is a standalone script — you can copy `start_onboarding.py` to any machine and run it with just `uv`.

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
uv run start_onboarding.py --server api-roborock.example.com --ssid "My Wifi" --password "Password123" --timezone "America/New_York" --cst EST5EDT,M3.2.0,M11.1.0 --country-domain us
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

## Web UI (start_onboarding_gui.py)

If you would rather not use the terminal, there is a web UI version of the same flow. It is a standalone script that runs a small local server on your machine and opens your browser automatically:

```bash
uv run start_onboarding_gui.py
```

No CLI flags. All configuration happens in the browser form on first load.

The main reason to use the GUI version is that this flow makes you switch your machine between your normal Wi-Fi and the vacuum's Wi-Fi hotspot several times. A browser talking to `127.0.0.1` keeps working through those switches. The CLI version can get into a bad state if a blocking network call hits while you are still on the vacuum hotspot.

### What it does on startup

1. Picks a random free port on `127.0.0.1`.
2. Generates a random per-run access token.
3. Starts a local server bound to localhost only.
4. Opens your default browser to `http://127.0.0.1:<port>/?token=<token>`.

The server is not reachable from your LAN. The token is required on every request, so other processes or browser tabs on the same machine cannot poke at it either. If the browser does not open on its own, copy the URL printed in the terminal (including the `?token=...` part) and open it manually.

### The five phases

The UI shows a stepper across the top and walks you through five phases:

1. **Configure.** Fill in the server host, admin password, your home Wi-Fi SSID and password, timezone, and country domain. The POSIX TZ string and country domain are auto-derived from the timezone if you leave them blank. Same fields as the CLI, just in a form.
2. **Select vacuum.** The script logs into the main server and lists the known vacuums with pills showing whether each has a public key, is connected, and how many query samples it has. Click one to start a session.
3. **Send onboarding.** Reset the vacuum's Wi-Fi, join its hotspot on this machine, then click "Send onboarding packet". The script sends the cfgwifi packet to `192.168.8.1` over the hotspot.
4. **Reconnect and poll.** Switch back to your normal Wi-Fi. The UI waits for the main server to become reachable again (up to two minutes), then polls every few seconds for up to five minutes. If you know you are already back online, click "I'm back online, skip the wait".
5. **Done.** The UI tells you whether to run another cycle, pick a different vacuum, or finish.

A live log pane below the stepper shows every packet, status check, and state transition. This is the same information the CLI prints to the terminal.

Your inputs live only in memory for the duration of the run and are discarded when you click Quit or shut down the server.

### Same caveats as the CLI

Everything in "What To Expect" above still applies. Some vacuums need 2-4 cycles, the Wi-Fi reset on the vacuum is still manual, and the POSIX TZ examples are the same. Only the interface changed, the underlying packet flow is identical.

### Troubleshooting

- **The browser didn't open.** Copy the URL printed in the terminal (including the `?token=...` query string) and open it manually.
- **"Onboarding send failed" right after clicking send.** You are probably not joined to the vacuum's hotspot yet, or the vacuum is not in pairing mode. Reset its Wi-Fi and try again.
- **"Could not reach the server after leaving the vacuum hotspot."** Your machine did not rejoin your normal Wi-Fi within two minutes. Check your network and click Retry.
- **The UI is stuck on "Polling...".** Give it the full five-minute timeout. If nothing changes, check the log pane for errors, then click Retry or Pick another vacuum.

## Related Docs

- [Installation](installation.md)
- [Tested vacuums](tested_vacuums.md)
- [Home Assistant](home_assistant.md)
- [Using the Roborock App](roborock_app.md)
