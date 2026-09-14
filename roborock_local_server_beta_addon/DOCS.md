# Roborock Local Server Beta

This is an opt-in prerelease for testing experimental changes. Version
`1.1.0-rc2` includes V2 public-key recovery and multipart NC form parsing.
The NC fix lets the server identify the vacuum and encrypt its reply when a
recovered public key is available. Complete V2 onboarding and MQTT connectivity
still need hardware tests.

The stable **Roborock Local Server** add-on remains on `1.0.2`. Installing or
updating that add-on does not select this prerelease. Beta is a separate add-on,
with its own settings, cloud import, keys, and persistent `/data` directory.

## First installation

1. Wait until the `v1.1.0-rc2` GitHub prerelease has published its container image.
2. Add the repository `https://github.com/Python-roborock/local_roborock_server`
   in the Home Assistant add-on store if it is not already present, then refresh
   the store and install **Roborock Local Server Beta**.
3. Back up the stable add-on if installed. If reusing its hostname and ports,
   stop the stable add-on and turn off its **Start on boot** setting while testing.
   The two add-ons use the same default ports (`555` and `8881`) and cannot run
   together on those ports. Beta defaults to manual startup.
4. Enter the server hostname, ports, admin password, protocol email/PIN, and TLS
   settings in Beta's configuration. Settings and private certificate files are
   not automatically copied from the stable add-on; use certificate paths that
   Beta can access, or configure certificate issuance for Beta.
5. Start Beta, open `https://YOUR_API_HOST:555/admin` using the configured port,
   and perform cloud import so the test vacuum appears. Enable **Allow new app
   logins, onboarding, and first-time vacuum connections**.
6. On a second computer with Wi-Fi, use the onboarding scripts from the
   `v1.1.0-rc2` checkout and run:

   ```bash
   uv run start_onboarding.py --server YOUR_API_HOST:555
   ```

   Follow the model's Wi-Fi reset and hotspot prompts. The terminal tool allows
   retrying while the server still marks V2 unsupported.

## What to check

When updating from rc1, keep the existing Beta data and recovered key. Update
and restart Beta, then repeat pairing. This fix does not require a state wipe or
another public-key recovery. If you inserted a key into the state file manually,
restart the server before pairing so the live encryptor loads it.

The V2 query sample counter may remain zero because V2 uses header signatures.
Wait for **Public Key determined** in the admin dashboard, then perform another
pairing cycle and check for NC registration, authenticated MQTT traffic, status
updates, and a command response. A recovered key or HTTP 200 alone does not
establish successful onboarding. The unsupported banner remains in this build.

For the NC check, look for a `POST /nc` attributed to the correct vacuum, a
string in `response_json.result` instead of a plaintext object, and an NC step
recorded for that vacuum. These show that the server handled the request;
MQTT traffic is still needed to establish that the vacuum accepted the reply.
If pairing stops at NC, retain its content type, redacted request field names,
response shape, and MQTT/TLS logs from the same time for investigation.

Keep the saved Beta data between attempts. Report the model, firmware, Beta
version, recovery state, and furthest connection stage reached. Keep original
logs locally and redact credentials before sharing excerpts.

## Later updates and returning to stable

Subsequent prereleases appear as updates to **Roborock Local Server Beta** after
the store refreshes. Update that entry normally to keep its settings and samples.

To return to stable, stop Beta and start the stable add-on. Restore its original
start-on-boot setting if desired. Stable's saved data is retained, but changes
made while testing Beta are not copied back. A vacuum paired to Beta may need
another onboarding cycle, and clients reconfigured for Beta may need to be
reconfigured for stable again.
