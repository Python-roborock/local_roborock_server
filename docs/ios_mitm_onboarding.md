# Roborock Local Server: macOS iPhone MITM Login Helper

An interactive Bash wrapper for the **official Roborock iOS app** login procedure used with [Python-roborock/local_roborock_server](https://github.com/Python-roborock/local_roborock_server).

**Status:** Community-contributed Bash helper, tested successfully on my Mac. It guides the existing onboarding procedure, launches and stops the temporary MITM server, and opens its authenticated browser interface. It is not an installer. Compatibility with other environments has not been confirmed.

## What this does

Once a vacuum has already been provisioned to Roborock Local Server, the official iOS app may need a one-time intercepted login so that its protocol authentication session can be synchronized to the local server. This helper walks the operator through that temporary process on a **Mac**:

- Checks whether the iPhone already trusts the Mac's mitmproxy CA.
- If needed, finds or generates the CA certificate on the Mac, opens it in Finder, and instructs the operator to AirDrop it to the iPhone.
- Coordinates obtaining the Roborock email verification code **before** enabling the WireGuard tunnel.
- Preflights the local server's protocol-sync endpoint and secret.
- Starts the repository's `mitm_redirect.py` with the explicit HTTPS endpoint, including `:443` when a reverse proxy terminates TLS on port 443.
- Presents a nine-step terminal wizard with ANSI colors, Unicode-bordered panels, progress indicators, and confirmation prompts.
- Opens the authenticated mitmweb capture interface on the Mac.
- Guides replacement of the Roborock MITM WireGuard tunnel and manual verification-code submission.
- Waits for manual confirmation that robot status and map work, then verifies the app again with WireGuard **off**.
- Stops the temporary MITM process and reminds the operator to disable trust in the temporary CA.

**This is not vacuum Wi-Fi onboarding.** First complete the upstream [Installation](https://github.com/Python-roborock/local_roborock_server/blob/main/docs/installation.md) and [Onboarding](https://github.com/Python-roborock/local_roborock_server/blob/main/docs/onboarding.md) instructions. This helper supplements the [Official Roborock App](https://github.com/Python-roborock/local_roborock_server/blob/main/docs/roborock_app.md) section.

## Requirements

- macOS computer with Bash, `curl`, `open`, and [`uv`](https://docs.astral.sh/uv/).
- A checkout of `local_roborock_server` or a directory containing its `mitm_redirect.py`, `pyproject.toml`, and `uv.lock`.
- The companion `roborock_onboard.sh` script, placed beside `mitm_redirect.py`.
- An operational Roborock Local Server instance, with vacuum already paired and account data imported.
- A valid HTTPS hostname for the local server, reachable from the Mac.
- Current **Protocol Auth / `admin.session_secret`** from the *running* server's admin dashboard.
- An iPhone with the official Roborock app and WireGuard installed, and the ability to receive the Roborock login email.
- AirDrop between the Mac and iPhone, if the CA is not already installed.

The hostname prompt expects a hostname without a port; the MITM launch explicitly appends `:443`. The script assumes the server's protocol-sync callback is accessible at `https://<your-hostname>:443/internal/protocol/user-data`. This matches one tested reverse-proxy layout; other port arrangements need script adjustments.

## Files

```text
local_roborock_server/
├── roborock_onboard.sh        # Community helper; add this file
├── mitm_redirect.py           # Upstream script
├── pyproject.toml             # Upstream dependencies
├── uv.lock                    # Upstream lockfile
└── ...
```

The Bash wrapper is not a replacement for `mitm_redirect.py`. If your local Python file has a development filename such as `mitm_redirect_fixed_v2.py`, confirm it is compatible and rename/copy it to `mitm_redirect.py` before running the wrapper.

## Quick start

From the directory containing the scripts:

```bash
chmod +x roborock_onboard.sh
./roborock_onboard.sh
```

The script prompts for your HTTPS hostname and current protocol-sync secret on first use. It stores them in `.roborock_onboard.conf` with permissions `0600`. **That file contains a sensitive credential:** do not commit, upload, share, or back it up to an untrusted location. Add `.roborock_onboard.conf`, `.roborock_mitm.pid`, and `roborock_mitm.log` to `.gitignore` before publishing the helper.

Other commands:

```bash
./roborock_onboard.sh status   # Check for the expected MITM process
./roborock_onboard.sh stop     # Stop a tracked/recognized MITM process
./roborock_onboard.sh config   # Replace saved hostname and secret
```

## Terminal interface

V2 uses ANSI colors for headings and status messages, Unicode-bordered panels, and nine-step progress indicators. Press Enter at each confirmation prompt only after completing the requested action; Ctrl+C cancels.

Color is enabled only when standard output is a terminal, `TERM` is not `dumb`, and `NO_COLOR` is unset or empty. To disable ANSI colors:

```bash
NO_COLOR=1 ./roborock_onboard.sh
```

Unicode borders and symbols remain when colors are disabled; use a terminal and font that display them correctly. The interface changes do not replace the existing authentication sequence or add automated verification of iPhone actions.

## Guided iPhone workflow

1. **Certificate:** Keep WireGuard off. If the iPhone lacks the mitmproxy CA, the helper checks `~/.mitmproxy/mitmproxy-ca-cert.cer`, attempts to generate the CA locally if absent, and opens Finder with the file selected. AirDrop it to the iPhone, install it under **Settings → General → VPN & Device Management**, then enable **Full Trust** under **Settings → General → About → Certificate Trust Settings**. The certificate must be generated by the *same mitmproxy installation* that will intercept traffic. Never download a stranger's root CA or distribute the private key.
2. **Email code:** With WireGuard still **off**, request a fresh Roborock verification code. Save the code somewhere you can easily reference, but **do not enter or submit it yet**. The wizard instructs you to type it manually later because the Roborock app does not allow pasting verification codes. Leave the app on the code-entry screen.
3. **Preflight:** The helper posts a deliberately incomplete payload to `/internal/protocol/user-data`. HTTP `400` with `code: 40041` and `reason: missing_user_data` is the expected success signal for this particular preflight. The current helper also accepts HTTP `2xx` responses. Its `40041` / `missing_user_data` check matches literal compact JSON strings, so differently formatted JSON can fail the check. An unexpected response requires investigation; this preflight does not prove the complete authentication flow works.
4. **MITM:** The helper starts the MITM launcher on the Mac with `--set web_open_browser=false`, disabling mitmweb's own automatic browser launch. It waits up to 45 seconds for the session-specific authentication URL in `roborock_mitm.log`, verifies the token against the live web interface, and opens the capture page in the Mac's default browser. The URL has this structure (open it **on the Mac**):

   ```text
   http://127.0.0.1:8081/?token=<session-token>#/capture
   ```

   Use the current session's token, not the placeholder above. Do not hardcode or share it. The helper can reuse a recognized running MITM instance only after verifying its authentication URL; an existing instance whose token cannot be verified is left running. A newly started instance is subject to cleanup if startup fails. Once reuse is verified, the wizard tracks that instance for subsequent cleanup as well.
5. **WireGuard and login:** Delete any pre-existing **Roborock MITM** WireGuard tunnel, then scan the current capture page's QR code to create a fresh tunnel for this session. Enable that new tunnel, return to the Roborock app, and manually type and submit the saved code. **Request the code with WireGuard off; submit it with WireGuard on.**
6. **Check intercepted session:** Confirm the robot appears and both status and map load. This can take around 1.5 minutes; there is **no fixed timeout for this manual verification step** (the MITM startup check has a separate 45-second deadline). Proceed only when successful. Inspect `roborock_mitm.log` for synchronization errors.
7. **Check normal operation:** Force-quit Roborock, switch WireGuard **off**, reopen the app, and verify that the robot, status, map, and controls still work without the tunnel.
8. **Shut down MITM:** After you confirm normal operation with WireGuard off, the helper stops the temporary MITM process.
9. **Certificate cleanup:** Confirm WireGuard remains **off**. Disable Full Trust for the mitmproxy CA on the iPhone. The installed profile can remain for future recovery, but should not remain trusted between sessions.

If onboarding is interrupted after MITM starts, the script attempts to stop MITM and prints a reminder to turn off WireGuard and certificate trust. **Always verify these settings manually.**

## Reverse-proxy note

If your public HTTPS entry point is a reverse proxy (for example, pfSense HAProxy on `443`) forwarding to the local server's internal HTTPS port (commonly `555`), configure the MITM callback with the **externally reachable port**:

```bash
uv run mitm_redirect.py \
  --local-api https://api-roborock.example.com:443 \
  --sync-secret 'YOUR_CURRENT_ADMIN_SESSION_SECRET'
```

Do not assume the upstream default `:555` is reachable from the Mac. Avoid exposing the local server's internal management port directly to the Internet. Prefer private DNS/network access where practical, and follow upstream guidance on securing the server.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `mitm.it` says traffic is not going through mitmproxy | Expected when the iPhone is not routed through the MITM instance. This helper uses **Mac-generated certificate + AirDrop**, not `mitm.it`, for initial certificate transfer. |
| `403 Authentication Required` | Use the current session's authenticated URL, including `?token=...` before `#/capture`. A bare `http://127.0.0.1:8081/#/capture` URL can fail authentication. Do not reuse an old session's token. |
| Two browser tabs open | Confirm the launcher supports and receives `--set web_open_browser=false`. The helper opens the authenticated page itself; an already-running instance may have launched a tab under its previous settings. |
| Capture page does not open, or startup times out | Inspect `roborock_mitm.log` for startup errors and the current `Web server listening at` authentication URL. Dependency downloads can exceed the 45-second startup window. Resolve the cause and retry; if only browser opening failed, open the current authenticated URL on the Mac and select Capture. Keep the token private. |
| Existing WireGuard tunnel fails | Delete the old Roborock MITM tunnel and scan the current session's QR code to create a fresh tunnel. |
| TLS/certificate error during intercepted login | Ensure the installed CA matches the Mac's current `~/.mitmproxy` CA and **Full Trust** is enabled. |
| Verification email does not arrive | Turn WireGuard off, request a new code, and only enable WireGuard before submitting it. |
| Preflight fails | Verify DNS, HTTPS certificate, reverse-proxy routing, callback path, and the active `admin.session_secret`. |
| `Address already in use` | Check for an earlier MITM process and run `./roborock_onboard.sh status` or `stop`. Do not terminate unrelated listeners. |
| App works with WireGuard on but not off | Do not declare success. Inspect the protocol-auth sync result and local server logs. |
| Certificate is absent from the Mac | The wrapper attempts local generation via `mitmdump`/`uv`; verify that the correct CA was generated before installing it. |

## Security and implementation caveats

- Temporarily trusting a custom root CA permits interception of TLS traffic routed through that proxy. Use only a Mac and iPhone you control, and revoke trust immediately afterward.
- The CA **private key** must stay on the Mac. Only AirDrop `mitmproxy-ca-cert.cer`, never `mitmproxy-ca.pem` or `mitmproxy-ca.p12`.
- The script stores a sensitive server secret in a local config file. Its process command line may also expose the secret to other local processes/users. Consider a more restrictive credential-handling design before upstreaming.
- The configuration file is sourced as shell code; protect it from modification by untrusted users. Treat MITM logs and web authentication tokens as sensitive too. The inspected helper creates a new MITM log with permissions `0600`.
- The helper's process detection and cleanup are best-effort and should be tested with the actual installed launcher and `uv` version. Existing MITM instances may have different command lines.
- The certificate-generation fallback starts and stops `mitmdump`; verify it does not interfere with any existing proxy instance.
- The success prompts rely on **user confirmation**; the script does not programmatically prove that the map or controls work.
- This helper targets the **official iOS app** and has not been validated as an Android onboarding tool.

## Developer notes and testing status

V2 is intended to include extensive developer-facing comments explaining configuration, certificate management, preflight validation, MITM lifecycle and cleanup, browser authentication, and the required login sequence. In the available local `roborock_onboard.sh`, comments explain terminal styling, Unicode progress alignment, log handling, token extraction and validation, and ownership of a reused MITM process. That copy does **not** contain extensive commentary across every subsystem; verify the final submitted script before claiming that broader documentation is complete.

The browser startup logic depends on the installed launcher forwarding `--set web_open_browser=false`, logging the expected `http://127.0.0.1:8081/?token=...` announcement, and exposing the authenticated `/flows` endpoint. Compare these assumptions with your installed `mitm_redirect.py` and mitmweb version. A different host, port, log format, or authentication mechanism can require changes.

This document was compared with the available local V2 helper. Bash syntax validation with `bash -n` passed for that copy. This is not an end-to-end test: certificate generation and installation, live server preflight, launcher compatibility, browser behavior, WireGuard routing, real iOS authentication, protocol synchronization, and interruption/cleanup behavior still require validation in the target environment. Prior reports of terminal rendering review do not establish compatibility with every terminal. Do not describe the final revision as independently end-to-end tested until that testing has actually been completed.

## Contributing upstream

If the maintainer would like this included, propose it as an **optional macOS helper** alongside an update to `docs/roborock_app.md`. Keep the upstream's normal manual procedure available. Test the complete flow and avoid adding machine-specific hostnames, secrets, certificates, or logs to the pull request.

Upstream repository: https://github.com/Python-roborock/local_roborock_server

License and attribution should follow the upstream project's contribution requirements.
