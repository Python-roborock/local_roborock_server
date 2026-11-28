# iOS App Onboarding Wizard (macOS)

The interactive `roborock_onboard.sh` wizard helps iOS users connect the **official Roborock app** to an already configured Roborock Local Server. It guides the Mac and iPhone operations needed for a temporary intercepted login and synchronization of the app's authentication session to your server.

First complete [Installation](installation.md) and [Onboarding](onboarding.md). The wizard does not install the server, provision Wi-Fi for your robot(s), or replace robot onboarding. See [Mobile App Options](roborock_app.md) for other ways to use the server.

## Requirements

- A Mac with Bash, including macOS's built-in **Bash 3.2**, and the commands `uv`, `uvx`, `curl`, and macOS `open`. Install [`uv`](https://docs.astral.sh/uv/) if needed; it includes `uvx`.
- **Python 3.8 or newer** for the wizard's embedded helper, available as `python3` or through `uv python find`. This does not replace the repository's separate Python requirement, currently **3.11 through 3.13**, for running the project and Python launcher.
- A trusted checkout with `roborock_onboard.sh` beside the repository's actual `mitm_redirect.py`, `pyproject.toml`, and `uv.lock`.
- An operational Roborock Local Server with your robot(s) already onboarded and account data imported. Its HTTPS endpoint must be reachable from the Mac and present a valid certificate for the hostname or IP address you enter.
- The running server's **Protocol Sync Secret**, available from its web interface.
- An iPhone with the official Roborock app and WireGuard installed, access to the account's verification email, and the ability to transfer the Mac's public CA certificate to the iPhone, for example with AirDrop.

The wizard uses the server address you enter for the app's local connections. It uses your selected HTTPS port for web requests and port `8881` for robot messaging. If you changed the robot messaging port or configured separate server addresses for the app's services, use the manual setup described in [Mobile App Options](roborock_app.md#official-roborock-app) and [Reverse Proxy](reverse_proxy.md).

!!! warning "Temporary certificate trust"
    Trusting the mitmproxy CA permits interception of HTTPS traffic routed through the proxy. Use a Mac and iPhone you control. Transfer only the public CA certificate, keep its private key on the Mac, and disable Full Trust after onboarding.

## Quick Start

In the repository directory, run:

```bash
chmod +x roborock_onboard.sh
./roborock_onboard.sh
```

On first use, the wizard prompts for the server address and Protocol Sync Secret. It then checks the server before asking you to change iPhone trust settings or request a short-lived verification code.

| Command | When to use it |
| --- | --- |
| `./roborock_onboard.sh config` | Replace the saved connection settings or Protocol Sync Secret, including recovery from invalid saved configuration. |
| `./roborock_onboard.sh status` | Inspect the recorded session for this checkout and report matching unmanaged processes. It does not check iPhone settings. |
| `./roborock_onboard.sh stop` | Stop the temporary MITM proxy and its background helpers started by the wizard in this project folder. |

### Server Address

| Setup | Example input | HTTPS port |
| --- | --- | --- |
| No reverse proxy / default installation | `192.168.1.50` | `555`, selected automatically |
| Reverse proxy | `roborock.example.com:443` | The externally reachable proxy port, here `443` |
| Customized HTTPS port in either setup | `roborock.example.com:8443` | The actual port you supply, here `8443` |

Enter a complete hostname or IPv4 address, with a port when needed. A port alone, such as `443` or `555`, is invalid. Explicit port numbers are preserved. Pasted `http://` and `https://` prefixes are normalized; connections still use **HTTPS**. Enter only the address and optional port, without paths or login details. IPv6 literals are not supported by the wizard.

Use an address that resolves and is reachable from the Mac. An IP address works only if the server's HTTPS certificate is valid for that IP. For proxy routing requirements, see [Reverse Proxy](reverse_proxy.md).

This is the **Roborock Local Server HTTPS endpoint**. It is separate from mitmweb's browser interface at `http://127.0.0.1:8081` on the Mac.

### Protocol Sync Secret

For a Home Assistant installation, follow this path:

**Home Assistant → Apps → Roborock Local Server → Open Web UI → log in with the admin password → copy Protocol Sync Secret → paste it into the terminal.**

For other installations, sign in to the running server's admin web interface and find the active secret under **Protocol Auth**. See [Home Assistant](home_assistant.md) for the server dashboard location.

Paste the **Protocol Sync Secret**, not the admin password. The admin password opens the web interface; the Protocol Sync Secret authorizes synchronization by the wizard. Pasted characters remain hidden in the terminal. Press Enter afterward. Empty and whitespace-only secrets are rejected; a saved whitespace-only secret prompts for replacement. Use `./roborock_onboard.sh config` to replace saved credentials or connection settings.

### Terminal Interface and Initial Check

Boxed headings, nine-step progress indicators, color-coded messages, and confirmation prompts guide the session. Press Enter only after completing the action described. **Ctrl+C cancels** and attempts cleanup.

ANSI colors are disabled when output is not a terminal, `TERM` is `dumb`, or `NO_COLOR` has a nonempty value. For example:

```bash
NO_COLOR=1 ./roborock_onboard.sh
```

Unicode borders and symbols remain visible without color; use a terminal font that supports them.

The following is an **illustrative initial screen** with saved settings and an expected successful server check, not a record of an onboarding run:

```text
╭──────────────────────────────────────────────────────────╮
│ ROBOROCK iOS ONBOARDING                                  │
╰──────────────────────────────────────────────────────────╯

To change the saved server or Protocol Sync Secret, run:
  ./roborock_onboard.sh config

Configured server: https://roborock.example.com:443
Checking the server connection and Protocol Sync Secret (up to 10 seconds)...
✓ Server connection verified.
```

The check sends a protocol-sync probe to the configured HTTPS endpoint with a **10-second total request limit**. DNS, connection, timeout, TLS/certificate, access, and unexpected-response failures stop the wizard with guidance to correct the settings. Complete this check before making any iPhone changes. It checks endpoint access, not the entire login flow.

## Guided iPhone Workflow

The nine steps below match the wizard's terminal headings. iPhone certificate installation, Full Trust, WireGuard state, login, maps, and controls depend on **your confirmation**. The Mac cannot change or verify those phone settings. Manual checkpoints have no MITM startup timeout.

### Step 1: PREPARE THE IPHONE

Keep **WireGuard OFF** throughout certificate preparation.

Check **Settings → General → About → Certificate Trust Settings** on the iPhone. If the correct mitmproxy certificate is already installed, enable it under **Enable Full Trust for Root Certificates**. The certificate must correspond to the Mac's CA used by mitmproxy for this session; the wizard cannot verify that an existing iPhone certificate matches.

If it is not installed, the wizard locates `~/.mitmproxy/mitmproxy-ca-cert.cer` and opens Finder with it selected. If Finder does not open, locate that file manually. AirDrop the public certificate to the iPhone, then:

1. Accept the transfer and open **Settings → General → VPN & Device Management**.
2. Select the mitmproxy profile and install it.
3. Open **Settings → General → About → Certificate Trust Settings**.
4. Enable the mitmproxy certificate under **Enable Full Trust for Root Certificates**.

Installing the profile and enabling Full Trust are separate actions. Confirm both before continuing.

If the Mac's certificate is missing, the wizard briefly runs installed `mitmdump`, or uses this fallback:

```bash
uvx --from mitmproxy mitmdump
```

The wizard adds a loopback-only listener on an automatically selected port, supervises the temporary processes, waits up to 90 seconds for certificate generation, and stops them afterward. Failures point to `.roborock_certificate.log`. It uses no `sudo` and makes no macOS Keychain or trust changes.

!!! warning "Transfer the public certificate only"
    Send `mitmproxy-ca-cert.cer`. Never transfer `mitmproxy-ca.pem` or `mitmproxy-ca.p12`, which contain the CA private key. Use the CA belonging to the mitmproxy installation used for this onboarding session.

### Step 2: GET THE ROBOROCK VERIFICATION CODE

With **WireGuard still OFF**, open the official Roborock app, log out if needed to reach login, enter your account email, accept the terms and conditions, and request a fresh email verification code.

**Save the verification code somewhere you can easily reference. DO NOT ENTER IT YET.**

The Roborock app does not allow pasting verification codes, so you will need to type the code manually later. Leave the app at the verification-code entry screen and confirm in the terminal only after the code arrives.

### Step 3: PREPARE MITM CONNECTION

The initial screen has already checked the configured server. At startup, the Python launcher performs its own fresh preflight to catch endpoint or credential changes during the manual phone steps. A failure stops onboarding before you enable WireGuard.

### Step 4: START MITM SERVER

The wizard starts a fresh managed MITM session with `--set web_open_browser=false`, disabling mitmweb's automatic browser launch. It shows startup progress and waits for the authenticated interface to become ready. The readiness window is **90 seconds**, after a separate short supervisor-startup allowance of up to five seconds. These are startup limits, not deadlines for completing phone instructions.

The wizard reads the current authentication URL from `roborock_mitm.log` and validates its token against the live authenticated `/flows` endpoint. Only then does it open the authenticated Capture page in the Mac's default browser, using this structure:

```text
http://127.0.0.1:8081/?token=<session-token>#/capture
```

The token is session-specific. Keep it private; never hardcode, share, or substitute an old token. The wizard does not trust stale log tokens or fall back to an unauthenticated page. Disabling mitmweb's own browser opener avoids redundant automatic tabs.

Failed readiness stops startup and triggers a cleanup attempt. If the server is ready but macOS reports that browser opening failed, the wizard pauses: **Open the authenticated URL from the private log, then select Capture.** Confirm only after the page is open. A successful `open` command dispatches the URL but cannot prove the browser displayed it; use the same recovery path if the page does not appear.

### Step 5: CONNECT WIREGUARD AND SUBMIT LOGIN

1. Delete any previous **Roborock MITM** WireGuard tunnel on the iPhone.
2. Create a new tunnel by scanning the **current session's** QR code on the Mac's Capture page. Create a fresh tunnel each time.
3. Enable the newly created tunnel.
4. Return to the Roborock app's code-entry screen and manually enter the saved verification code.
5. Submit the login, then confirm in the terminal after it succeeds.

**Request the code with WireGuard OFF; submit it with WireGuard ON.**

### Step 6: VERIFY ROBOT THROUGH MITM

Keep WireGuard **ON** and MITM running. Confirm your robot(s) appear, open the device screen, and wait for status and map data to load. The wizard suggests approximately 1.5 minutes, but this manual checkpoint has no fixed timeout. Continue only after status and maps work.

### Step 7: TEST WITHOUT THE MITM TUNNEL

Leave MITM running on the Mac. Force-quit the Roborock app, turn WireGuard **OFF**, and reopen the app. Confirm your robot(s), status, maps, and normal controls work. Do not continue if this check fails.

### Step 8: SHUT DOWN MITM

After your confirmation that normal operation works with WireGuard off, the wizard stops its verified temporary MITM session and child processes. If shutdown cannot be verified, follow the reported recovery guidance before considering cleanup complete.

### Step 9: CERTIFICATE CLEANUP

Confirm WireGuard remains **OFF**. In **Settings → General → About → Certificate Trust Settings**, disable Full Trust for the mitmproxy CA. The certificate profile may remain installed for future use, provided it is not left trusted between onboarding sessions. Confirm in the terminal after Full Trust is off.

!!! warning "Delete sensitive captures manually"
    `mitm_logs/<session>/` can contain complete request and response headers and bodies, including cloud login tokens, Roborock authentication credentials, `rriot` keys, and other intercepted account or protocol information. Never publish raw captures, credentials, or authentication URLs.

After successful onboarding, identify the **current session directory shown by the wizard** and delete that directory in Finder. If it cannot identify the directory automatically, use the `[LOG]` entries in `roborock_mitm.log` to locate that session under `mitm_logs/`. Preserve unrelated sessions unless you intentionally want to remove them. The wizard does **not** delete captures automatically.

Treat `roborock_mitm.log` separately: it contains the authenticated web URL. Delete that startup log after troubleshooting is finished.

## Stopping and Recovery

Run `./roborock_onboard.sh status` from this checkout to inspect its recorded session. An existing verified wizard session must be stopped with `./roborock_onboard.sh stop` before starting fresh with current settings. Sessions are not automatically reused.

Shutdown requires verified ownership of the managed session and its process group. Unrelated sessions and other checkouts are not terminated. Legacy or externally launched sessions must be stopped through their original launcher. A stale numeric PID is not permission to stop a process. If ownership cannot be verified, follow the diagnostic instructions and confirm the original server has stopped before removing only the state pointer identified by the wizard.

Pressing **Ctrl+C**, or an ordinary failure during onboarding, attempts cleanup of the temporary processes and reminds you to turn WireGuard and Full Trust off. Cleanup can fail, and power loss or forceful termination can prevent it. Check `status` and use `stop` as needed; **always check iPhone VPN and certificate trust settings manually**.

A checkout-wide lock prevents concurrent wizard runs. If a lock remains after interruption, first confirm that **no onboarding wizard is running**. Only then remove the empty `.roborock_onboard.lock` directory in this checkout using Finder and retry. Do not delete other state or captures to clear a lock.

macOS may deny inspection of unrelated processes. That message is advisory and does not itself block startup. An occupied port `8081` is reported without stopping its listener or overwriting the existing startup log. Stop a previous managed session with the wizard; close another listener through its own launcher.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Initial server check fails | Check the complete hostname/IP, HTTPS port, DNS, server availability, proxy routing, and Protocol Sync Secret. Use `./roborock_onboard.sh config` to correct saved settings. |
| Server HTTPS certificate or TLS verification fails | Check the server's certificate chain and that its certificate covers the address entered. Correct the endpoint or certificate; keep TLS verification enabled. This is separate from trusting the temporary CA on the iPhone. |
| Server returns an unexpected response | The incomplete POST to `/internal/protocol/user-data` must return HTTP **400** with structured JSON `data.reason` equal to `missing_user_data`. JSON spacing and key order do not matter. Ordinary 2xx, HTML, redirects, and unrelated errors are rejected; no particular numeric `code` is required. Check proxy routing and access requirements. |
| `403 Authentication Required` in mitmweb | Open the current session's private authenticated URL with `?token=...` before `#/capture`. A bare Capture URL or an old token is insufficient. |
| Browser does not open, or authenticated Capture page is missing | After readiness succeeds, open the authenticated URL from the current private startup log on the Mac and select Capture. If it still fails, inspect the startup log and session status before retrying. Keep the token private. |
| MITM exits or authenticated readiness fails | Inspect `roborock_mitm.log` locally for launcher preflight, dependency/tool startup, or binding errors. Downloads may exceed the readiness window. Resolve the cause, check `status`, stop any remaining verified session, and retry. |
| Port `8081` is already occupied | Use `status` and `stop` for a prior managed session. Otherwise close the listener through its original launcher. The wizard leaves that listener and the existing startup log untouched. |
| Certificate generation fails | Inspect `.roborock_certificate.log` locally and check `mitmdump` or `uvx` availability and network access. Transfer the public CA only after generation succeeds. |
| iPhone reports certificate errors during intercepted login | Check that the installed profile matches the Mac's current mitmproxy CA and Full Trust is enabled. This is an iPhone trust check, not a server HTTPS verification fix. |
| Verification email does not arrive | Keep WireGuard off while requesting a fresh code. Save it before enabling the new tunnel. |
| Previous WireGuard tunnel fails | Delete the old Roborock MITM tunnel and scan the current session's QR code. |
| App works through MITM but fails with WireGuard off | Stop at Step 7. Inspect protocol-sync errors in the private startup log and server logs; do not confirm successful onboarding. |

## Local Files and Credentials

Generated files are kept beside the wizard unless noted otherwise:

| Path | Purpose and handling |
| --- | --- |
| `.roborock_onboard.conf` | Sensitive server address and Protocol Sync Secret. Written atomically with mode `0600`; keep private. |
| `.roborock_sessions/` | Private per-launch supervisor state for MITM and certificate generation. Process-management data, separate from traffic captures. Preserve it while a session may still need shutdown. |
| `.roborock_mitm.pid` | Pointer to a managed session directory, despite the filename. Process-management data, not authority to terminate an arbitrary PID. |
| `.roborock_onboard.lock/` | Empty directory serializing wizard runs. Remove only as described under recovery. |
| `.roborock_certificate.log` | Restricted certificate-generation diagnostics. Review privately if generation fails. |
| `roborock_mitm.log` | Sensitive startup diagnostics and the session's authenticated web URL. Remove when troubleshooting is finished. |
| `mitm_logs/<session>/` | Sensitive intercepted traffic. Manually remove the identified session after successful onboarding. |

Configuration is **literal data**, not an executable shell script. Ordinary quotes and shell punctuation in values do not execute commands. Invalid legacy configuration requires replacement with `./roborock_onboard.sh config`; do not source it to recover values.

The wizard transports the secret through environment variables or standard input, rather than secret-bearing command arguments. Environment transport does not guarantee protection from privileged or same-user inspection. Restricted permissions and ignored files do not make credentials or captures safe to share or back up to an untrusted location.
