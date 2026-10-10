# Camera (live video)

Camera-capable robots can stream to a local WebRTC consumer such as
[go2rtc](https://github.com/AlexxIT/go2rtc) with a `roborock://` source.
Camera bootstrap, authentication and TURN all need to work.

## Bootstrap DNS, ports and certificates

Bootstrap depends on firmware. The tested Saros 10R (`roborock.vacuum.a144`,
FCC/US firmware) uses the onboarding region (`country_domain`). Qrevo MaxV
(`roborock.vacuum.a87`) was observed using `token.r`, including its explicit
port, even when a separate camera domain was supplied.

Firmware truncates the input to 15 characters and appends `iot.roborock.com`.
The input used by that firmware needs a trailing `/` and must fit in **15 characters total**,
including any port. A hostname without a port may be at most 14 characters.
The slash makes the request path `/iot.roborock.com/fwapi/createca`.
A 15-character string without the slash can produce an invalid hostname.

For example, onboarding server `api-vac.cc:555` produces `token.r = vac.cc:555/`.
Camera domain `api-vac.cc` produces `country_domain = api-vac.cc/`.
Qrevo requires DNS, trusted TLS and routing for `vac.cc:555`; Saros requires
`api-vac.cc:443`. Explicit ports are retained; inputs without a port use 443.
After device selection, onboarding checks the observed input for a87 and a144.
For an unknown model or a new vacuum whose model is not known yet, it checks
both inputs conservatively; configure both endpoints or first identify the model.
The initial configuration check only tests the API and MQTT listeners. Camera
checks always verify certificates, even if the CLI's insecure option is used
for the admin connection. A Saros can use a short camera domain with a longer
API/token hostname; a Qrevo with an explicit token port does not require a
separate camera-domain listener on 443.

Preflight also POSTs to the bootstrap route and checks that its advertised TURN
endpoint matches server status. An older server without TURN status is rejected
with update guidance. A trusted certificate for the wrong proxy service is not
sufficient. Set either camera domain or country domain, rather than both.

A wildcard for `*.vac.cc` covers `api-vac.cc` but **not** `vac.cc`; a certificate
for `vac.cc` plus `*.vac.cc` covers both. An API-only certificate does not cover
the stripped `token.r` hostname. DNS must resolve from the robot's network as
well as from the computer running onboarding.

Automatic ZeroSSL provisioning issues the base domain plus its wildcard and
renews them through the existing renewal loop. Set `tls.base_domain` to cover
both names. With provided certificates, arrange renewal yourself. Actalis
automatic provisioning covers only the API hostname; it does not provision a
second camera alias needed by Qrevo. A Saros using the API hostname as its
camera domain can use that certificate. For additional aliases, use ZeroSSL,
a provided wildcard/SAN certificate, or
`listener_mode = "external_tls"` with a proxy that provisions and renews the
required certificates. Route each name and port to this server. See
[reverse_proxy.md](reverse_proxy.md). Optional camera configuration does not
prevent ordinary server startup or onboarding without camera settings.

## TURN modes and port publication

Choose `provided` to start coturn inside the server container, `external` to use
an existing relay, or `disabled` to leave TURN off (the default).

```toml
[turn]
mode = "provided"   # disabled | provided | external
host = "api-vac.cc" # address reachable by robot and viewer
port = 3478
username = "rrturn"
password = "a-long-random-secret"
realm = "api-vac.cc"
ttl = 86400
```

For provided mode, the advertised IPv4 address is resolved from `host` at startup.
Publish the UDP listener and UDP relay range **49160–49179** with 1:1 mappings.
Compose leaves TURN ports unpublished by default. Start provided mode with:

```sh
docker compose -f compose.yaml -f compose.turn.yaml up -d
```

If changing `turn.port`, set `ROBOROCK_SERVER_TURN_PORT` to the same value.
For disabled/external mode, use `compose.yaml` alone. When switching away from
provided mode, recreate the container without the overlay to release its ports.

In Home Assistant, select `turn_mode = provided`, then enable UDP 3478 and every
UDP port 49160–49179 in the add-on's Network settings. Mappings default to
unpublished to avoid conflicts when TURN is disabled or external. Supervisor
cannot change mappings automatically based on the mode. Disable them when
switching away from provided mode. Home Assistant provided mode requires port
3478 because the add-on declares that container listener. Custom listener ports
are supported in external mode and standalone Docker, where you control mappings.
The add-on generates and persists a password when provided mode has none.

`turn_mode` is optional. Leaving it unset preserves older `turn_enabled = true`
options as external mode; otherwise unset means disabled. Explicit mode takes
precedence. Stable and beta add-ons expose the same TURN settings.

For external mode, supply the relay's host, port, username, password and realm;
no local TURN port publication is required. It must support authenticated UDP
allocations. Either active mode makes `/fwapi/createca` return relay credentials.
Status reports provided relay process health. A bootstrap response alone does
not prove media connectivity: verify an authenticated allocation and force a
viewer to use a relay candidate when testing actual frames.

If coturn fails at runtime, HTTPS and MQTT still start and relay health reports
failure. Coturn logs go to container stdout; configure log retention through your
container platform. The resolved advertised IPv4 address and unexpected relay
exit code are logged. TURN passwords are redacted from persisted HTTP responses.

## Remote-view authentication and activation

Use the existing remote-view PIN from the Roborock app. Convert drawing patterns
to digits in the order drawn using this grid:

```text
1 2 3
4 5 6
7 8 9
```

See [go2rtc's Roborock documentation](https://github.com/AlexxIT/go2rtc/blob/master/internal/roborock/README.md).
Keep the PIN out of shared logs and URLs.

The tested Saros 10R required two-key activation: set the remote-view PIN
(`set_homesec_password`), request activation through `set_camera_status` with
the two-key request bits set and monitor bit off, then press Power on the robot
within about 60 seconds. Activation varies by model.

## Troubleshooting and tested behavior

- Bootstrap falls back: inspect the actual hostname, port and path in server logs.
- No bootstrap request: check DNS, trusted TLS, the trailing slash, length limits
  and routing from the robot's network for both inputs.
- Preview rejected: check the existing PIN and the model's activation flow.
- Bootstrap succeeds without frames: check authenticated TURN allocation, UDP
  mappings, firewall rules and the advertised address.

Saros 10R completed a WebRTC handshake with coturn and go2rtc received frames.
Qrevo MaxV completed a forced-relay preview with frames after configuring the
`token.r` hostname and its explicit port. These observations do not establish
identical bootstrap or activation behavior on other firmware.
