# Camera (live video)

Camera-capable robots can stream to a local WebRTC consumer such as
[go2rtc](https://github.com/AlexxIT/go2rtc) with a `roborock://` source.
Camera bootstrap, authentication and TURN all need to work.

The camera bootstrap/TURN implementation was merged in
[PR #144](https://github.com/Python-roborock/local_roborock_server/pull/144) and
[PR #155](https://github.com/Python-roborock/local_roborock_server/pull/155), after
the `v1.2.1` tag. Results below identify development/custom builds where reported;
repulling the `v1.2.1` image does not add this implementation.

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

Do not infer the bootstrap source from the product family alone. The tested
Saros 20X uses `token.r`, unlike the Saros 10R above. A Qrevo Master report says
that putting a hostname in `country_domain` prevented onboarding; that setup used
a short `token.r` and a normal region instead.

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

`turn_mode` defaults to `disabled`. In `config.toml`, the earlier
`[turn] enabled = true` form is still read as external mode when `mode` is not
set; an explicit `mode` takes precedence.

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

A Qrevo Master report observed `set_camera_status` values `[417]` then `[4513]`
from an initial status of `385`, followed by a robot-reported status of `8613`,
without the Saros-style physical activation. An a226 report started at `257` and
observed `[385]`, `[417]`, then `[4513]`; setting the PIN alone had not enabled
remote viewing. These are captured sequences for those devices, not universal
values to copy onto another model. First-time cloud-free PIN setup remains
unverified for the Edge 2 Flow in
[#256](https://github.com/Python-roborock/local_roborock_server/issues/256).

## Reported camera results

The table records what each source tested. **TURN enabled** does not by itself
prove that media used the relay. A direct LAN stream, a packet-captured relay
stream, and a forced-relay test are different observations. Current onboarding
preflight does not automatically recognize every model in this table.

| Model / firmware | Bootstrap and setup | Confirmed scope and limits | Source |
|---|---|---|---|
| Saros 10R (a144), `02.33.88` US | `country_domain`; coturn and activated remote view | go2rtc received frames after activation; physical activation is model-specific. | [#18](https://github.com/Python-roborock/local_roborock_server/issues/18#issuecomment-6082544593) |
| Qrevo MaxV (a87), firmware not stated here | `token.r`, including explicit port | Existing validation recorded frames in a forced-relay preview. | [#155](https://github.com/Python-roborock/local_roborock_server/pull/155) |
| Saros 20X (a288), `02.55.44` EU | `token.r`; server `c3b3284`, provided TURN, patched Android 4.74.04 | Official-app video after shortening the name; reporter also applied HEAD/product-ID fixes. Existing pattern accepted without additional robot activation. | [#18 follow-up](https://github.com/Python-roborock/local_roborock_server/issues/18#issuecomment-6153351361) |
| Qrevo Master (a117), `02.28.26` | Short `token.r`, normal country region | Official-app video and activation sequence reported; a hostname in `country_domain` broke onboarding. | [#173](https://github.com/Python-roborock/local_roborock_server/pull/173) |
| Qrevo Curv 2 Flow, firmware not reported in comment | Short `token.r`, existing wildcard, TURN | Official app and LocalRock video; activation already enabled. Tested third-party client needed a modified SDP offer. | [#173 follow-up](https://github.com/Python-roborock/local_roborock_server/pull/173#issuecomment-6329081772) |
| S7 MaxV (a27), `02.59.36` | `token.r`, normal `eu` region, server base `c3b3284`, provided Let's Encrypt RSA-2048 and coturn | 640×480 H.264; 240 frames over 20 seconds with a test-only forced-relay go2rtc build. Audio/driving untested here. Proposed `--camera` preflight flag belongs to the open PR. | [#185](https://github.com/Python-roborock/local_roborock_server/pull/185) |
| S7 MaxV (a27), `02.59.36` | Short bootstrap name; Actalis RSA-2048, Nginx, custom scheduling build, provided TURN | Official iOS video, Call and remote driving; bulk media observed directly across LAN/VLANs, not forced relay. | [#215](https://github.com/Python-roborock/local_roborock_server/issues/215#issuecomment-6508919416) |
| S7 MaxV (a27), `02.59.36` | ZeroSSL automatic base/wildcard, HA add-on/HAProxy; both onboarding fields use the short name | SD preview with WAN blocked and packet-captured relayed media. Server version unspecified in follow-up. | [#215 follow-up](https://github.com/Python-roborock/local_roborock_server/issues/215#issuecomment-6836429054) |
| S8 MaxV Ultra (a97), `02.39.60` US | Short `token.r` including port 555, normal `us` region, provided ZeroSSL SAN and TURN | Official iOS video on LAN with existing PIN; HA, maps and rooms continued to work. | [#185 follow-up](https://github.com/Python-roborock/local_roborock_server/pull/185#issuecomment-6358124198) |
| Qrevo Edge 2 Pro / cloud alias Curv 2 Pro (a226), `02.43.62` | Short `token.r`, Let's Encrypt, custom product/plugin fixes | Official iOS and go2rtc video; two-way audio when microphone stream starts the producer. Cloud-app activation; relay versus direct media untested. | [#223](https://github.com/Python-roborock/local_roborock_server/issues/223) |
| Qrevo Edge 2 Pro (a226), `02.43.62` | Custom apex-host/bootstrap server, Let's Encrypt, custom L01 bridge and modified go2rtc | Fresh video/two-way audio with WAN blocked, recovery after host reboot. Controls/maps and first-time cloud-free activation untested. | [#239](https://github.com/Python-roborock/local_roborock_server/issues/239) |
| China P20 (a184), factory `02.22.56` | Custom certificate/interception setup; see [partial results](tested_vacuums.md#partial-compatibility-and-custom-setups) | Local camera reported; the mangled-hostname/SAN result does not establish a normal owned-domain certificate path. | [#229](https://github.com/Python-roborock/local_roborock_server/issues/229), [#230](https://github.com/Python-roborock/local_roborock_server/issues/230) |

The ordinary short-hostname setup above remains the documented path for publicly
issued certificates on domains you control. The a184 report reached a longer,
mangled hostname using a compromised-intermediate certificate; it does not mean
that a normal certificate for the API hostname covers that destination.

## Troubleshooting and tested behavior

- Bootstrap falls back: inspect the actual hostname, port and path in server logs.
- No bootstrap request: check DNS, trusted TLS, the trailing slash, length limits
  and routing from the robot's network for both inputs.
- Preview rejected: check the existing PIN and the model's activation flow.
- Bootstrap succeeds without frames: check authenticated TURN allocation, UDP
  mappings, firewall rules and the advertised address.
- Repeated `get_device_sdp` replies of `retry`: the Curv 2 Flow report succeeded
  with audio first (`sendrecv`, Opus/telephone-event), H.264 receive-only video
  with its associated RTX/RED/ULPFEC, no `extmap-allow-mixed`, and an offer sent
  before ICE candidates. Several properties changed together, so the reporter
  did not isolate one as the cause; this is not a universal SDP requirement.
- Video works but microphone does not: in #223, starting the go2rtc producer with
  `media: video,audio,microphone` worked, while switching an existing listen-only
  producer to that stream did not send microphone audio.

Saros 10R completed a WebRTC handshake with coturn and go2rtc received frames.
Qrevo MaxV completed a forced-relay preview with frames after configuring the
`token.r` hostname and its explicit port. These observations do not establish
identical bootstrap or activation behavior on other firmware.
