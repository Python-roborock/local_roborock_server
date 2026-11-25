# Compatibility report details

These notes reconcile compatibility reports and their follow-up comments
as of 15 November 2026. They supplement the [tested-vacuums table](tested_vacuums.md),
which retains earlier results. Observations are attributed to their reports;
they are not independent hardware tests by the documentation author.

Keep firmware, certificate chain, client, and server build together when comparing
results. A successful MQTT connection does not establish working controls, maps,
camera, or every Home Assistant entity. A later success with another chain or
firmware does not invalidate an earlier failure. An open PR's hardware report
does not mean its proposed implementation is in a release.

## Older S-series models

### S6 Pure (a08), firmware 02.13.68

On server **v1.2.1**, Docker Compose with the embedded broker and no reverse proxy,
Actalis RSA-2048 worked using TLS 1.0. The reported chain was Actalis Domain
Validated TLS Server RSA CA 2025 → Actalis TLS Server RSA Root CA 2025 → Actalis
Authentication Root CA. Four GUI pairing cycles recovered the key and connected.
HA status, controls, both floor maps and room targeting worked. Water-box-attached
and mop-mode entities available through the cloud were absent locally; mop intensity
remained available. The official app was not tested after onboarding.
[#191](https://github.com/Python-roborock/local_roborock_server/issues/191)

A second unit on the same firmware rejected a Let's Encrypt ECDSA chain
YE1 → Root YE → ISRG Root X2 → ISRG Root X1, but accepted a provided Actalis
RSA-2048 certificate issued through Certbot. Both reporters found that their
Actalis 90-day EAB credentials had issuance quota while their 1-year credentials
did not. One reporter changed a manually entered Bucharest POSIX timezone to
auto-filled Berlin settings before traffic started; the report does **not** isolate
the timezone from a malformed CST string as the cause.
[Follow-up](https://github.com/Python-roborock/local_roborock_server/issues/191#issuecomment-6431411331)

### S6 MaxV (a10), firmware 02.33.88 and 02.62.46

On **v1.2.1**, `02.33.88` worked with Actalis after Let's Encrypt and ZeroSSL
attempts failed. Docker ran in a Proxmox LXC with Caddy managing certificates.
HA and LocalRock controls/maps worked after three or four pairing cycles. Camera
setup remained unresolved and an authenticated external Mosquitto broker could
not be used; the reporter used the embedded broker instead.
[#231](https://github.com/Python-roborock/local_roborock_server/issues/231)

The newer `02.62.46` accepted **ZeroSSL** through the v1.2.1 HA add-on's ACME
flow. LocalRock onboarding and HA/LocalRock controls worked with Pi-hole DNS.
The official app did not work in that setup. This is firmware-specific evidence,
not a reason to overwrite the older certificate failures.
[#236](https://github.com/Python-roborock/local_roborock_server/issues/236)

### S7 MaxV (a27), firmware 02.59.36

Actalis RSA-2048, issued by Actalis Domain Validated TLS Server RSA CA 2025,
worked on a **custom scheduling build** in Docker on Linux Mint. Nginx terminated
HTTPS on 443 and MQTT TLS on 8881, forwarding to `external_tls` listeners. After
a firewall correction, three LocalRock pairing attempts completed onboarding.
Later tests confirmed official-iOS-app video, Call and remote driving with an
existing remote-view PIN. TURN had to be enabled, but the observed bulk media
was direct across the LAN/VLANs; that test did not prove forced-relay operation.
[#215](https://github.com/Python-roborock/local_roborock_server/issues/215#issuecomment-6508919416)

A separate HA add-on/HAProxy setup on the same firmware used automatically
provisioned **ZeroSSL** base-domain/wildcard certificates. With WAN blocked,
the reporter observed camera bootstrap, TURN allocation and relayed SD video
using published UDP 3478 and 49160–49179. The precise server version was not given
in that follow-up. See the [camera results](camera.md#reported-camera-results) for
the separate Let's Encrypt and forced-relay test from PR #185.
[ZeroSSL follow-up](https://github.com/Python-roborock/local_roborock_server/issues/215#issuecomment-6836429054)

### S7 Pro Ultra and QX Revo Ultra 2

The S7 Pro Ultra (a62) Actalis RSA-2048 result and Let's Encrypt R3/E1 rejection
are already in the table. Its firmware was not reported. The reporter observed
the connection closing after the TLS handshake but before HTTP/MQTT application
traffic with the rejected certificate. That symptom warrants checking the exact
chain **and hostname**; it does not prove a universally incompatible CA.
[PR #65](https://github.com/Python-roborock/local_roborock_server/pull/65)

QX Revo Ultra 2 (a298), `02.15.44`, was reported on **v1.2.1**, unmodified Docker
Compose, with Actalis: maps and cleaning/docking acknowledgements worked, and
the reporter observed five days of local operation. Recovery used header samples
while query samples stayed at zero. Idle reconnects were reported on this setup;
do not use that observation to dismiss command failures or stalled TLS listeners
on other models. The table keeps Actalis as the only established issuer for this
report. Proposed camera tooling in the PR is separate from that compatibility result.
[PR #194](https://github.com/Python-roborock/local_roborock_server/pull/194)

## Saros models

### Saros 20X (a288), firmware 02.55.44

The reported working setup used **v1.2.0**, Podman, LocalRock cloud-import
onboarding and HA controls, with both Let's Encrypt and ZeroSSL. Caddy supplied
certificate files but did not proxy the server. Earlier v1.1.0 attempts failed.
Increasing the container's constrained CPU/memory allocation helped; public-key
recovery can be expensive. The robot attempted DNS directly to `8.8.8.8` until
WAN access was blocked, then used DHCP-provided local DNS. See
[network troubleshooting](onboarding.md#network-and-resource-checks).
[#114](https://github.com/Python-roborock/local_roborock_server/issues/114)

### Saros 20 Neo (a296), firmware 02.27.04 and 02.29.56

`02.27.04` worked on **server build `94bffa7`**, Docker/Proxmox behind Traefik with
Let's Encrypt YR2 → Root YR → ISRG Root X1. The `02.29.56` follow-ups used
**v1.2.1**, both direct TLS with an ECDSA P-384 chain
YE1 → Root YE → ISRG Root X2 → ISRG Root X1 and Traefik with a YR2 chain.
HA maps, status and controls worked. One follow-up recovered the key from header
samples in about two minutes; WAN blocking before onboarding was needed in those
follow-ups. EU cloud import incorrectly selected the US region for one reporter;
explicit `base_url = https://euiot.roborock.com` returned the inventory.
[#139 and follow-ups](https://github.com/Python-roborock/local_roborock_server/issues/139)

Remaining model/client limitations: HA displays Vacuum then Mop as unknown;
`set_wash_towel_mode` was rejected in one setup. Another reporter found
`set_custom_mode` accepted only 101, while combined `set_clean_motor_mode`
accepted 102/103/104/105/106/110; mop-only used fan power 105. Mop modes 300 and
303 worked, 301 did not. `get_recover_maps` returned `unknown_method`. HA map
editing worked inside `start_edit_map` / `end_edit_map`. These are observations
on `02.29.56`, not universal command recipes for other firmware.
[Command details](https://github.com/Python-roborock/local_roborock_server/issues/139#issuecomment-6247548897)

### Saros 20 Sonic (a279), firmware 02.58.82

On the **v1.2.1 HA add-on with ZeroSSL**, the initial report had successful
onboarding and telemetry but no replies to commands. The reporter later confirmed
working operation after deleting/recreating server state and performing three
fresh pairing cycles. The suspected link to an intervening firmware update was
not established. Record this as a resolved setup report, not proof of a general
firmware-update fix or a recommendation to delete server data as a first step.
[#217 resolution](https://github.com/Python-roborock/local_roborock_server/issues/217#issuecomment-6504895070)

## Qrevo models

### Qrevo Curv (a135), firmware 02.28.92

On **v1.2.0**, Docker behind Nginx/SWAG with Let's Encrypt, HA worked. The
reporter manually backed up maps to the robot before migration; LocalRock did
not display carpet surfaces or custom room names. An admin-password UI change
was also requested. Recording the compatibility result does not implement those
UI improvements.
[#110](https://github.com/Python-roborock/local_roborock_server/issues/110)

### QV 35A (a168) and QX Revo Plus (reported a168)

QV 35A `02.49.24` worked on the **v1.2.0 HA add-on**, using ZeroSSL via Cloudflare
DNS-01, local dnsmasq DNS, and three script pairing cycles. HA and LocalRock
commands were confirmed. The requested `external_tls` option remains unavailable
in the HA add-on; that mode is for standalone/Docker deployments.
[#119](https://github.com/Python-roborock/local_roborock_server/issues/119)

QX Revo Plus `02.27.40`, reported model identifier a168, worked on **v1.2.1
Docker** with a ZeroSSL/Sectigo/USERTrust chain. HA connected and a cleaning
routine ran; ACME timeouts were reported during setup. Keep this retail name and
firmware distinct from other QX Revo Plus entries.
[#248](https://github.com/Python-roborock/local_roborock_server/issues/248)

### Qrevo S5V (a170) and QRevo 5AE

S5V `02.33.88` onboarded after four to six cycles on **v1.2.0 Docker with
Let's Encrypt**, but map saving was disabled. A follow-up enabled `lab_status`
through HA's `vacuum.send_command` with `set_lab_status` and
`[{"lab_status": 1}]`. A later LocalRock zone-cleaning coordinate problem remains
unresolved; the workaround does not establish that zone cleaning is fixed.
[#148](https://github.com/Python-roborock/local_roborock_server/issues/148)

QRevo 5AE `02.33.88` was reported working through HA and the Roborock app using
**ZeroSSL**, with the same map-saving workaround. The server version was entered
as `v1.1.2` in the report and has not been verified; the model identifier was not
given. Do not infer an a170 identifier from the shared workaround.
[#218](https://github.com/Python-roborock/local_roborock_server/issues/218)

### Qrevo S Pro (a326), firmware 02.49.24

On **v1.2.1-1-gc177a76**, Let's Encrypt RSA-2048 with
YR1 → ISRG Root YR → ISRG Root X1 worked. HA retrieved status and maps after
re-authentication. Pi-hole initially ignored queries from the routed IoT subnet;
allowing that subnet's DNS requests resolved it. The onboarding PC also needed
a hosts-file entry and routing adjustment while attached to the robot hotspot.
HA's local re-authentication asks for the configured PIN under the label
"verification code"; it sends no email. Stale MQTT credentials can be logged
until this step completes. See [HA setup](home_assistant.md#existing-roborock-integration-repointing-from-cloud).
[#156](https://github.com/Python-roborock/local_roborock_server/issues/156)

### QRevo Pro (a101), firmware 02.15.26

The **v1.2.1** Let's Encrypt/Caddy layer-4 setup had working HA but misleading
missing Region/NC Prepare messages in the admin page. A separate direct-TLS
Docker setup used a **ZeroSSL ECDSA P-256 wildcard** and completed NC Prepare
after three GUI cycles, with HA/LocalRock maps and controls working. Both blocked
WAN traffic. These are separate profiles, not evidence that the first status
problem was fixed.
[#171](https://github.com/Python-roborock/local_roborock_server/issues/171),
[ZeroSSL result](https://github.com/Python-roborock/local_roborock_server/issues/171#issuecomment-6589792705)

### QRevo 2 Pro / ProX (a294)

The **v1.2.1 HA add-on** with provided Let's Encrypt certificates (HA Let's
Encrypt add-on, Porkbun DNS-01) supported cloud-free initial onboarding, maps,
controls and room cleaning. HA reported firmware `02.33.88`, while device OTA
telemetry reported `02.37.80`; the report does not resolve that discrepancy.
On server 1.2.0, control failed with `rrcheck access denied` after about 48 hours;
1.2.1 worked after a fresh `/f/c` exchange. LocalRock room splitting worked but
room renaming did not. The first map saved after a completed run returned to dock.
[#192](https://github.com/Python-roborock/local_roborock_server/issues/192)

On `02.40.54`, a ProX carrying a294 worked with **v1.2.1**, rootless
Podman Compose and Let's Encrypt certificates copied from Nginx Proxy Manager.
HA and LocalRock controls were confirmed. The report's public-port workaround is
not a prerequisite for compatibility; use local DNS and reachable LAN endpoints
as described in [Installation](installation.md).
[#242](https://github.com/Python-roborock/local_roborock_server/issues/242)

### Qrevo S (a104), firmware 02.07.14

**v1.2.1 Docker**, with Let's Encrypt at a reverse proxy, worked without reported
functional limitations. Three attempts collected two samples and a fourth completed
pairing; repeated cycles alone were not evidence of incompatibility.
[#219](https://github.com/Python-roborock/local_roborock_server/issues/219)

### Qrevo Edge 2 Pro / Curv 2 Pro

Edge 2 Pro **a226, `02.33.88`** worked on the **v1.2.1 HA add-on with ZeroSSL**.
HA and LocalRock connected after fixing VLAN MQTT access and inconsistent DNS
answers from a Technitium forwarding/wildcard setup. The unpatched official app
could not log in on GrapheneOS; the reporter used fresh local onboarding instead.
Restarting LocalRock made the new vacuum appear. Resuming interrupted onboarding
was requested as a usability improvement.
[#237](https://github.com/Python-roborock/local_roborock_server/issues/237)

The **a226, `02.43.62`** reports are explicitly
[custom-build results](tested_vacuums.md#partial-compatibility-and-custom-setups).
In #223, the cloud called the product Curv 2 Pro (numeric product ID 199).
Let's Encrypt YR1 → Root YR → ISRG Root X1 worked on Kubernetes with a server at
`6030080` plus product/plugin patches. Initial blind onboarding and HA control
worked. Camera activation subsequently used the official cloud app; re-onboarding
after cloud import hit the stale identity/credentials problem in #222. The
official iOS app needed the #221 plugin changes and the MITM/WireGuard tunnel
disabled after login. For go2rtc two-way audio, the microphone-enabled stream
had to establish the producer first; switching from an existing listen-only
producer did not enable the microphone.
[#223](https://github.com/Python-roborock/local_roborock_server/issues/223)

In #239, a **custom ARM64 build at `02a1770`** on a Pi 5 used an apex-host opt-in,
camera-bootstrap patches, a custom L01 bridge and modified go2rtc at `990f4de`.
Let's Encrypt YE2 → Root YE → ISRG Root X2 → ISRG Root X1 covered the apex.
Video/audio worked with WAN blocked and resumed after a host reboot (about
8.5 minutes to reconnect). Camera access/PIN had been enabled in the cloud app.
No cleaning, maps, HA or post-migration official-app control was tested.
[#239](https://github.com/Python-roborock/local_roborock_server/issues/239)

Curv 2 Pro **`02.45.78`** also has a separate **v1.2.1** success report with a
provided Let's Encrypt RSA-4096 wildcard, YR1 → ISRG Root YR, exported from
Traefik. Two onboarding cycles were needed, with about 20 minutes waiting after
the first. The report does not identify the model code or explicitly validate
camera/audio; do not carry the custom a226 camera results forward to this firmware.
[#233](https://github.com/Python-roborock/local_roborock_server/issues/233)

### Qrevo Edge 3 Pro and Edge 2 Flow

Edge 3 Pro, **a296 as reported, `02.32.54`**, worked through LocalRock on the
**v1.2.1 HA add-on**. Three or four cycles recovered the key and connected even
though query samples stayed at zero. The issuer was entered as **unknown**;
`cloudflare_acme` and `zerossl` settings alone do not verify the served chain.
[#246](https://github.com/Python-roborock/local_roborock_server/issues/246)

Edge 2 Flow, **a328 as reported, `02.33.88`**, worked on the **v1.2.1 HA add-on**
with Let's Encrypt issued by the separate HA add-on using DNS-01. It had never
been connected to the official app/cloud, and mopping worked. Camera remains
unverified: the reporter could not set the PIN and received a parameter error.
Do not copy camera success from the differently named Curv 2 Flow.
[#256 and follow-ups](https://github.com/Python-roborock/local_roborock_server/issues/256)

## Q8 Max+

Firmware **02.07.60** onboarded using the HA add-on and ZeroSSL via Cloudflare
DNS-01. Four signature samples across repeated cycles recovered the key; the
official HA integration connected using Manual region. pfSense supplied local
DNS, there was no reverse proxy, and no Internet port forwarding was used.
The entered server version `18.2` is unverified and must not be treated as a
local-server release number. The report confirms onboarding/HA connection rather
than an exhaustive feature test.
[#216](https://github.com/Python-roborock/local_roborock_server/issues/216)

## China firmware and B01: keep experimental results separate

The China G30 **a146, 02.43.88**, on **v1.2.1-3-g5b99e93**, onboards using
ZeroSSL but rejects control with `rrcheck access denied`; a China VPN did not
resolve that setup. Separate a143 and a96 failures are listed in
[Known failures](tested_vacuums.md#known-failures).
[#161](https://github.com/Python-roborock/local_roborock_server/issues/161)

For China P20 **a184, factory 02.22.56**, #228 reports a startup `/f/c` call to
a hardcoded cloud hostname as well as renewal through `/devices/{did}/sh`.
A TLS failure before HTTP can therefore leave no `/f/c` entry in the local
server's logs. #229 reports camera hostname validation after the handshake.
#230 reports commands, map editing, schedules, camera and daily renewal checks
working in a custom intercepted setup using compromised-intermediate certificates.
That setup was never online and never updated. It establishes neither a standard
owned-domain certificate path nor a fix for already region-locked units.
[#228](https://github.com/Python-roborock/local_roborock_server/issues/228),
[#229](https://github.com/Python-roborock/local_roborock_server/issues/229),
[#230](https://github.com/Python-roborock/local_roborock_server/issues/230)

Q7 TF+ onboarding failure in #48 remains distinct from newer experimental sc05
results. PR #96 reports B01 bootstrap/inbound decoding on Q7 M5+, while its TF+
follow-up uses cloud pairing and custom interception. Neither makes all Q7/Q10
models supported. The PR discussion also contains a Q7 L5 bootloop report during
OTA probing, not successful local onboarding of that model.
[#48](https://github.com/Python-roborock/local_roborock_server/issues/48),
[PR #96](https://github.com/Python-roborock/local_roborock_server/pull/96)

## Follow-up work remains separate

Recording a result does not implement the requested fixes. In particular, the
admin-password UI (#110), HA external TLS (#119), Saros 20 Neo import/mode issues
(#139), zone coordinates (#148), onboarding status (#171), missing HA entities
(#191), room renaming (#192), and Edge 2 Flow camera/PIN setup (#256) remain
separate from the compatibility rows. Custom plugin and identity workarounds
(#221/#222 referenced by #223) are not stock-release guarantees.
