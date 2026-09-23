# Q7 sc05 custom-region migration without a firmware dump

This is an experimental path for an owner of a stock `roborock.vacuum.sc05`
running `03.01.74`. It is **not yet a device test procedure**. The local-server
pieces below have synthetic tests. A failed-download transport probe was sent
to the owner's Q7; no OTA package was delivered or installed.

The intended input is a normal Roborock account import containing the cloud
DUID and the device's 16-byte local key. The native numeric DID and the
per-device HMAC bootstrap secret are not required for the proposed OTA edit.
Use the **current account import**, not values copied from a prior firmware
dump. On the inspected Q7, re-onboarding left two server records with the same
hardware DID; the record with recent MQTT activity had a different DUID, and
the current local key differed from the dumped one. An older DUID could still
reach this one device through the local broker's DID route, so command delivery
alone is not proof that a DUID or local key is current.
An admin endpoint reserves an idempotent MQTT client ID, username and password
for that DUID. `scripts/q7_prepare_migration.py` puts those values and the
chosen HTTPS/MQTT origins in a private five-field manifest. Neither action
contacts the vacuum.

An offline firmware-specific builder can encrypt a small migration package
from that manifest and a private profile exported from the analyzed 03.01.74
firmware. Its proposed script preserves the device identity, account, local
key, Wi-Fi and certificate files while editing five saved IoT fields: API URL,
MQTT URL, MQTT client ID, username and password. The firmware-wide profile
contains a sensitive OTA key and is not distributed with this repository.

The server also provides an admin-only `POST /admin/api/q7/ota-package` to
stage at most two AES-aligned encrypted packages, each at most 4 MiB, after
exact SHA-256 and MD5 checks. The opaque download URL expires after 15
minutes; bytes remain in memory. `scripts/q7_stage_ota.py` validates an offline
artifact and can stage it explicitly with `--stage`. Staging does not send an
upgrade command. These scripts run from a source checkout with development
dependencies; they are not included in the Python wheel.

After a successful migration, the server accepts the reserved device MQTT
credentials. It records the native DID only when an inbound `rr/d/i` publish
has a topic username matching the authenticated MQTT CONNECT username. Until
that happens, the topic bridge does not guess a target DID from the model.

Hardware gates still open:

1. Establish full package-field handling. A single owner-authenticated
   `ota.upgrade.set` with `signed:false`, an impossible MD5, and a loopback
   URL returned `{"result":0}` on the inspected Q7. Its OTA state changed
   from `idle` to `downloading`, and work status changed from charging (4) to
   updating (8). This establishes local-broker write delivery and device-side
   OTA activation. It does not prove that the supplied `signed` flag or other
   fields survive to verification, nor that an encrypted package is accepted.
   The failed-download attempt remained at 0% `downloading` during initial
   monitoring. At 22:12:51 UTC the Q7 published a device-origin P201
   `mqttOtaStatus` event with `status:FAILED` and
   `errMsg:DOWNLOAD_ERROR`. A later getter returned OTA `idle` and work
   status 4 (charging). No package was served; no install or reboot was
   observed. The OTA handler also creates an upgrade marker, restarts a robot
   service, and removes old log files before the download result. This is a
   stateful hardware experiment rather than a harmless getter.
   Bounded Unicorn execution of the recovered ARM worker confirms that a
   failed download invokes neither package verification, install nor reboot;
   a synthetic success reaches those callbacks. The live failure event agrees
   with the worker's failed-download branch.
2. Verify that the robot can fetch an artifact over the chosen HTTPS origin.
   The staging route is tested locally, but the running add-on does not yet
   include it.
3. Establish a physically tested return from recovery. The stock updater
   changes persistent boot variables and reboots to recovery. A captured
   vendor 03.01.80 package contains an end script that restores normal
   `bootargs`/`bootcmd`, clears `boot_recovery`, syncs, and reboots; it is now
   the strongest reference for the offline return script. This still has not
   proven that a custom package returns to normal boot on hardware.
4. Verify that the saved IoT fields survive normal boot and that B01 region/NC
   does not overwrite the custom values. Then test the authenticated MQTT
   connection and owner-command routing on hardware.

The existing Q7 local bootstrap implementation is described in
[q7_b01.md](q7_b01.md). It handles devices whose HMAC secret is already known;
it does not remove the hardware gates above for a stock, no-dump device.

An additional offline probe reconstructed the inspected unit's normal
`bootcmd` and `bootargs` from its rootfs SquashFS header and the updater's
recovery values, matching both saved ENV copies. This may remove the need for a
per-device ENV snapshot on the same firmware, but it has not been checked on a
second Q7 or used in an OTA return script. The physical restore gate remains.

The controlled probe source is `scripts/q7_ota_transport_probe.py`. It is a
dry run unless `--live` is passed and checks for charging plus idle OTA state
before sending one deliberately unfetchable request. It is research evidence,
not a step in the user migration flow.

## Capturing a vendor OTA for reference

The vendor owner API has a read-only firmware-info request
(`GET /ota/firmware/{duid}/updatev2`) and a separate upgrade trigger
(`POST /ota/device/{duid}/upgrade`). The trigger chooses the vendor's package;
it does not accept an owner-supplied URL. The proposed capture is to keep the
physical Q7 on the local server, register a stand-in for **this same device**
under the owner's vendor account, connect that stand-in to the vendor MQTT
downlink topic, and trigger the cloud upgrade only while capturing the message.
The stand-in must never execute the update. The captured vendor package is a
real format/reference sample; it does not by itself prove that the custom
data-only package installs on a physical Q7.

Two credentials are separate here. The owner web API needs a valid account
session to list/register the device and trigger the upgrade. The device MQTT
topic needs broker credentials issued during device bootstrap; the account
session is not a substitute for those credentials. The older saved Home
Assistant account session returned `invalid_credentials`; the current
`conway220` session was valid and listed the same Q7 by serial-number hash.
Former MQTT credentials from the NAND image were rejected by the vendor
broker. Re-onboarding changed the cloud DUID and local key, so the current
account record and a fresh B01 `/b/nc` response were used instead.

On 2026-09-23, a **cloud-only stand-in** successfully completed the following
capture, with the physical Q7 still connected to the local server:

1. The owner firmware-info endpoint reported an available `03.01.80` update
   from `03.01.74`.
2. Using the inspected unit's known HMAC factory secret, signed `/b/region`
   and `/b/nc` calls returned the current cloud DUID and local key. The owner
   `newadd` result matched them. Derived B01 MQTT credentials connected to
   `mqtt-us-b.roborock.com:8883`. The broker accepted subscription to
   `rr/d/o/{cloud_duid}/{mqtt_username}`. It rejected a topic using the
   numeric hardware DID in place of the cloud DUID.
3. An owner-authenticated `POST /ota/device/{duid}/upgrade` returned success
   and delivered one 295-byte B01 MQTT message (protocol 202) to the stand-in.
   The decoded command specified `MANUAL`, version `03.01.80`, HTTPS URL,
   MD5, and size. It did not include a `signed` field. No command was sent to
   the physical Q7.
4. The package was downloaded privately. Its 35,353,120 bytes matched the
   command's size and MD5; SHA-256 is
   `b8f20b74d0b41f493df64feb47645abfacb7614564a91c3c4b940c2d56b50748`.
   Decryption with the static OTA AES key recovered from 03.01.74 produced a
   gzip stream containing a valid Q7 v0.3 container with five blocks, a
   72-byte begin script, and a 1,299-byte end script. The decrypted package
   also has a 1,024-byte trailer containing a length-prefixed DER ECDSA
   signature followed by zero padding. The public key recovered from the
   inspected Q7's userdata independently verifies that signature over the
   gzip member. This confirms the vendor package's signed format, but it
   does not validate the proposed `signed:false` custom-package path.

The vendor end script reads `rootfs_size` from the boot environment, changes
`bootargs` from recovery `mtdblock6` to normal `mtdblock7`, writes the normal
`bootcmd`, sets `boot_recovery` to 0, syncs, and reboots. This removes a major
format ambiguity in the proposed return path. The remaining gate is a
controlled **physical** test of a small custom package that verifies download,
decryption, `signed:false` handling, recovery execution, and return to normal
boot without modifying partitions. The existing no-dump migration design for
future owners still starts from an ordinary account import; this vendor
capture used the inspected unit's secret solely to obtain a reference OTA.

Static inspection of the 03.01.80 rootfs found its `/oem/bin/rriot_client`
byte-for-byte identical to the 03.01.74 binary carved from the inspected
flash image (158,516 bytes; SHA-256
`e1d1959014efc03bcb7f8dae397ea744fdcd7934721d925941389220d2b449d2`).
The unchanged client retains the B01 HMAC `/b/region` and `/b/nc` logic and
the separate RSA/V2 branch. The OTA's five blocks update kernel, recovery,
rootfs, and related environment content, not the persisted certificate or
userdata identity. Thus this update does not introduce a V2-only onboarding
client; the observed Q7 HMAC path should remain available after 03.01.80.
This is a static inference about the post-update device, not a claim that the
physical Q7 has installed 03.01.80.

## Why forcing V2 does not remove the secret requirement

The unchanged Q7 `rriot_client` chooses its alternate RSA/V2 request builder
only when the loaded factory private key has `RSA_size() == 512` (4096 bits).
The inspected Q7's key is 2048 bits, so its current identity selects B01
HMAC. Neither the Wi-Fi provisioning token nor an owner account setting was
found to change that selector. Switching it would require replacing the
factory key with a matching 4096-bit identity or changing signed firmware;
neither has an established owner-accessible route on this Q7.

The alternate builder changes request authentication and marks its headers
`v: v2`; its NC request still uses `/b/nc` and body protocol `p=B01`.
Consequently, selecting this branch alone would not turn the Q7 into a
different model's complete V2 onboarding flow. The 03.01.80 vendor OTA keeps
this client binary byte-for-byte unchanged, and its payload does not replace
the persisted certificate or userdata identity.

More decisively, bounded execution of the alternate Q7 NC branch showed that
it rejoins the same AES response handler, which uses the existing
`device.json` secret. Even a valid RSA/V2 request therefore would not let a
custom server construct an accepted NC response without that secret. This is
specific to the Q7's alternate branch and should not be generalized to other
V2 models.

A fresh read of the current owner's raw `/v3/user/homes/{home_id}` response
returned a 16,167-byte device inventory. A private comparison against the
inspected Q7's full secret, its middle AES-key slice, and a Base64 form found
no match. The earlier owner `newadd` and firmware-info responses likewise had
no match. This narrows the ordinary owner-cloud export route; it does not
exclude every undocumented vendor endpoint or official support export.
