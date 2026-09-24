# Q7 sc05 custom-region migration without a firmware dump

This is an experimental path for an owner of a stock `roborock.vacuum.sc05`
running `03.01.74`. One physical Q7 has completed the five-field migration to
the live FDS add-on and answered a read-only owner RPC through its normal MQTT
topic. This is a single-device result, not yet a general device test procedure.

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

An offline firmware-specific builder encrypted a small migration package
from that manifest and a private profile exported from the analyzed 03.01.74
firmware. Its script preserves the device identity, account, local
key, Wi-Fi and certificate files while editing five saved IoT fields: API URL,
MQTT URL, MQTT client ID, username and password. The firmware-wide profile
contains a sensitive OTA key and is not distributed with this repository.
The transferable profile consists only of `manifest.json`, `ota-key.bin`,
`editor.sh`, and `return.sh`; it carries no Q7 DID, HMAC bootstrap secret,
cloud DUID, local key, or owner account token. Treat its OTA key as private and
check the manifest hashes after transfer. The inspected profile has been saved
as a four-file archive in the owner's private workspace, outside Git.
The repository now has `scripts/q7_migration_ota_builder.py`, which takes that
portable profile and a new owner's five-field manifest without accessing their
device dump. With the inspected profile and the original test manifest, its
encrypted output was byte-identical to the 2,688-byte package accepted by the
physical Q7 (SHA-256
`04defa005b2f06c26585240ea21e7106aa164a98121a9daa4e836cf4271a0256`).
That comparison validates the builder, not a second device or firmware build.
From the source checkout, after obtaining the profile privately:

```text
uv run --no-sync python scripts/q7_migration_ota_builder.py --config ../private/q7-five-fields.json --profile ../private/q7_ota_profile_sc05_030174 --out ../private/q7-candidate
uv run --no-sync python scripts/q7_stage_ota.py --artifact-dir ../private/q7-candidate
```

The first command builds only local files; the second validates the encrypted
file without hosting it. The package embeds the local server's reserved MQTT
credentials. `scripts/q7_owner_ota.py` now provides a generic owner-side sender
without hard-coded account or device identity. It supports a Roborock email-code
login or a private JSON account export with `username`, `base_url`, and
`user_data` fields. `--list` reads current cloud Q7 DUIDs and firmware versions
without contacting a vacuum. A new owner can use that DUID in
`q7_prepare_migration.py`; the local server still needs a current cloud import
of the same account to know the actual local key.

After hosting the exact encrypted file at an HTTP(S) URL reachable by the Q7,
the owner can run the sender without `--live` to verify the hosted bytes, current
cloud identity, charging state, and idle OTA state. `--live` repeats those gates
and sends one `ota.upgrade.set` request. For example:

```text
uv run --no-sync python scripts/q7_owner_ota.py --email owner@example.com --list
uv run --no-sync python scripts/q7_owner_ota.py --email owner@example.com --duid CURRENT_CLOUD_DUID --artifact-dir ../private/q7-candidate --url http://LAN-HOST/q7-migration-v03.bin.gz.aes
uv run --no-sync python scripts/q7_owner_ota.py --email owner@example.com --duid CURRENT_CLOUD_DUID --artifact-dir ../private/q7-candidate --url http://LAN-HOST/q7-migration-v03.bin.gz.aes --live
```

Each `--email` invocation requests a fresh email code; an existing account
export avoids repeated login. The sender checks that the URL serves the exact
encrypted artifact immediately before it could send the command. The physical
test used a LAN HTTP URL. The server's short-lived HTTPS staging endpoint is
also available, but the stock Q7's trust of an arbitrary local HTTPS
certificate was not established by the physical test. A second physical Q7,
generic sender, and return path have not been tested end-to-end; this remains
an experimental procedure rather than a release-ready instruction.

The server also provides an admin-only `POST /admin/api/q7/ota-package` to
stage at most two AES-aligned encrypted packages, each at most 4 MiB, after
exact SHA-256 and MD5 checks. The opaque download URL expires after 15
minutes; bytes remain in memory. `scripts/q7_stage_ota.py` validates an offline
artifact and can stage it explicitly with `--stage`. Staging does not send an
upgrade command. These scripts run from a source checkout with development
dependencies; they are not included in the Python wheel.

After migration, the server accepts the reserved device MQTT credentials. It
learns the actual device-topic identifier only from an inbound `rr/d/i` publish
whose username matches an authenticated MQTT CONNECT. On this Q7, that topic
identifier was the current cloud DUID, **not** the old numeric factory DID.
The bridge does not guess a target from the model while this link is unverified.

The return-only hardware gate was crossed on 2026-09-23. While the inspected
Q7 was charging and reported OTA `idle`, an owner-authenticated local-broker
`ota.upgrade.set` sent a 528-byte AES-encrypted SStarOta v0.3 container with
zero payload blocks and the exact captured vendor begin/end scripts. It used
`signed:false`, the correct MD5 and size, and a temporary LAN HTTP URL whose
bytes were verified before sending. The vacuum reported `DOWNLOADING`,
`DOWNLOADED`, `INSTALLING`, and `INSTALLED`; its MQTT connection closed for the
reboot and reconnected roughly 20 seconds later. Read-only owner queries then
returned work status 4 (charging) and OTA `idle`. The encrypted package SHA-256
was `fc2d7fff51ad392470d6583aefb7c790bad9ea44be34d4a4022a75233eb13821`.
The hosted copy was removed after the test. No rootfs/kernel payload was in
this package. This proves the physical Q7 accepts this script-only unsigned
OTA and resumes normal owner RPC while paired to the local server. Recovery
execution and boot-variable restoration follow from the inspected firmware
flow and the observed reboot/reconnect; no direct boot-ENV read was available.
This return-only probe did not edit the region. Vendor-cloud delivery and the
five-field cutover were subsequently tested as described below.

## Physical five-field cutover on the live FDS add-on

On 2026-09-23, the Q7 accepted an owner-cloud `ota.upgrade.set` with
`signed:false` for a 2,688-byte encrypted SStarOta v0.3 package. It contained
zero firmware payload blocks. Its begin script edited the existing
`/userdata/rriot/data_dir/iot.json` in recovery, setting the HTTPS and MQTT
URLs plus three MQTT login fields; it did not deliver a separate JSON file or
replace the kernel or root filesystem. The encrypted package SHA-256 was
`04defa005b2f06c26585240ea21e7106aa164a98121a9daa4e836cf4271a0256`.

After reboot, the physical Q7 authenticated to the live **Roborock Local Server
FDS** add-on on MQTT port 8881, published B01 telemetry, and called local
`/time/now` and `/location` on HTTPS port 555. A direct read-only `prop.get`
returned charging status 4. The first owner-topic probe failed because startup
inventory seeding had overwritten the migration key provenance and an earlier
topic observation had created an anonymous duplicate record. The add-on now
preserves the cloud-imported Q7 provenance and merges only an anonymous row
with the same authenticated MQTT credentials. After rebuilding the live add-on,
the normal `rr/m/i` owner-topic probe returned charging status 4 and OTA state
`idle`. Other device identities were left intact.

The return package remains temporarily hosted for recovery. Its byte-identical
restore behavior was tested with the recovered updater in isolated QEMU, but
the restore has **not** been sent to the physical Q7. Physical Wi-Fi reset after
this custom URL edit, Roborock app behavior, a second Q7, and complete firmware
payload replacement are still untested.

After ordinary re-pairing to the owner's Roborock account, the physical Q7
appeared online with a current 16-byte local key. Through the vendor owner
MQTT route, it accepted the **same 528-byte return-only package** via
`ota.upgrade.set` even though the available vendor update was not installed
and the Q7 still reported firmware `03.01.74`. The device reported installation,
rebooted, and later answered owner queries again with work status 4 (charging)
and OTA `idle`. A repeat query confirmed it remained online. This proves that
the owner-authored OTA path can deliver a package to a stock, cloud-paired Q7
without a per-device firmware dump or a vendor version update. It does not
prove that another OTA can be delivered after changing the saved MQTT URL.
The temporary hosted copy was removed after confirmation.

The rollback concern is about transport, not firmware version. In the
recovered 03.01.74 `rriot_client`, the `local.wifi_reset_done` handler calls
the saved-IoT-profile deletion routine (`0x1f9b8` calls `0x212e8`), which
constructs the configured `iot.json` path and calls `unlink` at `0x21354`.
That supports physical Wi-Fi reset and re-pairing as a fallback if a custom
MQTT address becomes unreachable. Before the five-field cutover, this owner
re-paired the unmodified Q7 from the local server back to Roborock cloud.
The fallback has not been tested after an OTA-edited `iot.json`; the Q7 is
currently connected to the local server.

An offline two-package first stage is now available in
`scripts/q7_api_only_ota_builder.py`. It uses the exact vendor recovery return
script that worked in the 528-byte hardware probe, but its begin script calls
`scripts/q7_api_only_edit.sh` to edit **only** `api_url` and retain a byte-exact
rollback copy. The companion restore package copies that saved file back.
The builder requires the pinned captured 03.01.80 package and firmware-wide
OTA key; neither depends on the next owner's device dump. For the owner's
current target origin it built encrypted packages of 1,728 and 1,696 bytes.
No package was hosted or sent to the Q7.

The two encrypted packages were decrypted and passed to the recovered Q7
`otaunpack` in an isolated QEMU recovery chroot, with boot-ENV commands and
reboot stubbed out. On synthetic 12-field `iot.json`, the set package changed
only the API URL, kept all MQTT values and other lines byte-identical, and
saved the original file. The restore package returned it byte-for-byte.
Both runs executed the exact vendor end script's normal-boot ENV sequence.
An existing rollback copy, missing API field, or minified JSON caused the edit
to leave the source unchanged. `otaunpack` can still report success after a
begin-script failure, so a real test must verify the resulting behavior rather
than trust the install status alone. This first stage remains **hardware
untested** and does not prove the Q7 will stay connected to vendor MQTT after
the edit. `scripts/q7_stage_ota.py` can now validate either encrypted file
with `--package set-api` or `--package restore-api`; `--stage` additionally
requires the live server origin and admin login, and only hosts the selected
file briefly. It does not send an OTA command.

On 2026-09-23 the running Home Assistant **Roborock Local Server FDS** add-on
was updated from 1.0.3 to `1.1.0-q7.1`, using the latest branch at `0ee8c62`
plus the existing FDS log-capture route. The add-on's port mappings and saved
data directory were retained. Home Assistant reported it running, the HTTPS
admin page and FDS manifest returned 200, the two Q7 admin routes returned
401 without authentication rather than 404, MQTT TLS completed a verified
handshake, and all seven saved runtime device records remained. The original
add-on source, certificates and runtime credentials were backed up in
`private/fds_pre_q7_update_20260923`. These checks establish server deployment,
not an OTA or a Q7 URL change.

Earlier transport evidence:

1. A single owner-authenticated
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
2. On 2026-09-23 the
   owner's Q7 fetched a 16-byte invalid object from a reachable Home Assistant
   HTTP URL. The device published `DOWNLOADING`, then `DOWNLOADED`, then
   `FAILED/UNKNOWN`, and returned to charging/idle without a reboot. This
   proves basic owner-command delivery and LAN HTTP download. It does not
   prove that the Q7 could fetch the encrypted artifact from the chosen HTTPS
   origin. The later 528-byte return-only trial proved LAN HTTP delivery and
   acceptance of a valid encrypted package.

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

## Owner MQTT through the vendor broker

The vendor web upgrade trigger chooses a vendor package, but the owner's MQTT
connection offers a separate route. On 2026-09-23, the current owner account's
`RRiot` MQTT credentials connected to the vendor broker. An owner publish to
`rr/m/i/{owner}/{mqtt_username}/{duid}` targeting the cloud-registered Q7
stand-in was delivered to that stand-in's
`rr/d/o/{cloud_duid}/{device_mqtt_username}` subscription. The stand-in was
registered for this owner using the inspected unit's identity; the physical
Q7 remained on the local server throughout the test.

Two harmless broker tests were captured and decoded with the stand-in's
current 16-byte local key. The first 199-byte downlink contained `prop.get`
for `status`. The second 343-byte downlink contained `ota.upgrade.set` with
the exact owner-chosen loopback URL, impossible MD5, `packageSize: "16"`,
`signed: false`, and `packageType: "robot"`. The broker thus forwarded an
owner-authored OTA command and did not replace it with a vendor-selected
package. The stand-in had no robot updater and did not download anything.

This establishes a **no-dump OTA entry path** for a stock Q7 normally paired
to the owner account: import the current cloud DUID/local key and use owner
MQTT credentials to deliver an owner-chosen package. The later physical test
confirmed package download, unsigned installation, reboot and return to vendor
owner RPC. The later live FDS test above confirmed the saved-config edit and
custom-region reconnect on one Q7. The stand-in's device bootstrap used the
inspected unit's secret to obtain a reference identity; ordinary cloud pairing
of the physical Q7 did not require the owner to know that secret.

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
format ambiguity in the proposed return path. The return-only physical test
above then verified download, `signed:false` package acceptance, and return
to normal owner RPC without modifying rootfs or kernel. The
existing no-dump migration design for future owners still starts from an
ordinary account import; this vendor capture used the inspected unit's secret
solely to obtain a reference OTA.
`scripts/q7_return_probe_builder.py` constructs the zero-block encrypted
container using the exact vendor begin/end scripts and the pinned
firmware-wide OTA key. Its output has no user credentials or rootfs payload.
The specific 528-byte output hash above was physically accepted on the
inspected Q7. The builder has not been tested across other Q7 firmware builds.

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

The inspected bootstrap-key use sites, USB gadget prerequisites, and bounded
`signed:false` branch check are recorded in
[q7_crypto_usb_audit.md](q7_crypto_usb_audit.md).
