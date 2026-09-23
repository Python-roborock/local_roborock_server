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
3. Establish a device-specific boot environment snapshot and a physically
   tested restore path. The stock updater changes persistent boot variables
   and reboots to recovery. The offline return script and QEMU tests cannot
   guarantee a real NAND write or normal reboot, especially on another unit.
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
The stand-in must never execute the update. A vendor package would provide a
real format/reference sample; it would not by itself prove that the custom
data-only package installs on a physical Q7.

Two credentials are separate here. The owner web API needs a valid account
session to list/register the device and trigger the upgrade. The device MQTT
topic needs broker credentials issued during device bootstrap; the account
session is not a substitute for those credentials. On 2026-09-23, the saved
Home Assistant Roborock session returned `invalid_credentials` during a
read-only home query. A TLS MQTT CONNECT using the inspected Q7's former
credentials from its NAND image reached `mqtt-us-b.roborock.com:8883` but
received `Not authorized`. This was a passive connection attempt; no publish
or OTA request was sent. The old credentials cannot currently serve as the
stand-in. They may have been revoked when the Q7 was re-onboarded, but that
cause is an inference, not established by the broker's reason code.

Next capture prerequisites are a fresh owner account session and new valid
device-side MQTT credentials for the stand-in. The latter likely requires
reproducing the normal B01 region/NC bootstrap with this unit's already-known
factory secret and completing the cloud pairing flow. This dump-assisted
capture is only for obtaining a reference OTA; the proposed migration for
future owners still starts from their ordinary vendor account import and
does not assume access to their factory secret. Test cloud registration and
message receipt before any download, and do not direct the resulting upgrade
message to the physical Q7.
