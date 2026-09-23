# Q7 sc05 custom-region migration without a firmware dump

This is an experimental path for an owner of a stock `roborock.vacuum.sc05`
running `03.01.74`. It is **not yet a device test procedure**. The local-server
pieces below have synthetic tests. A failed-download transport probe was sent
to the owner's Q7; no OTA package was delivered or installed.

The intended input is a normal Roborock account import containing the cloud
DUID and the device's 16-byte local key. The native numeric DID and the
per-device HMAC bootstrap secret are not required for the proposed OTA edit.
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
   monitoring; do not send a second request while one is pending.
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
