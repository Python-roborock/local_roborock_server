# Q7 sc05 bootstrap-key and USB audit

Read-only analysis of the inspected Q7 03.01.74 image and the recovered vendor
03.01.80 OTA. The two versions have byte-identical `rriot_client` binaries
(SHA-256 `e1d1959014efc03bcb7f8dae397ea744fdcd7934721d925941389220d2b449d2`).
No USB gadget or unsigned OTA package was run on the physical vacuum.

## Which key protects which traffic

Within this `rriot_client`, the per-device `device.json` secret supplies two
different onboarding operations:

| Operation | Firmware site | Key material | Traffic |
| --- | --- | --- | --- |
| Request signature | `0x19efe`, `0x1a3b8` | Full `device.json` secret, HMAC-SHA256 | Outbound `/b/region` and `/b/nc` |
| Response decryption | `0x1a010`, `0x1a4d6` through `0x25028` | ASCII `secret[8:24]`, AES-128-CBC | Inbound `result` in `/b/region` and `/b/nc` |
| Ordinary framed command transport | `0x223c6`, `0x224ae` | Saved `iot.json` `localkey` | Inbound and outbound device messages |
| OTA file decryption | `systemApp`, not `rriot_client` | Firmware-wide static OTA key | Downloaded encrypted package |

The region and NC calls are the only callers of the per-device AES response
helper found in this client. The alternate RSA/V2 request branch also reaches
the same NC decryption helper. The generic AES-ECB decoder in this binary has
no observed external caller. `systemApp` also has a `getRR_secret` method, but
its embedded constant was privately compared and differs from this Q7's
`device.json` secret and AES slice; the name alone does not identify a second
use of the bootstrap key.

A packet capture can preserve the signed request and encrypted vendor response
for protocol analysis, but neither value discloses the key. Relaying the vendor
response leaves the vendor API/MQTT URLs in place. Changing a response for a
custom region still requires the per-device secret, a separately established
identity export, or a device-side migration that avoids onboarding. This audit
maps the inspected client and known application paths; it does not prove that
no undocumented process or future firmware ever reads the same file.

## USB enumeration

The 03.01.80 image contains UDC/composite modules and a generic
`gadget-configfs.sh` capable of configuring USB functions. Startup runs
`/config/demo.sh`, which loads the USB modules, but does not create a gadget or
bind a function to the UDC. The named 03.01.80 init directory contains no
`S50usbdevice`, and the image has no `adbd` binary. The generic script's ADB
option therefore cannot provide an ADB session on this image merely by being
present. Hardware USB socket wiring and UDC state were not observed.

Factory TCP command `0x80` calls `CSerTCPSocket::openAdb`, which only logs.
A separate `CDeviceR16::openAdb` in `everest-server` contains a call to
`/etc/init.d/S50usbdevice start`, but no direct caller was found and that file
is absent from the 03.01.80 rootfs. The 03.01.74 rootfs has damaged filename
metadata; its surviving reference to that path does not establish that the
script was present or what it did. No inspected factory-mode button or TCP
transition configures and binds a USB gadget. The owner's observed lack of
enumeration is consistent with these startup paths, while a board-level wiring
or a separate indirect software trigger remains unverified.

## OTA `signed` flag

A bounded synthetic ARM execution of the application verification branch on
both 03.01.74 and 03.01.80 confirms `signed:false` skips its ECDSA check and
`signed:true` enters signature setup. This is a branch-level result only. The
physical Q7 accepted a `signed:false` command and entered `downloading`, but
the deliberately unreachable URL failed before verification. Full encrypted
package acceptance, recovery execution, and normal reboot remain untested.
