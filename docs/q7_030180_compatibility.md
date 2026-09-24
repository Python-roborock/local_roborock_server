# Q7 sc05 03.01.80 no-dump compatibility check

The captured official `03.01.80` OTA can be decrypted with the same
firmware-wide OTA AES key used by the `03.01.74` script-only packages. On
2026-09-24, one physical Q7 completed the official update to `03.01.80`, a
return to vendor cloud, and a no-dump migration back to the local server using
the version-specific profile. It announced `03.01.80` after each reboot and
answered authenticated local owner RPC after re-entry. This is a result on
one owner's device, not an independent second-device validation.

The decrypted package is SStarOta v0.3 with five payload records. Each record
has a 276-byte header whose first word is its data length. Parsing all five
records consumes the container exactly:

| Record | Target | Bytes | Meaning |
| --- | --- | ---: | --- |
| 1 | `/dev/mtd4` | 2,611,216 | Normal kernel |
| 2 | `/dev/mtd5` | 2,611,216 | Recovery kernel; bytes identical to record 1 |
| 3 | `kernel_otaenv.sh` | 85 | Sets kernel/recovery size variables |
| 4 | `/dev/mtd7` | 30,126,336 | Normal SquashFS root filesystem |
| 5 | `rootfs_otaenv.sh` | 37 | Sets `rootfs_size` |

There is **no `/dev/mtd6` record**. In the inspected partition map, mtd6 is
`rootfs_recovery`, which contains `/bin/otaunpack`. Thus this vendor update
leaves the recovery installer from `03.01.74` in place. The extracted
`03.01.80` normal rootfs still has an `/usr/bin/update` script that changes
`bootcmd`, switches `bootargs` to mtdblock6, sets `boot_recovery=1`, and
reboots. Its `S88scinit` debug bind-mount path is also still present.
The normal rootfs payload has a valid SquashFS 4.0 superblock and was
extracted with `unsquashfs` without an eFuse or per-device key. This does not
prove what happened to unreadable metadata in the older NAND dump, but the
captured `03.01.80` OTA needs no hardware key for offline filesystem analysis.

The normal `rriot_client` binary is byte-identical across the two versions.
The new `systemApp` differs, but contains the same OTA AES key, and the
bounded `signed:false` verification-branch test passed on both binaries.
The physical Q7 then accepted both the 752-byte restore package and the
2,336-byte migration package with `signed:false`, reported OTA installation,
rebooted, and resumed owner communications. Neither custom package contained
a kernel or rootfs payload.

The `03.01.74` portable profile must **not** be sent to `03.01.80`: its
return script pins the old normal-rootfs size. The vendor `03.01.80` end
script reads the current `rootfs_size` environment variable and constructs
the authenticated normal boot command dynamically. An experimental four-file
`03.01.80` profile uses that captured vendor end script, the unchanged OTA
key, and the physically tested v2 IoT editor. It is kept outside Git because
the OTA key is sensitive. The builder, stage validator, and owner senders now
carry an exact target-firmware version and refuse a mismatched cloud inventory
version. The offline builder produced a 2,336-byte migration package (SHA-256
`2ed35d7e70c245062e35c2606603c5a9bc4ed274e8e87fd888aad5fce1abc76f`)
and a 752-byte restore package (SHA-256
`08ed018d3c3578aebb49529bbb79d431967979e4845dced966bec63def5d12bf`).
Both were verified against their hosted LAN bytes before sending.
The four-file private profile archive is SHA-256
`5546c6e1c6bf1083cab77351614e499f4d1c45149941cd71beb9fdc4375a3979`
(3,116 bytes). Its manifest records the one-unit physical test. A newly built
package retains `hardware_tested:false` until that owner's package is tried;
the profile test does not certify every future Q7.

The official vendor update itself was delivered to the same Q7 through the
local owner MQTT route with `signed:true`; its embedded vendor signature
verified offline. The Q7 installed it and reconnected to the local server at
`03.01.80`. The version-specific restore package then returned the Q7 to its
current Roborock account, which listed it online at `03.01.80`. The generic
owner-cloud sender delivered the version-specific migration package; after
reboot, the Q7 connected to the local server, announced `03.01.80`, and
answered `prop.get` and `ota.progress.get` with charging status 4 and OTA
`idle`. These observations establish the complete `03.01.80` round trip on
the same physical unit. A fresh account login and a second owner/device are
still untested.

The live add-on also exposed a routing defect during this test: a read of the
admin vacuum list downgraded the saved Q7 key origin from `inventory_cloud`
to `inventory`, causing the bridge to ignore the reserved migration identity.
The fix preserves that origin during inventory reads and restores it from an
authenticated publish using the reserved credentials. A regression test
covers both the admin read and an already-affected record. The Q7's observed
device topic used its current cloud DUID, not the old numeric factory DID. On
the rebuilt live add-on, refreshing the admin vacuum list still showed Q7
MQTT connected, and a subsequent local owner query returned charging status
4 and OTA `idle`.

To check that the profile is not tied to this unit's identity, a separate
synthetic-owner manifest with a different DUID, local key, and MQTT login was
built with the same four-file profile. The resulting `03.01.80` packages ran
through the recovered ARM `otaunpack` under an isolated QEMU recovery chroot.
Migration changed only the five intended IoT fields, restore returned the
synthetic `iot.json` byte-for-byte, re-entry worked with a matching backup,
and a mismatched backup left the source unchanged. Boot environment writes
and reboot were stubbed. This checks package portability offline; it is not
a second physical-vacuum test.
