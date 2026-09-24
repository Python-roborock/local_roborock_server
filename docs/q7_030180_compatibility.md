# Q7 sc05 03.01.80 no-dump compatibility check

The captured official `03.01.80` OTA can be decrypted with the same
firmware-wide OTA AES key used by the physically tested `03.01.74` script-only
packages. This is an offline compatibility finding, not a physical migration
test on `03.01.80`.

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
This supports a script-only package for an already-onboarded `03.01.80` Q7.
It does not establish that a physical `03.01.80` unit accepts the package or
successfully returns from recovery.

The `03.01.74` portable profile must **not** be sent to `03.01.80`: its
return script pins the old normal-rootfs size. The vendor `03.01.80` end
script reads the current `rootfs_size` environment variable and constructs
the authenticated normal boot command dynamically. An experimental four-file
`03.01.80` profile uses that captured vendor end script, the unchanged OTA
key, and the physically tested v2 IoT editor. It is kept outside Git because
the OTA key is sensitive. The builder, stage validator, and owner senders now
carry an exact target-firmware version and refuse a mismatched cloud inventory
version. The offline builder produced a 2,336-byte migration package and a
752-byte restore package; both passed local hash/size validation. No package
was sent to a `03.01.80` Q7.

Before this version can be presented as a tested user procedure, a charging,
cloud-online `03.01.80` Q7 should complete a return-only physical OTA, then
the migration/restore round trip with current account data. The current
physical test unit remains on `03.01.74` and on the custom local server.
