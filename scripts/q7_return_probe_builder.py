"""Build a Q7 script-only OTA probe using the vendor's recovery return script.

This is an offline research artifact. It contains no user identity or server
credentials, but has not been accepted by a physical vacuum. Building it does
not host the file or send an upgrade command.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


REFERENCE_SHA256 = "3cec9e08afab5d478e83e4748b5b5bb814e24fc4fb41dd8d12afecb97c0ec904"
BEGIN_SHA256 = "d78ee861261168855b8dc1445713856591999d5c433cc1c70c0e00e2c1fe592a"
END_SHA256 = "a5f599aaaa53c898090b81ff8e8a9a9312e48e75f18fb0a93f523492a6cacc26"
KEY_SHA256 = "a02bdcf7b3afdb5b0dce179326d81839c9d04d5bfb47fd318aba777633b01f5e"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build(reference: Path, key_file: Path, out: Path) -> dict[str, object]:
    if out.exists():
        raise FileExistsError(f"Refusing to overwrite {out}")
    source = reference.read_bytes()
    if digest(source) != REFERENCE_SHA256:
        raise ValueError("Captured vendor OTA reference does not match")
    _, major, minor, block_count, payload_size, begin_size, end_size = struct.unpack_from(
        "<7I", source
    )
    if (major, minor, block_count, begin_size, end_size) != (0, 3, 5, 72, 1299):
        raise ValueError("Unexpected vendor OTA layout")
    if payload_size <= 0:
        raise ValueError("Vendor package has no payload")
    begin = source[28 : 28 + begin_size]
    end = source[28 + begin_size : 28 + begin_size + end_size]
    if (digest(begin), digest(end)) != (BEGIN_SHA256, END_SHA256):
        raise ValueError("Vendor scripts do not match the captured reference")
    if not begin.startswith(b"#!/bin/sh\n") or not end.startswith(b"#!/bin/sh\n"):
        raise ValueError("Vendor scripts have an unexpected interpreter")

    key = key_file.read_bytes()
    if len(key) != 16 or digest(key) != KEY_SHA256:
        raise ValueError("Firmware-wide OTA key does not match the inspected Q7")

    tail = struct.pack("<6I", 0, 3, 0, 0, len(begin), len(end))
    container = struct.pack("<I", sum(tail) + sum(begin) + sum(end)) + tail + begin + end
    assert struct.unpack_from("<I", container)[0] == sum(container[4:])
    compressed = gzip.compress(container, compresslevel=9, mtime=0)
    padding = 16 - len(compressed) % 16
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encrypted = encryptor.update(compressed + bytes([padding]) * padding) + encryptor.finalize()

    out.mkdir(parents=True)
    artifact = out / "q7-vendor-return-probe.bin.gz.aes"
    artifact.write_bytes(encrypted)
    metadata: dict[str, object] = {
        "model": "roborock.vacuum.sc05",
        "target_firmware": "03.01.74",
        "container": "SStarOta 0.3, zero payload blocks",
        "signed": False,
        "package": artifact.name,
        "encrypted_size_bytes": len(encrypted),
        "encrypted_md5": hashlib.md5(encrypted).hexdigest(),
        "encrypted_sha256": digest(encrypted),
        "begin_sha256": digest(begin),
        "end_sha256": digest(end),
        "vendor_reference_sha256": REFERENCE_SHA256,
        "hardware_tested": False,
        "warning": "Offline candidate. Vendor end script writes boot ENV and reboots if executed.",
    }
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True, help="decompressed captured vendor OTA")
    parser.add_argument("--key-file", type=Path, required=True, help="private firmware-wide OTA key")
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    args = parser.parse_args()
    result = build(args.reference, args.key_file, args.out)
    print(json.dumps({k: result[k] for k in ("package", "encrypted_size_bytes", "encrypted_md5", "encrypted_sha256", "hardware_tested")}, indent=2))


if __name__ == "__main__":
    main()
