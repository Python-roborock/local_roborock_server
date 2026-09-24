"""Build offline Q7 API-only edit and rollback OTA packages.

Both packages leave the saved MQTT URL and credentials untouched. Building
them does not host anything or send an OTA command to a device.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

if __package__:
    from . import q7_return_probe_builder as reference_builder
else:
    import q7_return_probe_builder as reference_builder


EDITOR = Path(__file__).with_name("q7_api_only_edit.sh")
EDITOR_SHA256 = "06df6ad2c9f749ef261f48f91857e2054e4b3f5fbaf408ebf350e2459da766ef"
API_PATTERN = re.compile(r"https://[A-Za-z0-9._:/+\-]{1,232}\Z")


def _scripts(reference: Path) -> tuple[bytes, bytes]:
    source = reference.read_bytes()
    if reference_builder.digest(source) != reference_builder.REFERENCE_SHA256:
        raise ValueError("Captured vendor OTA reference does not match")
    _, major, minor, block_count, payload_size, begin_size, end_size = struct.unpack_from("<7I", source)
    if (major, minor, block_count, begin_size, end_size) != (0, 3, 5, 72, 1299) or payload_size <= 0:
        raise ValueError("Unexpected vendor OTA layout")
    begin = source[28 : 28 + begin_size]
    end = source[28 + begin_size : 28 + begin_size + end_size]
    if (reference_builder.digest(begin), reference_builder.digest(end)) != (
        reference_builder.BEGIN_SHA256, reference_builder.END_SHA256
    ):
        raise ValueError("Vendor return scripts do not match")
    return begin, end


def _package(begin: bytes, end: bytes, key: bytes) -> bytes:
    tail = struct.pack("<6I", 0, 3, 0, 0, len(begin), len(end))
    container = struct.pack("<I", sum(tail) + sum(begin) + sum(end)) + tail + begin + end
    if struct.unpack_from("<I", container)[0] != sum(container[4:]):
        raise AssertionError("SStarOta header checksum mismatch")
    compressed = gzip.compress(container, compresslevel=9, mtime=0)
    padding = 16 - len(compressed) % 16
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(compressed + bytes([padding]) * padding) + encryptor.finalize()


def build(reference: Path, key_file: Path, api_url: str, out: Path) -> dict[str, object]:
    if not API_PATTERN.fullmatch(api_url) or len(api_url) > 240:
        raise ValueError("API URL must be HTTPS with the Q7 editor's conservative alphabet")
    parsed = urlsplit(api_url)
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("API URL must be an HTTPS origin without credentials, path or query")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("API URL port is invalid") from exc
    if out.exists():
        raise FileExistsError(f"Refusing to overwrite {out}")
    vendor_begin, vendor_end = _scripts(reference)
    editor = EDITOR.read_bytes()
    if reference_builder.digest(editor) != EDITOR_SHA256 or not editor.startswith(b"#!/bin/sh\n"):
        raise ValueError("Unexpected API-only editor")
    key = key_file.read_bytes()
    if len(key) != 16 or reference_builder.digest(key) != reference_builder.KEY_SHA256:
        raise ValueError("Firmware-wide OTA key does not match the inspected Q7")

    path = '"${Q7_IOT_JSON_PATH:-/userdata/rriot/data_dir/iot.json}"'
    args = {
        "set-api": f"set -- set {path} '{api_url}'\n",
        "restore-api": f"set -- restore {path}\n",
    }
    out.mkdir(parents=True)
    result: dict[str, object] = {
        "model": "roborock.vacuum.sc05",
        "target_firmware": "03.01.74",
        "signed": False,
        "api_url": api_url,
        "editor_sha256": reference_builder.digest(editor),
        "vendor_end_sha256": reference_builder.digest(vendor_end),
        "hardware_tested": False,
        "packages": {},
    }
    packages = result["packages"]
    assert isinstance(packages, dict)
    for mode, argument_line in args.items():
        begin = vendor_begin + b"\n" + argument_line.encode("ascii") + editor
        encrypted = _package(begin, vendor_end, key)
        name = f"q7-{mode}-v03.bin.gz.aes"
        (out / name).write_bytes(encrypted)
        packages[mode] = {
            "file": name,
            "size": len(encrypted),
            "md5": hashlib.md5(encrypted).hexdigest(),
            "sha256": reference_builder.digest(encrypted),
            "begin_sha256": reference_builder.digest(begin),
        }
    (out / "metadata.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True, help="decompressed captured vendor OTA")
    parser.add_argument("--key-file", type=Path, required=True, help="private firmware-wide OTA key")
    parser.add_argument("--api-url", required=True, help="staged HTTPS API URL; MQTT stays unchanged")
    parser.add_argument("--out", type=Path, required=True, help="new private output directory")
    args = parser.parse_args()
    result = build(args.reference, args.key_file, args.api_url, args.out)
    print(json.dumps({"hardware_tested": False, "packages": result["packages"]}, indent=2))


if __name__ == "__main__":
    main()
