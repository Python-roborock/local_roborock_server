"""Build a Q7 03.01.74 custom-region OTA from a shared firmware profile.

The profile is firmware-wide, not a dump of the next owner's vacuum. Its OTA
key and the output package are private. This command only builds files; it
does not host an update or contact a device.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

try:
    from .q7_api_only_ota_builder import _package
except ImportError:  # Direct ``python scripts/q7_migration_ota_builder.py`` execution.
    from q7_api_only_ota_builder import _package


SCHEMA = "q7-sc05-03.01.74-migration-profile-v1"
MODEL = "roborock.vacuum.sc05"
VERSION = "03.01.74"
FIELDS = ("api_url", "mqtt_url", "mqtt_clientid", "mqtt_usr", "mqtt_passwd")
PROFILE_HASHES = {
    "ota-key.bin": "a02bdcf7b3afdb5b0dce179326d81839c9d04d5bfb47fd318aba777633b01f5e",
    "return.sh": "cffc933b62405211a18157c47c425344854607e7bdb830cac8fee527bc391a0c",
    "editor.sh": "80ba06173a49e476d606d6f39610b2ed976e9f559961df80262f873e7623df01",
}
URL_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[A-Za-z0-9._:/+\-]+$")
HEX_LENGTHS = {"mqtt_clientid": 16, "mqtt_usr": 16, "mqtt_passwd": 32}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fields(raw: object) -> dict[str, str]:
    if not isinstance(raw, dict) or set(raw) != set(FIELDS):
        raise ValueError("Migration config must contain exactly the five IoT fields")
    values = {}
    for name in FIELDS:
        value = raw[name]
        if not isinstance(value, str):
            raise ValueError(f"{name} must be a string")
        values[name] = value
    for name, scheme in (("api_url", "https://"), ("mqtt_url", "ssl://")):
        value = values[name]
        if not value.startswith(scheme) or len(value) > 240 or not URL_PATTERN.fullmatch(value):
            raise ValueError(f"{name} must be a supported {scheme} URL up to 240 characters")
        parsed = urlsplit(value)
        if (not parsed.hostname or parsed.username or parsed.password or parsed.query
                or parsed.fragment or parsed.path not in ("", "/")):
            raise ValueError(f"{name} must be an origin without credentials, path, or query")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError(f"{name} has an invalid port") from exc
    for name, length in HEX_LENGTHS.items():
        if not re.fullmatch(rf"[0-9a-fA-F]{{{length}}}", values[name]):
            raise ValueError(f"{name} must be {length} hexadecimal characters")
    return values


def _profile(path: Path) -> tuple[bytes, bytes, bytes]:
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    if (not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA
            or manifest.get("model") != MODEL or manifest.get("firmware_version") != VERSION
            or manifest.get("file_sha256") != PROFILE_HASHES):
        raise ValueError("The firmware-wide profile is not the inspected Q7 build")
    blobs = {}
    for name, expected_hash in PROFILE_HASHES.items():
        item = path / name
        if item.is_symlink() or not item.is_file():
            raise ValueError(f"Profile file {name} must be a regular file")
        blob = item.read_bytes()
        if _sha256(blob) != expected_hash:
            raise ValueError(f"Profile file {name} failed its pinned hash")
        blobs[name] = blob
    key, end, editor = blobs["ota-key.bin"], blobs["return.sh"], blobs["editor.sh"]
    if len(key) != 16 or not end.startswith(b"#!/bin/sh\n") or not editor.startswith(b"#!/bin/sh\n"):
        raise ValueError("Profile key or recovery scripts have unexpected structure")
    return key, end, editor


def build(config: object, profile: Path, out: Path) -> dict[str, object]:
    values = _fields(config)
    if out.exists():
        raise FileExistsError(f"Refusing to overwrite {out}")
    key, end, editor = _profile(profile)
    args = ['"${Q7_IOT_JSON_PATH:-/userdata/rriot/data_dir/iot.json}"']
    args.extend("'" + values[name] + "'" for name in FIELDS)
    begin = ("#!/bin/sh\nset -- " + " ".join(args) + "\n").encode("ascii") + editor.split(b"\n", 1)[1]
    encrypted = _package(begin, end, key)

    out.mkdir(parents=True)
    try:
        out.chmod(0o700)
    except OSError:
        pass
    name = "q7-migration-v03.bin.gz.aes"
    artifact = out / name
    descriptor = os.open(artifact, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encrypted)
    metadata: dict[str, object] = {
        "firmware": f"{MODEL} {VERSION}, pinned inspected firmware profile",
        "package": name,
        "encrypted_size_bytes": len(encrypted),
        "encrypted_md5": hashlib.md5(encrypted).hexdigest(),
        "encrypted_sha256": _sha256(encrypted),
        "begin_sha256": _sha256(begin),
        "end_sha256": _sha256(end),
        "build_mode": "portable_profile",
        "signed": False,
        "hardware_tested": False,
        "secrets_in_package": True,
        "config_field_names": list(FIELDS),
    }
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="private five-field JSON manifest")
    parser.add_argument("--profile", type=Path, required=True, help="private firmware-wide OTA profile")
    parser.add_argument("--out", type=Path, required=True, help="new private artifact directory")
    args = parser.parse_args()
    metadata = build(json.loads(args.config.read_text(encoding="utf-8")), args.profile, args.out)
    print(json.dumps({key: metadata[key] for key in (
        "package", "encrypted_size_bytes", "encrypted_md5", "encrypted_sha256", "hardware_tested"
    )}, indent=2))


if __name__ == "__main__":
    main()
