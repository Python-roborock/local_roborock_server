"""Build a Q7 custom-region OTA from a pinned firmware-wide profile.

The profile is firmware-wide, not a dump of the next owner's vacuum. Its OTA
key and the output package are private. Cloud-identity fingerprints remain in
metadata and are not embedded in the OTA script. This command only builds
files; it does not host an update or contact a device.
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
REENTRY_SCHEMA = "q7-sc05-03.01.74-migration-profile-v2"
EXPERIMENTAL_030180_SCHEMA = "q7-sc05-03.01.80-migration-profile-v1"
MODEL = "roborock.vacuum.sc05"
VERSION = "03.01.74"
FIELDS = ("api_url", "mqtt_url", "mqtt_clientid", "mqtt_usr", "mqtt_passwd")
RESTORE_NAME = "q7-restore-local-v03.bin.gz.aes"
# This companion script restored the inspected Q7's saved vendor IoT profile.
# It does not contain device-specific values; it uses the adjacent rollback copy
# made by the migration editor. Keep its bytes stable for physical-test parity.
RESTORE_BEGIN = b"""#!/bin/sh
set -eu
json_path=${Q7_IOT_JSON_PATH:-/userdata/rriot/data_dir/iot.json}
backup=${json_path}.before-q7-local-edit
bb=${Q7_BUSYBOX:-/bin/busybox}
case "$json_path" in */iot.json) ;; *) exit 1 ;; esac
[ -f "$json_path" ] && [ ! -L "$json_path" ] || exit 1
[ -f "$backup" ] && [ ! -L "$backup" ] || exit 1
[ -x "$bb" ] || exit 1
tmp=$("$bb" mktemp "${json_path}.restore.XXXXXX") || exit 1
trap '"$bb" rm -f -- "$tmp"' EXIT
"$bb" cp -p "$backup" "$tmp" || exit 1
"$bb" cmp -s "$backup" "$tmp" || exit 1
"$bb" mv -f "$tmp" "$json_path" || exit 1
"$bb" sync
"""
PROFILE_HASHES = {
    "ota-key.bin": "a02bdcf7b3afdb5b0dce179326d81839c9d04d5bfb47fd318aba777633b01f5e",
    "return.sh": "cffc933b62405211a18157c47c425344854607e7bdb830cac8fee527bc391a0c",
    "editor.sh": "80ba06173a49e476d606d6f39610b2ed976e9f559961df80262f873e7623df01",
}
REENTRY_PROFILE_HASHES = {
    **PROFILE_HASHES,
    "editor.sh": "2fce38f7ba828b361fa644c5e8fea8c5858f9bc0eeaeab931610e18e6da3fb04",
}
EXPERIMENTAL_030180_HASHES = {
    "ota-key.bin": PROFILE_HASHES["ota-key.bin"],
    "return.sh": "a5f599aaaa53c898090b81ff8e8a9a9312e48e75f18fb0a93f523492a6cacc26",
    "editor.sh": REENTRY_PROFILE_HASHES["editor.sh"],
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


def _profile(path: Path) -> tuple[bytes, bytes, bytes, str, str]:
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("The firmware-wide profile manifest is malformed")
    schema = manifest.get("schema")
    spec = {
        SCHEMA: (VERSION, PROFILE_HASHES),
        REENTRY_SCHEMA: (VERSION, REENTRY_PROFILE_HASHES),
        EXPERIMENTAL_030180_SCHEMA: ("03.01.80", EXPERIMENTAL_030180_HASHES),
    }.get(schema)
    if spec is None:
        raise ValueError("The firmware-wide profile is not the inspected Q7 build")
    version, expected = spec
    if (manifest.get("model") != MODEL
            or manifest.get("firmware_version") != version
            or manifest.get("file_sha256") != expected):
        raise ValueError("The firmware-wide profile is not the inspected Q7 build")
    blobs = {}
    for name, expected_hash in expected.items():
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
    return key, end, editor, schema, version


def build(config: object, profile: Path, out: Path) -> dict[str, object]:
    if not isinstance(config, dict):
        raise ValueError("Migration config must be an object")
    preflight = config.get("_preflight")
    if preflight is not None:
        if (not isinstance(preflight, dict)
                or set(preflight) != {"duid_sha256", "local_key_sha256"}
                or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                       for value in preflight.values())):
            raise ValueError("Migration preflight fingerprints are malformed")
    values = _fields({name: value for name, value in config.items() if name != "_preflight"})
    config_sha256 = _sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode("ascii"))
    if out.exists():
        raise FileExistsError(f"Refusing to overwrite {out}")
    key, end, editor, schema, version = _profile(profile)
    args = ['"${Q7_IOT_JSON_PATH:-/userdata/rriot/data_dir/iot.json}"']
    args.extend("'" + values[name] + "'" for name in FIELDS)
    begin = ("#!/bin/sh\nset -- " + " ".join(args) + "\n").encode("ascii") + editor.split(b"\n", 1)[1]
    encrypted = _package(begin, end, key)
    restore_encrypted = _package(RESTORE_BEGIN, end, key)

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
    restore_path = out / RESTORE_NAME
    restore_descriptor = os.open(restore_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(restore_descriptor, "wb") as handle:
        handle.write(restore_encrypted)
    metadata: dict[str, object] = {
        "firmware": f"{MODEL} {version}, pinned inspected firmware profile",
        "target_firmware": version,
        "package": name,
        "encrypted_size_bytes": len(encrypted),
        "encrypted_md5": hashlib.md5(encrypted).hexdigest(),
        "encrypted_sha256": _sha256(encrypted),
        "begin_sha256": _sha256(begin),
        "end_sha256": _sha256(end),
        "build_mode": "portable_profile",
        "profile_schema": schema,
        "signed": False,
        "hardware_tested": False,
        "secrets_in_package": True,
        "config_field_names": list(FIELDS),
        "config_sha256": config_sha256,
        "preflight": preflight,
        "restore_package": {
            "package": RESTORE_NAME,
            "encrypted_size_bytes": len(restore_encrypted),
            "encrypted_md5": hashlib.md5(restore_encrypted).hexdigest(),
            "encrypted_sha256": _sha256(restore_encrypted),
            "begin_sha256": _sha256(RESTORE_BEGIN),
            "end_sha256": _sha256(end),
            "secrets_in_package": False,
        },
    }
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="private JSON manifest with five IoT fields and cloud-key preflight fingerprints")
    parser.add_argument("--profile", type=Path, required=True, help="private firmware-wide OTA profile")
    parser.add_argument("--out", type=Path, required=True, help="new private artifact directory")
    args = parser.parse_args()
    metadata = build(json.loads(args.config.read_text(encoding="utf-8")), args.profile, args.out)
    summary = {key: metadata[key] for key in (
        "package", "encrypted_size_bytes", "encrypted_md5", "encrypted_sha256", "hardware_tested"
    )}
    summary["restore_package"] = {
        key: metadata["restore_package"][key] for key in (
            "package", "encrypted_size_bytes", "encrypted_md5", "encrypted_sha256"
        )
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
