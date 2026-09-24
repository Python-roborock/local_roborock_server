"""Validate a locally built Q7 migration or restore OTA before hosting it."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


PACKAGE_NAME = "q7-migration-v03.bin.gz.aes"
RESTORE_PACKAGE_NAME = "q7-restore-local-v03.bin.gz.aes"
MAX_PACKAGE_BYTES = 4 * 1024 * 1024


def inspect(artifact_dir: Path, *, package_kind: str = "") -> tuple[bytes, dict[str, object]]:
    directory = artifact_dir.resolve()
    metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
    if not isinstance(metadata, dict) or metadata.get("signed") is not False:
        raise ValueError("Expected an unsigned Q7 migration metadata object")
    version = metadata.get("target_firmware")
    if (version not in ("03.01.74", "03.01.80")
            or f"roborock.vacuum.sc05 {version}" not in str(metadata.get("firmware", ""))):
        raise ValueError("Package metadata does not name the inspected Q7 firmware")
    if version == "03.01.80" and metadata.get("profile_schema") != (
        "q7-sc05-03.01.80-migration-profile-v1"
    ):
        raise ValueError("03.01.80 requires its version-specific profile")
    if package_kind == "restore":
        selected = metadata.get("restore_package")
        if not isinstance(selected, dict) or selected.get("package") != RESTORE_PACKAGE_NAME:
            raise ValueError("Companion restore package is missing")
        name = selected["package"]
        expected_size = selected.get("encrypted_size_bytes")
        expected_sha = selected.get("encrypted_sha256")
        expected_md5 = selected.get("encrypted_md5")
    elif not package_kind:
        name = metadata.get("package")
        if name != PACKAGE_NAME:
            raise ValueError("Unexpected Q7 migration package name")
        expected_size = metadata.get("encrypted_size_bytes")
        expected_sha = metadata.get("encrypted_sha256")
        expected_md5 = metadata.get("encrypted_md5")
    else:
        raise ValueError("Unsupported Q7 package selection")
    package = directory / name
    if package.is_symlink() or package.resolve().parent != directory:
        raise ValueError("Package must be a regular file in the artifact directory")
    payload = package.read_bytes()
    if not payload or len(payload) > MAX_PACKAGE_BYTES or len(payload) % 16:
        raise ValueError("Package length is outside the AES-aligned limit")
    digest_sha = hashlib.sha256(payload).hexdigest()
    digest_md5 = hashlib.md5(payload).hexdigest()
    if (expected_size != len(payload) or expected_sha != digest_sha or expected_md5 != digest_md5):
        raise ValueError("Package bytes do not match metadata")
    return payload, {
        "package": name,
        "encrypted_size_bytes": len(payload),
        "encrypted_sha256": digest_sha,
        "encrypted_md5": digest_md5,
        "target_firmware": version,
        "preflight": metadata.get("preflight"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--package", choices=("restore",))
    args = parser.parse_args()
    _payload, result = inspect(args.artifact_dir, package_kind=args.package or "")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
