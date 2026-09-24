"""Validate or briefly stage an offline Q7 OTA candidate for a hardware trial.

This does not publish an OTA command to the robot. With --stage, it uploads
encrypted bytes to the local server's admin endpoint and prints the private
15-minute download URL. The server must run the matching source revision.
"""

from __future__ import annotations

import argparse
from getpass import getpass
import hashlib
import json
from pathlib import Path
import re

import httpx

try:
    from .q7_prepare_migration import _https_origin
except ImportError:  # Direct ``python scripts/q7_stage_ota.py`` execution.
    from q7_prepare_migration import _https_origin


PACKAGE_NAMES = {"q7-migration-v03.bin.gz.aes", "return-noop-v03.bin.gz.aes"}
RESTORE_PACKAGE_NAME = "q7-restore-local-v03.bin.gz.aes"
API_ONLY_PACKAGE_NAMES = {
    "set-api": "q7-set-api-v03.bin.gz.aes",
    "restore-api": "q7-restore-api-v03.bin.gz.aes",
}
DOWNLOAD_PATH = re.compile(r"/q7/ota-package/[0-9a-f]{64}\Z")
MAX_PACKAGE_BYTES = 4 * 1024 * 1024


def inspect(artifact_dir: Path, *, package_kind: str = "") -> tuple[bytes, dict[str, object]]:
    directory = artifact_dir.resolve()
    metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
    if not isinstance(metadata, dict) or metadata.get("signed") is not False:
        raise ValueError("Expected an unsigned Q7 research package metadata object")
    if "packages" in metadata:
        if metadata.get("model") != "roborock.vacuum.sc05" or metadata.get("target_firmware") != "03.01.74":
            raise ValueError("API-only package metadata does not name the inspected Q7 firmware")
        if package_kind not in API_ONLY_PACKAGE_NAMES:
            raise ValueError("API-only artifacts require --package set-api or restore-api")
        package_map = metadata["packages"]
        if not isinstance(package_map, dict):
            raise ValueError("API-only package metadata is malformed")
        selected = package_map.get(package_kind)
        if not isinstance(selected, dict):
            raise ValueError("Requested API-only package is missing")
        name = selected.get("file")
        if name != API_ONLY_PACKAGE_NAMES[package_kind]:
            raise ValueError("Unexpected API-only Q7 package name")
        expected_size = selected.get("size")
        expected_sha = selected.get("sha256")
        expected_md5 = selected.get("md5")
    else:
        version = metadata.get("target_firmware", "03.01.74")
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
            name = metadata.get("package") or metadata.get("encrypted_file")
            if name not in PACKAGE_NAMES:
                raise ValueError("Unexpected Q7 package name")
            expected_size = metadata.get("encrypted_size_bytes")
            expected_sha = metadata.get("encrypted_sha256")
            expected_md5 = metadata.get("encrypted_md5")
        else:
            raise ValueError("Unsupported package selection for this artifact")
    package = directory / str(name)
    if package.is_symlink() or package.resolve().parent != directory:
        raise ValueError("Package must be a regular file in the artifact directory")
    payload = package.read_bytes()
    if not payload or len(payload) > MAX_PACKAGE_BYTES or len(payload) % 16:
        raise ValueError("Package length is outside the AES-aligned limit")
    digest_sha = hashlib.sha256(payload).hexdigest()
    digest_md5 = hashlib.md5(payload).hexdigest()
    if (expected_size != len(payload)
            or expected_sha != digest_sha
            or expected_md5 != digest_md5):
        raise ValueError("Package bytes do not match metadata")
    return payload, {
        "package": name,
        "encrypted_size_bytes": len(payload),
        "encrypted_sha256": digest_sha,
        "encrypted_md5": digest_md5,
        "hardware_tested": False,
        "target_firmware": metadata.get("target_firmware", "03.01.74"),
        "preflight": metadata.get("preflight"),
    }


def stage(*, server: str, artifact_dir: Path, admin_password: str, package_kind: str = "",
          transport: httpx.BaseTransport | None = None) -> dict[str, object]:
    origin = _https_origin(server)
    payload, details = inspect(artifact_dir, package_kind=package_kind)
    with httpx.Client(base_url=origin, timeout=30.0, follow_redirects=False, transport=transport) as client:
        login = client.post("/admin/api/login", json={"password": admin_password})
        login.raise_for_status()
        response = client.post(
            "/admin/api/q7/ota-package",
            content=payload,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Q7-SHA256": str(details["encrypted_sha256"]),
                "X-Q7-MD5": str(details["encrypted_md5"]),
            },
        )
        response.raise_for_status()
        staged = response.json()
    path = str(staged.get("download_path") or "")
    if not DOWNLOAD_PATH.fullmatch(path):
        raise ValueError("Server returned an invalid Q7 download path")
    for key in ("encrypted_size_bytes", "encrypted_sha256", "encrypted_md5"):
        if staged.get(key) != details[key]:
            raise ValueError(f"Server returned mismatched {key}")
    return {
        **details,
        "download_url": origin + path,
        "expires_in_seconds": staged.get("expires_in_seconds"),
        "device_command_sent": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--package", choices=(*API_ONLY_PACKAGE_NAMES, "restore"),
                        help="Select an API-only package or the full migration restore")
    parser.add_argument("--server", help="HTTPS local-server origin; required with --stage")
    parser.add_argument("--stage", action="store_true", help="Upload bytes to the local server (no robot command)")
    args = parser.parse_args()
    if args.stage:
        if not args.server:
            parser.error("--server is required with --stage")
        result = stage(server=args.server, artifact_dir=args.artifact_dir,
                       package_kind=args.package or "",
                       admin_password=getpass("Local server admin password: "))
    else:
        _payload, result = inspect(args.artifact_dir, package_kind=args.package or "")
        result["device_command_sent"] = False
        result["staged"] = False
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
