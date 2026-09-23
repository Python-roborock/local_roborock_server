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
DOWNLOAD_PATH = re.compile(r"/q7/ota-package/[0-9a-f]{64}\Z")
MAX_PACKAGE_BYTES = 4 * 1024 * 1024


def inspect(artifact_dir: Path) -> tuple[bytes, dict[str, object]]:
    directory = artifact_dir.resolve()
    metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
    if not isinstance(metadata, dict) or metadata.get("signed") is not False:
        raise ValueError("Expected an unsigned Q7 research package metadata object")
    if "roborock.vacuum.sc05 03.01.74" not in str(metadata.get("firmware", "")):
        raise ValueError("Package metadata does not name the inspected Q7 firmware")
    name = metadata.get("package") or metadata.get("encrypted_file")
    if name not in PACKAGE_NAMES:
        raise ValueError("Unexpected Q7 package name")
    package = directory / str(name)
    if package.is_symlink() or package.resolve().parent != directory:
        raise ValueError("Package must be a regular file in the artifact directory")
    payload = package.read_bytes()
    if not payload or len(payload) > MAX_PACKAGE_BYTES or len(payload) % 16:
        raise ValueError("Package length is outside the AES-aligned limit")
    digest_sha = hashlib.sha256(payload).hexdigest()
    digest_md5 = hashlib.md5(payload).hexdigest()
    if (metadata.get("encrypted_size_bytes") != len(payload)
            or metadata.get("encrypted_sha256") != digest_sha
            or metadata.get("encrypted_md5") != digest_md5):
        raise ValueError("Package bytes do not match metadata")
    return payload, {
        "package": name,
        "encrypted_size_bytes": len(payload),
        "encrypted_sha256": digest_sha,
        "encrypted_md5": digest_md5,
        "hardware_tested": False,
    }


def stage(*, server: str, artifact_dir: Path, admin_password: str,
          transport: httpx.BaseTransport | None = None) -> dict[str, object]:
    origin = _https_origin(server)
    payload, details = inspect(artifact_dir)
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
    parser.add_argument("--server", help="HTTPS local-server origin; required with --stage")
    parser.add_argument("--stage", action="store_true", help="Upload bytes to the local server (no robot command)")
    args = parser.parse_args()
    if args.stage:
        if not args.server:
            parser.error("--server is required with --stage")
        result = stage(server=args.server, artifact_dir=args.artifact_dir,
                       admin_password=getpass("Local server admin password: "))
    else:
        _payload, result = inspect(args.artifact_dir)
        result["device_command_sent"] = False
        result["staged"] = False
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
