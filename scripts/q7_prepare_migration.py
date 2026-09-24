"""Reserve local MQTT credentials for an experimental dump-free Q7 migration.

Requires the local server's new admin endpoint and an existing cloud import
with the Q7 cloud DUID and true local key. A numeric DID is not required.
Writes a private JSON input with five IoT fields and cloud-identity fingerprints
for the offline OTA builder. This sends no command or package to the vacuum.
"""

from __future__ import annotations

import argparse
from getpass import getpass
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

import httpx


URL_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[A-Za-z0-9._:/+\-]+$")


def _https_origin(raw: str) -> str:
    parsed = urlsplit(raw)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("--server must be an HTTPS origin without embedded credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("--server must not include a path, query, or fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("--server has an invalid port") from exc
    return raw.rstrip("/")


def _target_url(raw: str, *, field: str, scheme: str) -> str:
    if not raw.startswith(scheme + "://") or len(raw) > 240 or not URL_PATTERN.fullmatch(raw):
        raise ValueError(f"{field} must be a supported {scheme} URL of at most 240 characters")
    parsed = urlsplit(raw)
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError(f"{field} must have a host and no embedded credentials or fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError(f"{field} has an invalid port") from exc
    return raw


def prepare(*, server: str, duid: str, api_url: str,
            mqtt_url: str, out: Path, admin_password: str,
            did: str = "") -> dict[str, str]:
    origin = _https_origin(server)
    api_url = _target_url(api_url, field="api_url", scheme="https")
    mqtt_url = _target_url(mqtt_url, field="mqtt_url", scheme="ssl")
    if out.exists():
        raise FileExistsError(f"Refusing to overwrite {out}")
    if not duid.strip():
        raise ValueError("Cloud DUID is required")
    with httpx.Client(base_url=origin, timeout=15.0, follow_redirects=False) as client:
        login = client.post("/admin/api/login", json={"password": admin_password})
        login.raise_for_status()
        response = client.post(
            "/admin/api/q7/migration-credentials",
            json={"did": did.strip(), "duid": duid.strip()},
        )
        response.raise_for_status()
        payload = response.json()
    if payload.get("duid") != duid.strip() or (did.strip() and payload.get("did") != did.strip()):
        raise ValueError("Server response does not match the requested Q7 identity")
    local_key_sha256 = payload.get("local_key_sha256")
    if not isinstance(local_key_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", local_key_sha256):
        raise ValueError("Server did not provide a valid cloud-imported local-key fingerprint")
    fields = {
        "api_url": api_url,
        "mqtt_url": mqtt_url,
        "mqtt_clientid": str(payload["mqtt_clientid"]),
        "mqtt_usr": str(payload["mqtt_usr"]),
        "mqtt_passwd": str(payload["mqtt_passwd"]),
        "_preflight": {
            "duid_sha256": hashlib.sha256(duid.strip().encode("utf-8")).hexdigest(),
            "local_key_sha256": local_key_sha256,
        },
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(out, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(fields, handle, indent=2)
            handle.write("\n")
    except BaseException:
        out.unlink(missing_ok=True)
        raise
    return {"did": str(payload.get("did") or ""), "duid": duid.strip(), "manifest": str(out.resolve())}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, help="HTTPS admin origin, e.g. https://api.example.com:555")
    parser.add_argument("--did", default="", help="optional known numeric device ID")
    parser.add_argument("--duid", required=True)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--mqtt-url", required=True)
    parser.add_argument("--out", type=Path, required=True, help="new private manifest path")
    args = parser.parse_args()
    admin_password = getpass("Local server admin password: ")
    result = prepare(
        server=args.server,
        did=args.did,
        duid=args.duid,
        api_url=args.api_url,
        mqtt_url=args.mqtt_url,
        out=args.out,
        admin_password=admin_password,
    )
    print(json.dumps({**result, "device_command_sent": False}, indent=2))


if __name__ == "__main__":
    main()
