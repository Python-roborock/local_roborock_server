"""Preflight or restore a migrated Q7 to its saved vendor region.

Uses the current owner's cloud inventory for the device local key and the
five-field migration manifest for the local broker credentials. The companion
restore package must come from the same portable build as the migration OTA.
Without --live this sends only read-only owner queries to the local Q7.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import secrets
import sys
from urllib.parse import urlsplit

import aiohttp
from roborock.data import RRiot, Reference
from roborock.devices.rpc.b01_q7_channel import send_decoded_command
from roborock.devices.transport.mqtt_channel import MqttChannel
from roborock.mqtt.roborock_session import create_mqtt_session
from roborock.mqtt.session import MqttParams
from roborock.protocols.b01_q7_protocol import Q7RequestMessage

try:
    from .q7_owner_ota import _account, package_request
except ImportError:  # Direct ``python scripts/q7_local_restore.py`` execution.
    from q7_owner_ota import _account, package_request


def _broker(manifest_path: Path) -> tuple[str, int, str, str, str]:
    values = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(values, dict) or set(values) != {
        "api_url", "mqtt_url", "mqtt_clientid", "mqtt_usr", "mqtt_passwd"
    }:
        raise ValueError("Expected the exact five-field migration manifest")
    url = urlsplit(values["mqtt_url"])
    if (url.scheme != "ssl" or not url.hostname or url.username or url.password
            or url.path not in ("", "/") or url.query or url.fragment):
        raise ValueError("Migration manifest has an invalid local MQTT origin")
    port = url.port or 8883
    for name, length in (("mqtt_clientid", 16), ("mqtt_usr", 16), ("mqtt_passwd", 32)):
        value = values[name]
        if not isinstance(value, str) or len(value) != length or any(c not in "0123456789abcdefABCDEF" for c in value):
            raise ValueError(f"Migration manifest has an invalid {name}")
    return url.hostname, port, values["mqtt_usr"], values["mqtt_passwd"], values["mqtt_url"]


async def run(args: argparse.Namespace) -> dict[str, object]:
    request = package_request(args.artifact_dir, args.url, package_kind="restore")
    source = json.loads(args.config.read_text(encoding="utf-8"))
    metadata = json.loads((args.artifact_dir / "metadata.json").read_text(encoding="utf-8"))
    target_firmware = metadata.get("target_firmware", "03.01.74")
    if target_firmware not in ("03.01.74", "03.01.80"):
        raise ValueError("Restore package targets an unsupported Q7 firmware")
    config_sha256 = hashlib.sha256(
        json.dumps(source, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    if metadata.get("config_sha256") != config_sha256:
        raise ValueError("Restore manifest differs from the migration package input")
    host, port, username, password, mqtt_url = _broker(args.config)
    async with aiohttp.ClientSession() as web_session:
        api, owner = await _account(args, web_session)
        home = await api.get_home_data_v3(owner)
    models = {product.id: product.model for product in home.products}
    candidates = [device for device in home.devices if device.duid == args.duid]
    if len(candidates) != 1:
        raise ValueError("Exactly one device with the selected DUID must belong to this account")
    device = candidates[0]
    if (models.get(device.product_id) != "roborock.vacuum.sc05"
            or device.fv != target_firmware or len(device.local_key or "") != 16):
        raise ValueError(f"Selected device must be a Q7 sc05 on {target_firmware} with a 16-byte local key")
    report: dict[str, object] = {
        "duid_hash": hashlib.sha256(device.duid.encode()).hexdigest()[:12],
        "model": models[device.product_id],
        "firmware": device.fv,
        "target_firmware": target_firmware,
        "package_sha256": hashlib.sha256(
            (args.artifact_dir / "q7-restore-local-v03.bin.gz.aes").read_bytes()
        ).hexdigest(),
        "command_sent": False,
    }
    rriot = RRiot(
        u="q7-local-restore", s=secrets.token_hex(16), h=secrets.token_hex(5),
        k=device.local_key,
        r=Reference(r="US", a="", m=mqtt_url, l=""),
    )
    params = MqttParams(host=host, port=port, tls=True, username=username, password=password)
    session = await create_mqtt_session(params)
    try:
        channel = MqttChannel(session, device.duid, device.local_key, rriot, params)

        async def query(method: str, arguments: dict[str, object]) -> object:
            return await asyncio.wait_for(send_decoded_command(
                channel, Q7RequestMessage(dps=10000, command=method, params=arguments)
            ), timeout=15)

        status = await query("prop.get", {"property": ["status"]})
        progress = await query("ota.progress.get", {})
        report["work_status"] = status.get("status") if isinstance(status, dict) else None
        report["ota_state"] = progress.get("state") if isinstance(progress, dict) else None
        if report["work_status"] != 4 or report["ota_state"] != "idle":
            report["aborted"] = "Q7 must be charging with OTA idle"
            return report
        if not args.live:
            return report
        response = await query("ota.upgrade.set", request)
        report["command_sent"] = True
        report["set_result"] = response.get("result") if isinstance(response, dict) else None
        observations: list[object] = []
        for _ in range(8):
            await asyncio.sleep(2)
            try:
                state = await query("ota.progress.get", {})
                observations.append(state.get("state") if isinstance(state, dict) else type(state).__name__)
            except Exception as exc:
                observations.append(type(exc).__name__)
                break
        report["ota_states_after"] = observations
        return report
    finally:
        await session.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    identity = parser.add_mutually_exclusive_group(required=True)
    identity.add_argument("--email", help="Roborock account email; requests a login code")
    identity.add_argument("--account", type=Path, help="private owner account JSON export")
    parser.add_argument("--duid", required=True, help="current cloud DUID from this account")
    parser.add_argument("--config", type=Path, required=True, help="private five-field migration manifest")
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--url", required=True, help="HTTP(S) URL serving the companion restore package")
    parser.add_argument("--live", action="store_true", help="send one restore OTA after preflight")
    args = parser.parse_args()
    try:
        print(json.dumps(asyncio.run(run(args)), sort_keys=True), flush=True)
    except Exception as exc:
        print(json.dumps({"status": "error", "error_type": type(exc).__name__}), flush=True)
        raise SystemExit(1) from None


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    main()
