"""Preflight or send one owner-authenticated Q7 migration OTA.

The Q7 must still be online in the owner's Roborock account. This tool uses
normal account login and the current cloud DUID/local key; it needs no device
dump or factory HMAC secret. Without --live it sends read-only queries only.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit
from urllib.request import urlopen

import aiohttp
from roborock.data import UserData
from roborock.devices.rpc.b01_q7_channel import send_decoded_command
from roborock.devices.transport.mqtt_channel import MqttChannel
from roborock.mqtt.roborock_session import create_mqtt_session
from roborock.protocol import create_mqtt_params
from roborock.protocols.b01_q7_protocol import Q7RequestMessage
from roborock.web_api import RoborockApiClient

try:
    from .q7_stage_ota import inspect
except ImportError:  # Direct ``python scripts/q7_owner_ota.py`` execution.
    from q7_stage_ota import inspect


def package_request(artifact_dir: Path, url: str) -> dict[str, object]:
    payload, metadata = inspect(artifact_dir)
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Package URL must be HTTP(S) and reachable by the vacuum")
    if parsed.hostname in ("localhost", "127.0.0.1", "::1") or parsed.fragment:
        raise ValueError("Package URL cannot use a loopback host or fragment")
    with urlopen(url, timeout=15) as response:
        hosted = response.read(len(payload) + 1)
    if hosted != payload:
        raise ValueError("Hosted package differs from the pinned local artifact")
    return {
        "packageUrl": url,
        "md5": metadata["encrypted_md5"],
        "packageSize": str(len(payload)),
        "signed": False,
        "packageType": "robot",
    }


async def _account(args: argparse.Namespace, web_session: aiohttp.ClientSession) -> tuple[RoborockApiClient, UserData]:
    if args.account:
        saved = json.loads(args.account.read_text(encoding="utf-8"))
        if not isinstance(saved, dict) or not isinstance(saved.get("username"), str):
            raise ValueError("Account JSON must contain username and user_data")
        owner = UserData.from_dict(saved["user_data"])
        api = RoborockApiClient(saved["username"], base_url=saved.get("base_url"), session=web_session)
        return api, owner
    if not args.email:
        raise ValueError("Provide --email for code login or --account for an existing private account export")
    api = RoborockApiClient(args.email, session=web_session)
    await api.request_code_v4()
    code = input("Roborock email login code: ").strip()
    if not code:
        raise ValueError("A login code is required")
    return api, await api.code_login_v4(code)


async def run(args: argparse.Namespace) -> dict[str, object]:
    async with aiohttp.ClientSession() as web_session:
        api, owner = await _account(args, web_session)
        home = await api.get_home_data_v3(owner)
    models = {product.id: product.model for product in home.products}
    if args.list:
        return {
            "devices": [{
                "duid": device.duid,
                "firmware": device.fv,
                "cloud_online": device.online,
                "local_key_length": len(device.local_key or ""),
            } for device in home.devices if models.get(device.product_id) == "roborock.vacuum.sc05"],
            "command_sent": False,
        }
    candidates = [device for device in home.devices if device.duid == args.duid]
    if len(candidates) != 1:
        raise ValueError("Exactly one device with the selected cloud DUID must belong to this account")
    device = candidates[0]
    if models.get(device.product_id) != "roborock.vacuum.sc05":
        raise ValueError("The selected cloud device is not a Q7 sc05")
    report: dict[str, object] = {
        "duid_hash": hashlib.sha256(device.duid.encode()).hexdigest()[:12],
        "model": models[device.product_id],
        "firmware": device.fv,
        "cloud_online": device.online,
        "package_sha256": hashlib.sha256((args.artifact_dir / "q7-migration-v03.bin.gz.aes").read_bytes()).hexdigest(),
        "command_sent": False,
    }
    if device.online is not True or device.fv != "03.01.74" or len(device.local_key or "") != 16:
        report["aborted"] = "Q7 must be cloud-online on 03.01.74 with a current 16-byte local key"
        return report
    mqtt_params = create_mqtt_params(owner.rriot)
    session = await create_mqtt_session(mqtt_params)
    try:
        channel = MqttChannel(session, device.duid, device.local_key, owner.rriot, mqtt_params)

        async def query(method: str, params: dict[str, object]) -> object:
            return await asyncio.wait_for(send_decoded_command(
                channel, Q7RequestMessage(dps=10000, command=method, params=params)
            ), timeout=15)

        status = await query("prop.get", {"property": ["status"]})
        progress = await query("ota.progress.get", {})
        report["work_status"] = status.get("status") if isinstance(status, dict) else None
        report["ota_state"] = progress.get("state") if isinstance(progress, dict) else None
        if report["work_status"] != 4 or report["ota_state"] != "idle":
            report["aborted"] = "Q7 must be charging with OTA idle"
            return report
        # Verify the temporary hosted URL immediately before it could be sent.
        request = package_request(args.artifact_dir, args.url)
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
    identity.add_argument("--account", type=Path, help="private JSON with username, base_url, user_data")
    parser.add_argument("--list", action="store_true", help="list account-owned Q7 DUIDs; no device connection")
    parser.add_argument("--duid", help="current cloud DUID from the owner's account")
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--url", help="HTTP(S) URL serving the exact encrypted artifact")
    parser.add_argument("--live", action="store_true", help="send the single OTA command after preflight")
    args = parser.parse_args()
    if args.list:
        if args.duid or args.artifact_dir or args.url or args.live:
            parser.error("--list cannot be combined with OTA options")
    elif not args.duid or not args.artifact_dir or not args.url:
        parser.error("--duid, --artifact-dir and --url are required for an OTA preflight")
    try:
        print(json.dumps(asyncio.run(run(args)), sort_keys=True), flush=True)
    except Exception as exc:
        print(json.dumps({"status": "error", "error_type": type(exc).__name__}), flush=True)
        raise SystemExit(1) from None


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    main()
