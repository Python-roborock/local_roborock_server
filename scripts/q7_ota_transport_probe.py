"""Probe Q7 owner-MQTT OTA command delivery with an impossible package.

The URL is robot loopback port 1 and the expected MD5 is all zeroes. The
firmware's download/verification failure path returns before install/reboot.
This is a controlled-device research probe, not an update mechanism.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import secrets
from pathlib import Path
from typing import Any

from roborock.data import RRiot, Reference
from roborock.devices.rpc.b01_q7_channel import send_decoded_command
from roborock.devices.transport.mqtt_channel import MqttChannel
from roborock.mqtt.roborock_session import create_mqtt_session
from roborock.protocol import create_mqtt_params
from roborock.protocols.b01_q7_protocol import Q7RequestMessage
from roborock_local_server.bundled_backend.shared.runtime_credentials import RuntimeCredentialsStore


PROBE_URL = "http://127.0.0.1:1/q7-ota-transport-probe"
PROBE_MD5 = "0" * 32
PROBE_PARAMS: dict[str, Any] = {
    "packageUrl": PROBE_URL,
    "md5": PROBE_MD5,
    "packageSize": "16",
    "signed": False,
    "packageType": "robot",
}


async def probe(args: argparse.Namespace) -> dict[str, Any]:
    credentials = RuntimeCredentialsStore(Path(args.credentials))
    matches = [
        device
        for device in credentials.devices()
        if str(device.get("did")) == args.did and device.get("duid") == args.duid
    ]
    if len(matches) != 1:
        raise ValueError(f"Expected one exact DID/DUID record; found {len(matches)}")
    local_key = matches[0].get("localkey", "")
    mqtt_user = str(credentials.bootstrap_value("mqtt_usr", ""))
    mqtt_password = str(credentials.bootstrap_value("mqtt_passwd", ""))
    backend_port = int(credentials.bootstrap_value("mqtt_backend_port", 18830))
    if not (local_key and mqtt_user and mqtt_password):
        raise ValueError("Runtime record lacks MQTT credentials or local key")

    report: dict[str, Any] = {
        "mode": "dry-run" if not args.live else "live",
        "target_match_count": len(matches),
        "url": PROBE_URL,
        "md5": PROBE_MD5,
        "packageSize": PROBE_PARAMS["packageSize"],
        "signed": False,
        "packageType": PROBE_PARAMS["packageType"],
    }
    if not args.live:
        return report

    rriot = RRiot(
        u=mqtt_user,
        s=mqtt_password,
        h=secrets.token_hex(5),
        k=local_key,
        r=Reference(r="US", a="", m=f"tcp://127.0.0.1:{backend_port}", l=""),
    )
    mqtt_params = create_mqtt_params(rriot)
    session = await create_mqtt_session(mqtt_params)
    try:
        channel = MqttChannel(session, args.duid, local_key, rriot, mqtt_params)

        async def query(command: str, params: dict[str, Any]) -> Any:
            return await send_decoded_command(
                channel, Q7RequestMessage(dps=10000, command=command, params=params)
            )

        status = await query("prop.get", {"property": ["status"]})
        progress = await query("ota.progress.get", {})
        report["status_before"] = status
        report["progress_before"] = progress
        if not isinstance(status, dict) or status.get("status") != 4:
            report["aborted"] = "Q7 is not reporting charging status 4"
            return report
        if not isinstance(progress, dict) or progress.get("state") != "idle":
            report["aborted"] = "OTA state is not idle"
            return report

        try:
            report["set_response"] = await query("ota.upgrade.set", PROBE_PARAMS)
        except Exception as exc:  # A missing async acknowledgement is possible.
            report["set_error_type"] = type(exc).__name__

        observations = []
        for _ in range(4):
            await asyncio.sleep(2)
            try:
                observation = await query("ota.progress.get", {})
                observations.append(observation)
                if isinstance(observation, dict) and observation.get("state") not in ("idle", "downloading"):
                    break
            except Exception as exc:
                observations.append({"error_type": type(exc).__name__})
        report["progress_after"] = observations
        report["status_after"] = await query("prop.get", {"property": ["status"]})
        return report
    finally:
        await session.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", default="/config/runtime/runtime_credentials.json")
    parser.add_argument("--did", required=True)
    parser.add_argument("--duid", required=True)
    parser.add_argument("--live", action="store_true", help="Send one failed-download OTA command")
    args = parser.parse_args()
    try:
        print(json.dumps(asyncio.run(probe(args)), sort_keys=True))
    except Exception as exc:
        print(json.dumps({"status": "error", "error_type": type(exc).__name__}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
