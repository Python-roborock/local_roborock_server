"""Import the Q7 bootstrap secret from a local dump, without printing credentials."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile


def import_device(device_file: Path, iot_file: Path, output: Path) -> None:
    device = json.loads(device_file.read_text(encoding="utf-8"))
    iot = json.loads(iot_file.read_text(encoding="utf-8"))
    did, model = str(device["did"]), device["model"]
    secret, duid = device["secret"], iot["duid"]
    if not did.isascii() or not did.isdecimal() or model != "roborock.vacuum.sc05":
        raise ValueError("Expected a Q7 sc05 device with a numeric DID")
    if not isinstance(secret, str) or not 24 <= len(secret.encode("ascii")) <= 64:
        raise ValueError("Invalid Q7 device secret")
    if not isinstance(duid, str) or not 1 <= len(duid.encode("ascii")) <= 32:
        raise ValueError("Invalid Q7 cloud DUID")
    state = (
        json.loads(output.read_text(encoding="utf-8"))
        if output.exists()
        else {"devices": {}}
    )
    if not isinstance(state, dict) or not isinstance(state.get("devices"), dict):
        raise ValueError("Invalid B01 device state file")
    entry = {"model": model, "duid": duid, "secret": secret}
    if did in state["devices"] and state["devices"][did] != entry:
        raise ValueError(
            "A different entry already exists for this DID; review it before replacing"
        )
    state["devices"][did] = entry
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(dir=output.parent, prefix=".b01-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, indent=2)
            stream.write("\n")
        os.replace(temp_path, output)
    finally:
        Path(temp_path).unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-config", type=Path, required=True)
    parser.add_argument("--iot-config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    import_device(args.device_config, args.iot_config, args.output)
    print(
        f"Imported Q7 bootstrap configuration into {args.output}; credentials were not displayed."
    )


if __name__ == "__main__":
    main()
