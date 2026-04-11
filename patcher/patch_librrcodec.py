#!/usr/bin/env python3
"""Patch librrcodec.so to remove the signing-cert check.

Tested on Roborock app 4.60.06.
"""

import struct
import sys
from pathlib import Path

NOP = struct.pack("<I", 0xD503201F)
OFFSETS = (0x4ADCC, 0x4B428)


def main() -> int:
    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
    else:
        found = list(Path.cwd().rglob("librrcodec.so"))
        if not found:
            print("usage: patch_librrcodec.py [path/to/librrcodec.so]")
            return 1
        target = next((p for p in found if "arm64-v8a" in p.parts), found[0])
        print(f"Found: {target}")

    with open(target, "r+b") as f:
        data = bytearray(f.read())
        for offset in OFFSETS:
            data[offset:offset + 4] = NOP
        f.seek(0)
        f.write(data)

    print("Patched successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())