#!/usr/bin/env python3
"""Patch librrcodec.so to remove the signing-cert check.

Tested on Roborock app 4.60.06 (build ID becc35bc1a75903df1eae3f90b380ca5403d06cb).
Aborts if the target file is a different build.
"""

import struct
import sys
from pathlib import Path

NOP = struct.pack("<I", 0xD503201F)
OFFSETS = (0x4ADCC, 0x4B428)
KNOWN_BUILD_ID = "becc35bc1a75903df1eae3f90b380ca5403d06cb"


def read_build_id(data: bytes) -> str | None:
    """Find the GNU build ID note in an ELF file."""
    needle = b"GNU\x00"
    idx = 0
    while True:
        idx = data.find(needle, idx)
        if idx == -1:
            return None
        if idx >= 12:
            namesz, descsz, ntype = struct.unpack_from("<III", data, idx - 12)
            if namesz == 4 and ntype == 3:
                return data[idx + 4 : idx + 4 + descsz].hex()
        idx += 1


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

    data = bytearray(target.read_bytes())

    # Check 1: GNU build ID matches the known-good Roborock 4.60.06 build.
    build_id = read_build_id(bytes(data))
    if build_id != KNOWN_BUILD_ID:
        print(f"ERROR: build ID mismatch.")
        print(f"  expected: {KNOWN_BUILD_ID}")
        print(f"  got:      {build_id}")
        print(f"This patcher is only known to work on Roborock app 4.60.06.")
        return 2

    # Check 2: each offset actually contains a BL instruction.
    for offset in OFFSETS:
        if offset + 4 > len(data):
            print(f"ERROR: offset 0x{offset:X} past end of file.")
            return 3
        instr = data[offset : offset + 4]
        if not (0x94 <= instr[3] <= 0x97):
            print(f"ERROR: bytes at 0x{offset:X} are not a BL instruction.")
            print(f"  got: {instr.hex()}")
            return 4

    # All checks passed. Patch.
    for offset in OFFSETS:
        data[offset : offset + 4] = NOP

    target.write_bytes(bytes(data))
    print("Patched successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())