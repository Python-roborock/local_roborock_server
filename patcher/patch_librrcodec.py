import struct

NOP = struct.pack("<I", 0xD503201F)

with open("librrcodec.so", "r+b") as f:
    data = bytearray(f.read())
    data[0x4ADCC:0x4ADCC+4] = NOP  # Patch BL at VA 0x4bdcc
    data[0x4B428:0x4B428+4] = NOP  # Patch BL at VA 0x4c428
    f.seek(0)
    f.write(data)

print("Patched successfully")