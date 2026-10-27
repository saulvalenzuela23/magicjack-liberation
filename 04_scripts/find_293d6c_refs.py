import struct
fw = open("dump1.bin","rb").read()

# Search for the raw little-endian u32 values in literal pools
for name, val in [("B=0x293d6c", 0x293d6c),
                  ("C=0x293d70", 0x293d70),
                  ("out_len=0x293d84", 0x293d84),
                  ("in_ptr=0x4164c", 0x4164c)]:
    needle = struct.pack("<I", val)
    positions = []
    p = 0
    while True:
        p = fw.find(needle, p)
        if p == -1: break
        positions.append(p); p += 4
    print(f"{name}: {len(positions)} occurrences at {[hex(x) for x in positions[:10]]}")
