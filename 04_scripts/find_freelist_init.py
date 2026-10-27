import struct
fw = open("dump1.bin","rb").read()
# Search for PC-relative LDR of 0x293d6c, i.e. literal pool containing 0x293d6c
# We already know one at 0x970b8 (the driver). Now scan the whole binary for
# OTHER occurrences.
needle = struct.pack("<I", 0x293d6c)
p = 0; found = []
while True:
    p = fw.find(needle, p)
    if p == -1: break
    found.append(p); p += 4
print(f"0x293d6c appears at: {[hex(x) for x in found]}")

# Same for 0x293d70 (C), 0x293d84 (outlen)
for name, v in [("C=0x293d70", 0x293d70), ("outlen=0x293d84", 0x293d84)]:
    needle = struct.pack("<I", v)
    p = 0; f = []
    while True:
        p = fw.find(needle, p)
        if p == -1: break
        f.append(p); p += 4
    print(f"{name} appears at: {[hex(x) for x in f]}")
