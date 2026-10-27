fw = open("dump1.bin","rb").read()
is_ff = [fw[i] == 0xFF for i in range(len(fw))]
trans, prev, start = [], is_ff[0], 0
for i in range(1, len(fw)):
    if is_ff[i] != prev:
        trans.append((start, i, "FF" if prev else "DATA"))
        start, prev = i, is_ff[i]
trans.append((start, len(fw), "FF" if prev else "DATA"))
print(f"Total size: {len(fw)} bytes (0x{len(fw):x})")
for s, e, t in trans:
    if e - s > 0x100:
        print(f"  {t:4s}  0x{s:06x}..0x{e:06x}  ({e-s} bytes)")
