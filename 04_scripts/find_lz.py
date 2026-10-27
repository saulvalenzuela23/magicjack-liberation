import capstone

with open("dump1.bin","rb") as f:
    data = f.read()

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)

# Look for loop bodies containing at least 2 of: ldrb, strb, lsl, orr, add (heavy LZ signature)
win = data[0x96000:0x98000]
prev = []
for i in md.disasm(win, 0x96000):
    prev.append(i)
    if len(prev) > 30: prev.pop(0)
    mnems = [x.mnemonic for x in prev]
    score = sum(1 for m in mnems if m in ("ldrb","strb"))
    if score >= 4 and "b" in mnems:   # loop with byte-wise copy
        print(f"--- candidate @ 0x{i.address:08x} (prev 30 insns)")
        for x in prev:
            print(f"  0x{x.address:08x}: {x.mnemonic:<8} {x.op_str}")
        print()
        # only one hit per address
