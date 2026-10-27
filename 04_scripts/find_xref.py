import capstone

with open("dump1.bin","rb") as f:
    data = f.read()

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
md.detail = True

TARGET = 0x5ffe3b
hits = []
# ARM code lives roughly in 0x96000..0x97fff and possibly elsewhere.
# Scan whole image but skip obvious data (start at 0x96000 for speed).
for start in (0x96000, 0x0):
    end = min(len(data), start + 0x40000)
    for insn in md.disasm(data[start:end], start):
        # LDR Rd, [PC, #imm]  -> op_str like "r3, [pc, #0xb0]"
        if insn.mnemonic == "ldr" and "[pc" in insn.op_str:
            # compute literal address: PC = insn.address + 8 on ARM
            try:
                imm = int(insn.op_str.split("#")[1].rstrip("]"), 0)
            except Exception:
                continue
            lit_addr = insn.address + 8 + imm
            if abs(lit_addr - TARGET) < 0x20:
                hits.append((insn.address, insn.mnemonic, insn.op_str, lit_addr))

for h in hits:
    print(f"0x{h[0]:08x}: {h[1]:<6} {h[2]:<20}  -> loads from 0x{h[3]:08x}")
if not hits:
    print("No PC-relative load near 0x5ffe3b found in scanned range.")
