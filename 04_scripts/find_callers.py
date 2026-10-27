import capstone

with open("dump1.bin","rb") as f:
    data = f.read()

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)

TARGETS = {0x97480, 0x972c4, 0x97158, 0x970dc, 0x96e5c}
for insn in md.disasm(data[0x90000:0x98000], 0x90000):
    if insn.mnemonic in ("bl","blx"):
        try:
            tgt = int(insn.op_str.lstrip("#"), 0)
        except Exception:
            continue
        if tgt in TARGETS:
            print(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
