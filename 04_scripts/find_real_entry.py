import capstone

with open("dump1.bin","rb") as f:
    data = f.read()

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
md.detail = True

TARGETS = {0x96a64, 0x96b48, 0x96e5c}
for insn in md.disasm(data[0x90000:0x98000], 0x90000):
    if insn.mnemonic in ("bl", "blx"):
        try:
            tgt = int(insn.op_str.lstrip("#"), 0)
        except Exception:
            continue
        if tgt in TARGETS:
            print(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")

# Also disassemble 0x96a00..0x96b48 to find 0x96a64's prologue
print("\n=== 0x96a00..0x96b50 disassembly ===")
for i in md.disasm(data[0x96a00:0x96b50], 0x96a00):
    print(f"0x{i.address:08x}: {i.mnemonic:<10} {i.op_str}")
