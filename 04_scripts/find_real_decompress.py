import capstone, struct

fw = open("dump1.bin","rb").read()
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)

# 1) Find "bl 0x96a64" — the parent of the 0x96b48 block
print("=== Callers of 0x96a64 ===")
for i in md.disasm(fw[0x90000:0x98000], 0x90000):
    if i.mnemonic in ("bl", "blx"):
        try:
            tgt = int(i.op_str.lstrip("#"), 0)
        except Exception:
            continue
        if tgt == 0x96a64:
            print(f"0x{i.address:08x}: {i.mnemonic} {i.op_str}")

# 2) Find PC-relative loads of 0x98700000 and 0x98200000 (descriptor refs)
print("\n=== PC-relative loads of 0x98700000 / 0x98200000 ===")
targets = {0x98700000: "desc", 0x98200000: "src"}
for i in md.disasm(fw[0x90000:0x98000], 0x90000):
    if i.mnemonic == "ldr" and "[pc" in i.op_str:
        try:
            imm = int(i.op_str.split("#")[1].rstrip("]"), 0)
        except Exception:
            continue
        lit = i.address + 8 + imm
        if lit + 4 <= len(fw):
            val = struct.unpack("<I", fw[lit:lit+4])[0]
            if val in targets:
                print(f"0x{i.address:08x}: {i.op_str}  -> 0x{val:08x} ({targets[val]})")
