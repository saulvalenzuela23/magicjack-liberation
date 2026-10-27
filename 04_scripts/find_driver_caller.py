import capstone
fw = open("dump1.bin","rb").read()
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
print("=== Callers of 0x97000 ===")
for i in md.disasm(fw[0x90000:0x98000], 0x90000):
    if i.mnemonic in ("bl","blx"):
        try: tgt = int(i.op_str.lstrip("#"),0)
        except: continue
        if tgt == 0x97000:
            print(f"0x{i.address:08x}: {i.mnemonic} {i.op_str}")

print("\n=== Callers of 0x972c4 (allocator) ===")
for i in md.disasm(fw[0x90000:0x98000], 0x90000):
    if i.mnemonic in ("bl","blx"):
        try: tgt = int(i.op_str.lstrip("#"),0)
        except: continue
        if tgt == 0x972c4:
            print(f"0x{i.address:08x}: {i.mnemonic} {i.op_str}")
