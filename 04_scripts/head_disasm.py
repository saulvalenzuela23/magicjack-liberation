import capstone
with open("dump1.bin","rb") as f: data = f.read(64)
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
for i in md.disasm(data, 0x0):
    print(f"0x{i.address:08x}: {i.mnemonic:<8} {i.op_str}")
