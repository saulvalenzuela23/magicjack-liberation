import capstone
fw = open("dump1.bin","rb").read()
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
for i in md.disasm(fw[0x96000:0x98000], 0x96000):
    if i.mnemonic in ("bl", "blx") and "0x97" in i.op_str:
        print(f"0x{i.address:08x}: {i.mnemonic} {i.op_str}")
