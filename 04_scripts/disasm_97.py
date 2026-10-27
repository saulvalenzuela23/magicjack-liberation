import capstone
fw = open("dump1.bin","rb").read()
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
for i in md.disasm(fw[0x97000:0x97560], 0x97000):
    print(f"0x{i.address:08x}: {i.mnemonic:<10} {i.op_str}")
