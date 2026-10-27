import capstone

blob = open("tj_stage2_blob.bin","rb").read()

for mode, name in [(capstone.CS_MODE_THUMB, "THUMB-2"),
                   (capstone.CS_MODE_ARM, "ARM")]:
    md = capstone.Cs(capstone.CS_ARCH_ARM, mode)
    print(f"\n=== {name} (first 25 insns) ===")
    n = 0
    for i in md.disasm(blob, 0):
        print(f"0x{i.address:04x}: {i.mnemonic:<10} {i.op_str}")
        n += 1
        if n >= 25: break
