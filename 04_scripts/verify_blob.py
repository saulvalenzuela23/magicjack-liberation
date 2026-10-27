fw = open("dump1.bin","rb").read()
blob = open("tj_stage2_blob.bin","rb").read()

for off in (0x1ff000, 0x200000, 0x1fff00):
    print(f"dump1.bin[0x{off:x}:0x{off:x}+16] = {fw[off:off+16].hex(' ')}")

print(f"\ntj_stage2_blob[0:16]  = {blob[0:16].hex(' ')}")
match = fw.find(blob[:16])
print(f"blob[0:16] first appears in dump1.bin at offset 0x{match:x}")
