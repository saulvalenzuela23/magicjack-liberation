import capstone, struct
fw = open("dump1.bin","rb").read()
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)

# Search for PC-relative loads of 0x293d6c, 0x293d70, 0x293d84 anywhere in fw
targets = {0x293d6c:"B(freelist)", 0x293d70:"C(block)", 0x293d84:"out_len", 0x4164c:"in_ptr"}
hits = []
# Scan whole binary as ARM; skip obvious data
for start in range(0, len(fw) - 4, 4):
    try:
        chunk = fw[start:start+4]
        if len(chunk) < 4: break
        for i in md.disasm(chunk, start):
            if i.mnemonic == "ldr" and "[pc" in i.op_str:
                try:
                    imm = int(i.op_str.split("#")[1].rstrip("]"), 0)
                except: continue
                lit = i.address + 8 + imm
                if lit + 4 <= len(fw):
                    v = struct.unpack("<I", fw[lit:lit+4])[0]
                    if v in targets:
                        hits.append((i.address, v, targets[v]))
            break
    except Exception:
        pass

for a, v, name in hits[:30]:
    print(f"0x{a:08x}  ->  0x{v:08x}  ({name})")
print(f"total: {len(hits)}")
