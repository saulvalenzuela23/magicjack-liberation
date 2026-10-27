import capstone

with open("dump1.bin","rb") as f:
    data = f.read()

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)

# 1) Disassemble first 64 bytes (vector table?)
print("=== First 64 bytes as ARM @ 0x0 ===")
for i in md.disasm(data[:64], 0):
    print(f"0x{i.address:08x}: {i.mnemonic:<8} {i.op_str}")

# 2) Look for likely reset vector: LDR pc,[pc,#imm] at 0x0/0x4/0x8/0xc
print("\n=== Reset vector candidates ===")
for addr in (0x0,0x4,0x8,0xc,0x14,0x18,0x1c):
    chunk = data[addr:addr+4]
    for i in md.disasm(chunk, addr):
        print(f"0x{addr:04x}: {i.mnemonic:<8} {i.op_str}")

# 3) Scan for a Linux/uImage/TJ header signature
import re
for sig, name in [(b"\x27\x05\x19\x56","uImage"),
                  (b"\x1f\x8b\x08\x00","real gzip"),
                  (b"\x7fELF","ELF"),
                  (b"MZ","PE/MZ")]:
    p = data.find(sig)
    if p != -1:
        print(f"{name} @ 0x{p:x}")

# 4) Search for the u32 value 0x5ffe3b used as data (already know it's at 0x5ffe3b)
#    Now search for a *2nd copy* of that value anywhere (could be GOT slot)
needle = (0x5ffe3b).to_bytes(4,"little")
positions = []
p = 0
while True:
    p = data.find(needle, p)
    if p == -1: break
    positions.append(p); p += 4
print(f"\n0x5ffe3b used as data at: {[hex(x) for x in positions]}")
