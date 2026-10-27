from unicorn import *
from unicorn.arm_const import *
import struct

fw = open("dump1.bin","rb").read()
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(0x00000000, 0x40000000)
mu.mem_write(0x00000000, fw)
mu.mem_write(0x00290000, b"\x00" * 0x50000)

OUT     = 0x20000000
OUT_CAP = 0x1000000
OUTLEN  = 0x3FFFF000
STACK   = 0x3FFFF000
mu.reg_write(UC_ARM_REG_SP, STACK)
mu.mem_write(STACK, struct.pack("<I", OUT_CAP))

# Try MANY input lengths — some will hit the natural end correctly
for in_off in (0x41b000, 0x200000):
    for in_len in (0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x180000, 0x200000, 0x25271e):
        if in_off + in_len > len(fw):
            continue
        mu.mem_write(OUTLEN, b"\x00" * 4)
        mu.mem_write(OUT, b"\x00" * 0x100)
        mu.reg_write(UC_ARM_REG_R0, in_off)
        mu.reg_write(UC_ARM_REG_R1, in_len)
        mu.reg_write(UC_ARM_REG_R2, OUT)
        mu.reg_write(UC_ARM_REG_R3, OUTLEN)
        try:
            mu.emu_start(0x96b48, 0xDEAD0000, timeout=5000, count=500_000_000)
            status = "OK"
        except UcError as e:
            status = str(e)
        ol = struct.unpack("<I", mu.mem_read(OUTLEN, 4))[0]
        data = bytes(mu.mem_read(OUT, OUT_CAP)).rstrip(b"\x00")
        has_ecos   = b"eCos"    in data[:0x10000]
        has_voip   = b"Voip"    in data[:0x10000]
        has_mzdec  = b"MZ decomp" in data[:0x10000]
        print(f"in=0x{in_off:x} len=0x{in_len:x}  {status:<25} out_len=0x{ol:x}  trimmed={len(data):>7d}  eCos={has_ecos} Voip={has_voip} MZdec={has_mzdec}")
        # Save when out_len is set (natural termination)
        if ol > 0 and ol < OUT_CAP:
            open(f"decomp_ok_{in_off:x}_{in_len:x}.bin","wb").write(bytes(mu.mem_read(OUT, ol)))
            print(f"  [+] SAVED {ol} bytes -> decomp_ok_{in_off:x}_{in_len:x}.bin")
