from unicorn import *
from unicorn.arm_const import *
import struct

fw = open("dump1.bin","rb").read()
BASE = 0x98000000
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(BASE, 0x800000)
mu.mem_write(BASE, fw)

# Also map a private scratch page at 0x40000000 (out of firmware)
mu.mem_map(0x40000000, 0x100000)
mu.reg_write(UC_ARM_REG_SP, 0x400FF000)
EXIT = 0xDEAD0000

# Descriptor scratch
DESC     = 0x40080000
OUT      = 0x40100000   # output buffer (256 KB)
OUTLEN   = 0x4007F000

def call(entry, in_ptr, in_len, out_ptr, outlen_ptr, count=20_000_000):
    mu.mem_write(out_ptr, b"\x00" * 0x1000)
    mu.mem_write(outlen_ptr, b"\x00" * 4)
    mu.reg_write(UC_ARM_REG_R0, in_ptr)
    mu.reg_write(UC_ARM_REG_R1, in_len)
    mu.reg_write(UC_ARM_REG_R2, out_ptr)
    mu.reg_write(UC_ARM_REG_R3, outlen_ptr)
    try:
        mu.emu_start(entry, EXIT, timeout=3000, count=count)
        status = "ok"
    except UcError as e:
        status = str(e)
    ol = struct.unpack("<I", mu.mem_read(outlen_ptr, 4))[0]
    hd = bytes(mu.mem_read(out_ptr, 16)).hex(" ")
    return status, ol, hd

print("[*] Calling 0x96a64 (outer function) with various inputs")
for IN_OFF in (0x281402, 0x28140a, 0x281412, 0x280000, 0x200000, 0x97560):
    st, ol, hd = call(BASE + 0x96a64, BASE + IN_OFF, 0x100000, OUT, OUTLEN)
    print(f"  in=0x{IN_OFF:06x}  {st:<30}  out_len=0x{ol:x}  head={hd}")

print("\n[*] Calling 0x96a64 with self-referential src=0x98200000 (what wrapper set up)")
# The wrapper 0x96e5c populated 0x98200000 with code. Try it as input.
st, ol, hd = call(BASE + 0x96a64, 0x98200000, 0x5ab9, OUT, OUTLEN)
print(f"  in=0x98200000  {st:<30}  out_len=0x{ol:x}  head={hd}")

# After a run, also dump descriptor that wrapper wrote at 0x98700000
print(f"\n[*] Descriptor @ 0x98700000: {bytes(mu.mem_read(0x98700000, 32)).hex(' ')}")
