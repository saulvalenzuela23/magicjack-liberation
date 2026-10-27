from unicorn import *
from unicorn.arm_const import *
import struct

fw = open("dump1.bin","rb").read()
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(0x00000000, 0x01000000)
mu.mem_write(0x00000000, fw)
mu.mem_write(0x00290000, b"\x00" * 0x50000)

# Map output region at 0x08000000 with 16 MB
OUT      = 0x08000000
OUT_SIZE = 0x01000000
OUTLEN   = 0x08FFF000          # INSIDE the mapped region
mu.mem_map(OUT, OUT_SIZE)

STACK = 0x00FF0000
mu.reg_write(UC_ARM_REG_SP, STACK)

candidates = [
    (0x41b000, 0x25271e),
    (0x41b000, 0x250000),
    (0x4164c,  0x25271e),
    (0x4164c,  0x250000),
    (0x044000, 0x25271e),
    (0x200000, 0x25271e),
    (0x41b000, 0x200000),
    (0x41b000, 0x260000),
]

for in_off, in_len in candidates:
    if in_off + in_len > len(fw):
        print(f"  skip in=0x{in_off:x} (past EOF)")
        continue
    mu.mem_write(OUTLEN, b"\x00" * 4)
    mu.mem_write(OUT, b"\x00" * 0x100)
    mu.reg_write(UC_ARM_REG_R0, in_off)
    mu.reg_write(UC_ARM_REG_R1, in_len)
    mu.reg_write(UC_ARM_REG_R2, OUT)
    mu.reg_write(UC_ARM_REG_R3, OUTLEN)
    try:
        mu.emu_start(0x96b48, 0xDEAD0000, timeout=8000, count=200_000_000)
        status = "OK"
    except UcError as e:
        status = f"{e}"
    ol = struct.unpack("<I", mu.mem_read(OUTLEN, 4))[0]
    head = bytes(mu.mem_read(OUT, 64)).hex(" ")
    print(f"in=0x{in_off:x} len=0x{in_len:x}  {status:<45}  out_len=0x{ol:x}")
    print(f"  head: {head}")
