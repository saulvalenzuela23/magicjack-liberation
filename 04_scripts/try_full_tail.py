from unicorn import *
from unicorn.arm_const import *
import struct

fw = open("dump1.bin","rb").read()
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(0x00000000, 0x10000000)
mu.mem_write(0x00000000, fw)
mu.mem_write(0x00290000, b"\x00" * 0x50000)

OUT = 0x80000000
mu.mem_map(OUT, 0x10000000)
OUTLEN = 0x8FFFF000
mu.mem_write(OUTLEN, b"\x00" * 4)
mu.reg_write(UC_ARM_REG_SP, 0x0FFFFFF0)

for in_off in (0x41b000, 0x200000, 0x44000):
    in_len = len(fw) - in_off
    mu.mem_write(OUTLEN, b"\x00" * 4)
    mu.mem_write(OUT, b"\x00" * 0x200)
    mu.reg_write(UC_ARM_REG_R0, in_off)
    mu.reg_write(UC_ARM_REG_R1, in_len)
    mu.reg_write(UC_ARM_REG_R2, OUT)
    mu.reg_write(UC_ARM_REG_R3, OUTLEN)
    try:
        mu.emu_start(0x96b48, 0xDEAD0000, timeout=20000, count=1_000_000_000)
        status = "OK"
    except UcError as e:
        status = str(e)
    pc = mu.reg_read(UC_ARM_REG_PC)
    ol = struct.unpack("<I", mu.mem_read(OUTLEN, 4))[0]
    head = bytes(mu.mem_read(OUT, 32)).hex(" ")
    print(f"in=0x{in_off:x} len=0x{in_len:x}  {status:<42} PC=0x{pc:x} out_len=0x{ol:x}")
    print(f"  head: {head}")
    if ol > 0:
        data = bytes(mu.mem_read(OUT, min(ol, 0x1000000)))
        open(f"decompressed_{in_off:x}.bin","wb").write(data)
        print(f"  [+] SAVED decompressed_{in_off:x}.bin ({len(data)} bytes)")
