from unicorn import *
from unicorn.arm_const import *
import struct

fw = open("dump1.bin","rb").read()
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(0x00000000, 0x01000000)
mu.mem_write(0x00000000, fw)

# Zero .bss region (typical: 0x293000..0x300000 — around our vars)
# But safer: zero everything from the end of .text (say 0x200000) up to 0x400000
# EXCEPT we need input at 0x4164c preserved (it's all 0xFF anyway)
mu.mem_write(0x00293000, b"\x00" * (0x40000))   # 0x293000..0x2A3000
mu.reg_write(UC_ARM_REG_SP, 0x00FF0000)

try:
    mu.emu_start(0x97000, 0xDEAD0000, timeout=15000, count=100_000_000)
    print("[+] driver returned")
except UcError as e:
    print(f"[-] {e} @ PC=0x{mu.reg_read(UC_ARM_REG_PC):x}")

B = struct.unpack("<I", mu.mem_read(0x293d6c,4))[0]
C = struct.unpack("<I", mu.mem_read(0x293d70,4))[0]
O = struct.unpack("<I", mu.mem_read(0x293d84,4))[0]
print(f"[*] B=0x{B:x}  C=0x{C:x}  out_len=0x{O:x}")
