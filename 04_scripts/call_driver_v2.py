from unicorn import *
from unicorn.arm_const import *
import struct

fw = open("dump1.bin","rb").read()
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(0x00000000, 0x01000000)   # 16 MB: covers code + .bss (0x293d6c) + input (0x4164c) + heap
mu.mem_write(0x00000000, fw)
mu.reg_write(UC_ARM_REG_SP, 0x00FF0000)

try:
    mu.emu_start(0x97000, 0xDEAD0000, timeout=15000, count=100_000_000)
    print("[+] driver returned")
except UcError as e:
    print(f"[-] {e} @ PC=0x{mu.reg_read(UC_ARM_REG_PC):x}")

# B/C/out are at VAs 0x293d6c/0x293d70/0x293d84
B = struct.unpack("<I", mu.mem_read(0x293d6c, 4))[0]
C = struct.unpack("<I", mu.mem_read(0x293d70, 4))[0]
O = struct.unpack("<I", mu.mem_read(0x293d84, 4))[0]
print(f"[*] B=[0x293d6c]=0x{B:x}")
print(f"[*] C=[0x293d70]=0x{C:x}")
print(f"[*] out_len=[0x293d84]=0x{O:x}")

if C and C < 0x1000000:
    print(f"[*] First 64 bytes at C: {bytes(mu.mem_read(C, 64)).hex(' ')}")
