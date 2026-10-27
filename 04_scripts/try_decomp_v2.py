from unicorn import *
from unicorn.arm_const import *
import struct, sys

fw = open("dump1.bin","rb").read()
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(0x00000000, 0x40000000)
mu.mem_write(0x00000000, fw)
mu.mem_write(0x00290000, b"\x00" * 0x50000)

OUT    = 0x20000000
OUT_CAP = 0x400000      # 4 MB output cap (plausible for a firmware blob)
OUTLEN = 0x3FFFF000
mu.mem_write(OUTLEN, b"\x00" * 4)

STACK = 0x3FFFF000
mu.reg_write(UC_ARM_REG_SP, STACK)
# The real driver does 'str r7, [sp]' before calling. Set [sp] = OUT_CAP.
mu.mem_write(STACK, struct.pack("<I", OUT_CAP))

in_off = 0x41b000
in_len = len(fw) - in_off

mu.mem_write(OUTLEN, b"\x00" * 4)
mu.mem_write(OUT, b"\x00" * 0x200)
mu.reg_write(UC_ARM_REG_R0, in_off)
mu.reg_write(UC_ARM_REG_R1, in_len)
mu.reg_write(UC_ARM_REG_R2, OUT)
mu.reg_write(UC_ARM_REG_R3, OUTLEN)

# Hook to detect when PC leaves the decompressor region (function return)
EXIT_HIT = [False]
def hook(uc, addr, size, ud):
    if addr == 0xDEAD0000 or addr > 0x40000000:
        EXIT_HIT[0] = True
        uc.emu_stop()
mu.hook_add(UC_HOOK_CODE, hook)

try:
    mu.emu_start(0x96b48, 0xDEAD0000, timeout=60000, count=10_000_000_000)
    status = "OK"
except UcError as e:
    status = str(e)

pc = mu.reg_read(UC_ARM_REG_PC)
ol = struct.unpack("<I", mu.mem_read(OUTLEN, 4))[0]
head = bytes(mu.mem_read(OUT, 64)).hex(" ")
print(f"status={status}  PC=0x{pc:x}  out_len=0x{ol:x}")
print(f"head: {head}")

# Find how much output was actually written (scan for last non-zero, or use full cap)
data = bytes(mu.mem_read(OUT, OUT_CAP))
# Trim trailing zeros
trimmed = data.rstrip(b"\x00")
print(f"non-zero output: {len(trimmed)} bytes (trimmed from {OUT_CAP})")
open("decompressed_41b000_full.bin","wb").write(data)
open("decompressed_41b000_trimmed.bin","wb").write(trimmed)
print("[+] Saved decompressed_41b000_full.bin and _trimmed.bin")

# Also write first 1 MB for inspection
open("decompressed_41b000_head1mb.bin","wb").write(data[:0x100000])
