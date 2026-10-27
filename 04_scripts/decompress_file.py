from unicorn import *
from unicorn.arm_const import *
import struct, sys, os

BIN = sys.argv[1]
fw = open("dump1.bin","rb").read()
payload = open(BIN, "rb").read()
print(f"[*] Input: {BIN} ({len(payload)} bytes)")

mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(0x00000000, 0x01000000)
mu.mem_write(0x00000000, fw)
# Overlay the payload at a scratch VA (use 0x0E000000, outside fw)
mu.mem_map(0x0E000000, 0x01000000)
mu.mem_write(0x0E000000, payload)
mu.mem_write(0x00290000, b"\x00" * 0x50000)

OUT = 0x08000000
mu.mem_map(OUT, 0x01000000)
OUTLEN = 0x08FFF000
mu.mem_write(OUTLEN, b"\x00" * 4)

mu.reg_write(UC_ARM_REG_SP, 0x00FF0000)
mu.reg_write(UC_ARM_REG_R0, 0x0E000000)
mu.reg_write(UC_ARM_REG_R1, len(payload))
mu.reg_write(UC_ARM_REG_R2, OUT)
mu.reg_write(UC_ARM_REG_R3, OUTLEN)

try:
    mu.emu_start(0x96b48, 0xDEAD0000, timeout=10000, count=500_000_000)
    print("[+] OK")
except UcError as e:
    print(f"[-] {e}")

ol = struct.unpack("<I", mu.mem_read(OUTLEN, 4))[0]
print(f"[*] out_len = 0x{ol:x} ({ol} bytes)")
if 0 < ol <= 0x1000000:
    data = bytes(mu.mem_read(OUT, ol))
    outname = os.path.basename(BIN) + ".decompressed"
    open(outname, "wb").write(data)
    print(f"[+] Saved {outname}")
    print(f"    head: {data[:64].hex(' ')}")
