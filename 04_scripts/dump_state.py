from unicorn import *
from unicorn.arm_const import *
import struct

fw = open("dump1.bin","rb").read()
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(0x98000000, 0x800000)
mu.mem_write(0x98000000, fw)
mu.reg_write(UC_ARM_REG_SP, 0x987FF000)
try:
    mu.emu_start(0x98096e5c, 0xDEAD0000, timeout=10000, count=50_000_000)
    print("[+] wrapper returned")
except UcError as e:
    print(f"[-] {e}")

# Dump the populated region
blob = bytes(mu.mem_read(0x98200000, 0x5ab9))
open("tj_stage2_blob.bin","wb").write(blob)
print(f"[+] Saved {len(blob)} bytes to tj_stage2_blob.bin")
print(f"    head: {blob[:32].hex(' ')}")

desc = bytes(mu.mem_read(0x98700000, 0x20))
open("tj_descriptor.bin","wb").write(desc)
print(f"[+] Descriptor: {desc.hex(' ')}")
