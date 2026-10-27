from unicorn import *
from unicorn.arm_const import *
import struct

fw = open("dump1.bin","rb").read()
BASE = 0x98000000
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(BASE, 0x800000)          # covers code + state/descriptor at 0x982/0x987
mu.mem_write(BASE, fw)

# Map output heap area far away (doesn't collide with firmware)
mu.mem_map(0x40000000, 0x1000000)   # 16 MB heap
mu.reg_write(UC_ARM_REG_SP, 0x40FFF000)

# Also need to prime the allocator: at runtime, [B] (free-list head) must be
# initialized. Look at what the firmware does at 0x9700c..0x97014 before we
# crash — but let's just try and see what happens.

EXIT = 0xDEAD0000

# Decode the driver's literals first so we know what it'll use
def r32(off): return struct.unpack("<I", fw[off:off+4])[0]

print("=== Driver literals ===")
for n, off in [("A (alloc size)",   0x970b4),
               ("B (free-list ptr)",0x970b8),
               ("C (block ptr)",    0x970bc),
               ("in_ptr",           0x970c0),
               ("in_len",           0x970c4),
               ("out_len ptr",      0x970c8)]:
    print(f"  {n:20s} @ 0x{off:x}: 0x{r32(off):08x}")

# Try running the driver directly
print("\n=== Running 0x97000 (the real driver) ===")
try:
    mu.emu_start(BASE + 0x97000, EXIT, timeout=15000, count=100_000_000)
    print("[+] Returned normally")
except UcError as e:
    print(f"[-] {e} @ PC=0x{mu.reg_read(UC_ARM_REG_PC):x}")

# Read what happened
try:
    # The output size/ptr are at C and out_len; probe them
    C = r32(0x970bc)             # VA of "block ptr" storage
    A = r32(0x970b4)
    print(f"[*] A (out size) = 0x{A:x}")
    print(f"[*] C = 0x{C:x}, *C = 0x{struct.unpack('<I', mu.mem_read(C,4))[0]:x}")
except Exception as e:
    print(f"[-] post-read failed: {e}")

# Dump a slice around each known literal target to see if any got populated
for label, off in [("C", 0x970bc), ("B", 0x970b8)]:
    ptr = r32(off)
    if 0x40000000 <= ptr < 0x41000000:
        print(f"[*] {label}=0x{ptr:x} inside heap, contents: {bytes(mu.mem_read(ptr,32)).hex(' ')}")
