from unicorn import *
from unicorn.arm_const import *
import struct

with open("dump1.bin","rb") as f:
    fw = f.read()

BASE = 0x98000000
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
# Map a generous range covering 0x98000000..0x98800000 for code/state/output
mu.mem_map(BASE, 0x800000)
mu.mem_write(BASE, fw)

# Extra RAM for output (0x98700000 already inside the mapped region)
STACK = 0x987FF000
mu.reg_write(UC_ARM_REG_SP, STACK)

EXIT = 0xDEAD0000

# ------------------------------------------------------------------
# Attempt 1: call the wrapper 0x96e5c with no args (self-contained)
# ------------------------------------------------------------------
print("[*] Attempt 1: call wrapper 0x96e5c (self-contained)")
try:
    mu.emu_start(BASE + 0x96e5c, EXIT, timeout=10000, count=50_000_000)
    print("[+] Returned normally")
except UcError as e:
    print(f"[-] UcError: {e}")
    print(f"    PC=0x{mu.reg_read(UC_ARM_REG_PC):x}")

# Inspect state at 0x98200000 (offsets)
st = bytes(mu.mem_read(0x98200000, 0x40))
print(f"[*] State[0x98200000][0:0x40]: {st.hex(' ')}")
print(f"    as u32s: {[hex(x) for x in struct.unpack('<16I', st)]}")

# Inspect output at 0x98700000
out = bytes(mu.mem_read(0x98700000, 0x40))
print(f"[*] Output[0x98700000][0:0x40]: {out.hex(' ')}")

# ------------------------------------------------------------------
# Attempt 2: call 0x96b48 directly with a *fresh* input pointer,
# matching what 0x96b48 expects (r0=src, r1=len, r2=dst, r3=&out_len)
# Try several candidate input offsets.
# ------------------------------------------------------------------
print("\n[*] Attempt 2: call 0x96b48 directly with varied inputs")
for IN_OFF in (0x281402, 0x28140a, 0x281412, 0x200000, 0x97560, 0x5ffe3b):
    # reset registers and mapped memory (only code + input area)
    mu.mem_write(0x98700000, b"\x00" * 0x1000)   # clear 4KB output
    mu.reg_write(UC_ARM_REG_R0, BASE + IN_OFF)
    mu.reg_write(UC_ARM_REG_R1, 0x100000)
    mu.reg_write(UC_ARM_REG_R2, 0x98700000)
    mu.reg_write(UC_ARM_REG_R3, 0x987FF800)       # scratch for out_len
    mu.mem_write(0x987FF800, b"\x00" * 4)

    try:
        mu.emu_start(BASE + 0x96b48, EXIT, timeout=2000, count=10_000_000)
    except UcError as e:
        pass

    out_len = struct.unpack("<I", mu.mem_read(0x987FF800, 4))[0]
    first16 = bytes(mu.mem_read(0x98700000, 16)).hex(" ")
    print(f"  in=0x{IN_OFF:06x} -> out_len=0x{out_len:x}  head: {first16}")
