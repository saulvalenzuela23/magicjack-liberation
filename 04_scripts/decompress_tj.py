from unicorn import *
from unicorn.arm_const import *
import struct

with open("dump1.bin","rb") as f:
    fw = f.read()

# ---- Load the raw firmware at VA 0 so all offsets are identity-mapped ----
RAM_BASE, RAM_SIZE = 0x00000000, 0x1000000     # 16 MB
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(RAM_BASE, RAM_SIZE)
mu.mem_write(RAM_BASE, fw)

STACK = 0x00F00000
mu.reg_write(UC_ARM_REG_SP, STACK)

# ---- Arguments for 0x96b48(input, input_len, output, *output_len) ----
IN_OFFSET    = 0x281402          # where the "1f8b840a..." starts in dump1.bin
IN_LEN       = 0x100000          # give it plenty of room (whole tail of file)
OUT_OFFSET   = 0x800000          # put output into upper RAM, won't collide with fw
OUT_SIZE     = 0x400000
OUTLEN_ADDR  = 0x7FF000          # scratch u32 for return length

# Make sure IN_LEN doesn't overflow past end of file
if IN_OFFSET + IN_LEN > len(fw):
    IN_LEN = len(fw) - IN_OFFSET

mu.reg_write(UC_ARM_REG_R0, IN_OFFSET)   # input ptr (file offset)
mu.reg_write(UC_ARM_REG_R1, IN_LEN)      # input length
mu.reg_write(UC_ARM_REG_R2, OUT_OFFSET)  # output ptr
mu.reg_write(UC_ARM_REG_R3, OUTLEN_ADDR) # where to store output length

EXIT = 0xDEAD0000
def stop_on_bx_lr(uc, addr, size, ud):
    # stop when we return from the routine (branch outside its range)
    if addr < 0x96b48 or addr > 0x96eb0:
        uc.emu_stop()

mu.hook_add(UC_HOOK_CODE, stop_on_bx_lr)

print(f"[*] Calling decompressor 0x96b48(in=0x{IN_OFFSET:x}, len=0x{IN_LEN:x}, out=0x{OUT_OFFSET:x})")
try:
    mu.emu_start(0x96b48, EXIT, timeout=30000, count=200_000_000)
except UcError as e:
    print(f"[-] UcError: {e}")
    print(f"    PC=0x{mu.reg_read(UC_ARM_REG_PC):x} R0=0x{mu.reg_read(UC_ARM_REG_R0):x}")

# Read returned length and output
out_len = struct.unpack("<I", mu.mem_read(OUTLEN_ADDR, 4))[0]
print(f"[+] Decompressor returned out_len = 0x{out_len:x} ({out_len} bytes)")

# Guard against absurd sizes
if 0 < out_len <= OUT_SIZE:
    data = bytes(mu.mem_read(OUT_OFFSET, out_len))
    with open("tj_decompressed.bin","wb") as w:
        w.write(data)
    print(f"[+] Saved {len(data)} bytes to tj_decompressed.bin")
    # Peek at the header
    print(f"    First 32 bytes: {data[:32].hex(' ')}")
else:
    print("[-] Output length looks wrong. Dumping 4KB anyway to inspect.")
    data = bytes(mu.mem_read(OUT_OFFSET, 4096))
    with open("tj_decompressed_raw.bin","wb") as w:
        w.write(data)
    print(f"    First 32 bytes: {data[:32].hex(' ')}")

# Also dump the saved state struct that 0x96e5c writes (0x7FF000 area)
print(f"[*] State-ish bytes @ 0x{OUTLEN_ADDR:x}: {bytes(mu.mem_read(OUTLEN_ADDR, 16)).hex(' ')}")
