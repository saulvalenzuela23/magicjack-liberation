from unicorn import *
from unicorn.arm_const import *
import struct

fw = open("dump1.bin","rb").read()
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(0x00000000, 0x40000000)
mu.mem_write(0x00000000, fw)
mu.mem_write(0x00290000, b"\x00" * 0x50000)

OUT     = 0x20000000
OUT_CAP = 0x4000000    # 64 MB cap — plenty for the whole firmware
OUT_END = OUT + OUT_CAP
OUTLEN  = 0x3FFFF000
mu.mem_write(OUTLEN, b"\x00" * 4)

STACK = 0x3FFFF000
mu.reg_write(UC_ARM_REG_SP, STACK)

# Hook every strb in the copy loops + the entry point to detect buffer overrun
STOP_FLAG = [False]
def hook(uc, addr, size, ud):
    # Bound output when we're in the copy loops (0x96d24, 0x96d90, 0x96ba8, etc.)
    if addr in (0x96d24, 0x96d90, 0x96d20, 0x96ba8):
        r6 = uc.reg_read(UC_ARM_REG_R6)   # output ptr in copy loops
        if r6 >= OUT_END:
            STOP_FLAG[0] = True
            uc.emu_stop()
mu.hook_add(UC_HOOK_CODE, hook)

def decompress(in_off, label):
    in_len = len(fw) - in_off
    mu.mem_write(OUTLEN, b"\x00" * 4)
    mu.mem_write(OUT, b"\x00" * 0x100)
    mu.reg_write(UC_ARM_REG_R0, in_off)
    mu.reg_write(UC_ARM_REG_R1, in_len)
    mu.reg_write(UC_ARM_REG_R2, OUT)
    mu.reg_write(UC_ARM_REG_R3, OUTLEN)
    STOP_FLAG[0] = False
    try:
        mu.emu_start(0x96b48, 0xDEAD0000, timeout=120000, count=20_000_000_000)
        status = "OK"
    except UcError as e:
        status = str(e)
    pc = mu.reg_read(UC_ARM_REG_PC)
    r6 = mu.reg_read(UC_ARM_REG_R6)
    ol = struct.unpack("<I", mu.mem_read(OUTLEN, 4))[0]
    out_written = r6 - OUT if 0 <= r6 - OUT <= OUT_CAP else "?"

    print(f"=== {label}: in=0x{in_off:x} ===")
    print(f"  status={status}  PC=0x{pc:x}  out_len=0x{ol:x}  bytes_written={out_written}")

    # Save everything written up to r6
    if isinstance(out_written, int) and out_written > 0:
        data = bytes(mu.mem_read(OUT, out_written))
    else:
        data = bytes(mu.mem_read(OUT, OUT_CAP))
        data = data.rstrip(b"\x00")
    fname = f"decompressed_{label}.bin"
    open(fname, "wb").write(data)
    print(f"  [+] Saved {fname} ({len(data)} bytes)")
    print(f"  head: {data[:32].hex(' ')}")
    # Quick strings peek
    print(f"  strings: {data[:2000].find(b'eCos')} ... {data[:20000].find(b'Voip')}")
    print()

decompress(0x41b000, "boot_41b000")
decompress(0x200000, "main_200000")
decompress(0x044000, "alt_044000")
