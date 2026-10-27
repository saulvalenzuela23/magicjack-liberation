from unicorn import *
from unicorn.arm_const import *
import struct

fw = open("dump1.bin","rb").read()
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(0x00000000, 0x40000000)
mu.mem_write(0x00000000, fw)
mu.mem_write(0x00290000, b"\x00" * 0x50000)

OUT     = 0x20000000
OUT_CAP = 0x2000000    # 32 MB
OUT_END = OUT + OUT_CAP
OUTLEN  = 0x3FFFF000
STACK   = 0x3FFFF000
mu.reg_write(UC_ARM_REG_SP, STACK)
mu.mem_write(STACK, struct.pack("<I", OUT_CAP))

# Track max output extent per run
STATE = {"max_out": 0, "stall": 0, "last_r6": 0}

def hook(uc, addr, size, ud):
    # Copy-loop write sites: 0x96d24 (byte copy), 0x96d90 (byte copy 2), 0x96d1c, 0x96ba8
    if addr in (0x96d24, 0x96d90, 0x96d1c, 0x96ba8, 0x96d20):
        r6 = uc.reg_read(UC_ARM_REG_R6)
        if r6 > OUT_END:
            uc.emu_stop(); return
        written = r6 - OUT
        if written > STATE["max_out"]:
            STATE["max_out"] = written
            STATE["stall"] = 0
        else:
            STATE["stall"] += 1
            # If 50 million iterations without growth, bail (clear infinite loop)
            if STATE["stall"] > 50_000_000:
                uc.emu_stop()
mu.hook_add(UC_HOOK_CODE, hook)

def decompress(in_off, label):
    in_len = len(fw) - in_off
    # Fully clear the output buffer (not just 0x100 bytes)
    mu.mem_write(OUT, b"\x00" * 0x100000)
    # Also clear the rest (large but OK, only runs 2x)
    mu.mem_write(OUT + 0x100000, b"\x00" * (OUT_CAP - 0x100000))
    mu.mem_write(OUTLEN, b"\x00" * 4)
    mu.reg_write(UC_ARM_REG_R0, in_off)
    mu.reg_write(UC_ARM_REG_R1, in_len)
    mu.reg_write(UC_ARM_REG_R2, OUT)
    mu.reg_write(UC_ARM_REG_R3, OUTLEN)
    STATE["max_out"] = 0
    STATE["stall"] = 0
    try:
        mu.emu_start(0x96b48, 0xDEAD0000, timeout=180000, count=50_000_000_000)
        status = "OK"
    except UcError as e:
        status = str(e)
    ol = struct.unpack("<I", mu.mem_read(OUTLEN, 4))[0]
    wrote = STATE["max_out"]
    head = bytes(mu.mem_read(OUT, 32)).hex(" ")
    print(f"=== {label} ===")
    print(f"  status={status}  out_len=0x{ol:x}  wrote={wrote}  stall={STATE['stall']}")
    print(f"  head: {head}")
    if wrote > 0:
        data = bytes(mu.mem_read(OUT, wrote))
        fn = f"decomp_clean_{label}.bin"
        open(fn,"wb").write(data)
        print(f"  [+] SAVED {fn} ({wrote} bytes)")
    print()

decompress(0x41b000, "boot")
decompress(0x200000, "app")
