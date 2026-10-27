from unicorn import *
from unicorn.arm_const import *
import capstone

BINARY = "dump1.bin"
RAM_BASE, RAM_SIZE = 0x00000000, 0x1000000   # 16 MB
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)

with open(BINARY,"rb") as f: fw = f.read()

mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(RAM_BASE, RAM_SIZE)
mu.mem_write(RAM_BASE, fw)

STACK = 0x00F00000
mu.reg_write(UC_ARM_REG_SP, STACK)

# Trace a small number of insns from 0
count = 0
def hook(uc, addr, size, ud):
    global count
    if count < 40:
        try:
            for i in md.disasm(uc.mem_read(addr, size), addr):
                print(f"0x{addr:08x}: {i.mnemonic:<8} {i.op_str}")
        except Exception:
            pass
    count += 1

mu.hook_add(UC_HOOK_CODE, hook)

try:
    mu.emu_start(0x0, 0x100000, timeout=2000, count=200)
    print("[+] Finished trace.")
except UcError as e:
    print(f"[-] {e}  PC=0x{mu.reg_read(UC_ARM_REG_PC):08x}")
