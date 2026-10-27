import sys
from unicorn import *
from unicorn.arm_const import *
import capstone

# Configuration
BINARY_PATH = "dump1.bin"
RAM_BASE = 0x00000000
RAM_SIZE = 16 * 1024 * 1024  # 16 MB simulated address space
CODE_ENTRY = 0x097480        # Function entry point
EXIT_ADDR  = 0x88888888      # Dummy exit address to catch returns

def run_emulator():
    print("[*] Loading firmware image...")
    with open(BINARY_PATH, "rb") as f:
        firmware_data = f.read()

    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    print(f"[*] Mapping {RAM_SIZE / 1024 / 1024} MB RAM space at {hex(RAM_BASE)}...")
    mu.mem_map(RAM_BASE, RAM_SIZE)

    print("[*] Writing firmware into emulator memory...")
    mu.mem_write(RAM_BASE, firmware_data)

    STACK_TOP = RAM_BASE + RAM_SIZE - 0x1000
    mu.reg_write(UC_ARM_REG_SP, STACK_TOP)
    mu.reg_write(UC_ARM_REG_LR, EXIT_ADDR)  # Prevent returning to 0

    # Initialize Capstone disassembler for tracing
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)

    def hook_code(uc, address, size, user_data):
        if address == EXIT_ADDR:
            print("[+] Successfully reached function return / exit address!")
            uc.emu_stop()
            return
        try:
            code = uc.mem_read(address, size)
            for i in md.disasm(code, address):
                print(f"  0x{i.address:08x}: {i.mnemonic:<10} {i.op_str}")
        except Exception:
            pass

    mu.hook_add(UC_HOOK_CODE, hook_code)

    print(f"[*] Starting emulation at {hex(CODE_ENTRY)}...")
    try:
        mu.emu_start(CODE_ENTRY, EXIT_ADDR, timeout=5000, count=500)
        print("[+] Emulation finished.")
    except UcError as e:
        print(f"[-] Emulation error: {e}")
        pc = mu.reg_read(UC_ARM_REG_PC)
        print(f"    PC: {hex(pc)}")

if __name__ == "__main__":
    run_emulator()
