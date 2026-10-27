import usb.core
import usb.util
import time

VID = 0x06E6
PID = 0xC200
HID_INTF = 4
EP_HID_IN = 0x85

def build_packet(cmd, data=b""):
    length = len(data)
    return bytes([
        0x04, 0x00, 0x00, 0x00, 
        cmd & 0xFF, (cmd >> 8) & 0xFF, 
        length & 0xFF, (length >> 8) & 0xFF, 
        0x00, 0x55
    ]) + data

dev = usb.core.find(idVendor=VID, idProduct=PID)
if not dev:
    print("[-] Not found")
    exit()

if dev.is_kernel_driver_active(HID_INTF): dev.detach_kernel_driver(HID_INTF)
usb.util.claim_interface(dev, HID_INTF)

# Exact 11-byte packet for Command 16 (0x10), Data 0x20
payload = build_packet(0x10, b"\x20")
print(f"[*] Testing 11-byte packet: {payload.hex(' ')}")

# Method A: SET_REPORT (wValue=0x0200)
try:
    dev.ctrl_transfer(0x21, 0x09, 0x0200, HID_INTF, payload, timeout=1000)
    print("[+] Method A (SET_REPORT, wValue=0x0200) SUCCESS!")
except usb.core.USBError as e:
    print(f"[-] Method A failed: {e}")

# Method B: SET_REPORT (wValue=0x0000 - No Report ID)
try:
    dev.ctrl_transfer(0x21, 0x09, 0x0000, HID_INTF, payload, timeout=1000)
    print("[+] Method B (SET_REPORT, wValue=0x0000) SUCCESS!")
except usb.core.USBError as e:
    print(f"[-] Method B failed: {e}")

# Method C: SET_FEATURE (wValue=0x0300) - Common for some vendors
try:
    dev.ctrl_transfer(0x21, 0x03, 0x0300, HID_INTF, payload, timeout=1000)
    print("[+] Method C (SET_FEATURE) SUCCESS!")
except usb.core.USBError as e:
    print(f"[-] Method C failed: {e}")

# Check for response
try:
    resp = dev.read(EP_HID_IN, 64, timeout=500)
    print(f"[+] RESPONSE RECEIVED: {bytes(resp).hex(' ')}")
except usb.core.USBTimeoutError:
    print("[-] No response from 0x85.")

usb.util.release_interface(dev, HID_INTF)
