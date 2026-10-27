import usb.core
import usb.util
import time

VID = 0x06E6
PID = 0xC200
HID_INTF = 4

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

# The sequence extracted from TjIpSys.dll
sequence = [
    (0x00, b"", "INIT (Command 0)"),
    (0x63, b"", "INIT (Command 99 / 0x63)"),
    (0x10, b"\x20", "Command 16 (0x10)"),
    (0x11, b"\x2d", "Command 17 (0x11)"),
    (3, b"\x01", "Command 3 - Toggle Relay (Off-Hook)"),
    (3, b"\x00", "Command 3 - Toggle Relay (On-Hook)"),
]

for cmd, data, desc in sequence:
    payload = build_packet(cmd, data)
    print(f"[*] Sending: {desc} -> {payload.hex(' ')}")
    
    try:
        # Send via HID Control Transfer (Method A)
        dev.ctrl_transfer(0x21, 0x09, 0x0200, HID_INTF, payload, timeout=1000)
        print("    [+] Success.")
    except usb.core.USBError as e:
        print(f"    [-] Failed: {e}")
    
    time.sleep(0.5) # Wait a moment between commands

usb.util.release_interface(dev, HID_INTF)
print("\n[*] Test complete.")
