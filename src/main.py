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

def send_test_ring_command(dev):
    print("[*] Sending Command 3 (Off-Hook) to grab the line...")
    payload = build_packet(0x03, b"\x01")
    try:
        dev.ctrl_transfer(0x21, 0x09, 0x0200, HID_INTF, payload, timeout=1000)
        print("    [+] Line grabbed.")
    except usb.core.USBError as e:
        print(f"    [-] Failed: {e}")

def listen_for_events(dev):
    print("[*] Sending Initialization sequence to wake up device...")
    try:
        dev.ctrl_transfer(0x21, 0x09, 0x0200, HID_INTF, build_packet(0x00), timeout=1000)
        time.sleep(0.1)
        dev.ctrl_transfer(0x21, 0x09, 0x0200, HID_INTF, build_packet(0x63), timeout=1000)
        time.sleep(0.1)
    except usb.core.USBError as e:
        print(f"[-] Init failed: {e}")

    print("[*] Listening for events. Pick up the receiver and press buttons! (Ctrl+C to stop)")
    while True:
        try:
            data = dev.read(0x85, 64, timeout=500) 
            print(f"[+] Received event: {data.hex(' ')}")
        except usb.core.USBError as e:
            # Only ignore timeouts. Print actual errors!
            if e.errno == 110 or "timeout" in str(e).lower():
                pass
            else:
                print(f"[-] Read error: {e}")
                time.sleep(1) # Prevent terminal spam if it loops an error

# --- USB Claiming Logic ---
print("[*] Finding MagicJack device...")
dev = usb.core.find(idVendor=VID, idProduct=PID)

if not dev:
    print("[-] Device not found.")
    exit()

if dev.is_kernel_driver_active(HID_INTF):
    dev.detach_kernel_driver(HID_INTF)

usb.util.claim_interface(dev, HID_INTF)

# 1. Ring the phone
send_test_ring_command(dev)

# 2. Listen for events
listen_for_events(dev)

# Clean up
usb.util.release_interface(dev, HID_INTF)