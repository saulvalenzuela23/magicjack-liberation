# magicJack PyUSB Control Driver

This folder contains the Python scripts used to bypass the official Windows `TjIpSys.dll` and communicate directly with the TigerJet TJ911 hardware.

## How it works
The magicJack uses a standard HID interface (Interface 4) for its control plane. 
We send commands using a HID `SET_REPORT` Control Transfer (`bmRequestType=0x21`, `bRequest=0x09`, `wValue=0x0200`).

### Packet Format
Commands are sent as a 10-byte header followed by the payload:
- **Byte 0-3:** `04 00 00 00` (Magic / Report ID)
- **Byte 4-5:** Command ID (Little Endian)
- **Byte 6-7:** Payload Length (Little Endian)
- **Byte 8-9:** `00 55` (Sync)

## Usage
You must run this as root (or with a udev rule) because it detaches the kernel HID driver.
`sudo python3 magicjack_control.py`
