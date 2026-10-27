# magicJack Hardware Liberation (TigerJet TJ911)

Reverse engineering the magicJack USB dongle to bypass the proprietary Windows client and subscription service, turning it into a standard open-source Analog Telephone Adapter (ATA) for use with Asterisk.

## 🔬 Hardware & Architecture Specs

- **SoC:** TigerJet TJ911 (running eCos RTOS, not Linux)
- **USB Vendor ID:** `0x06E6`
- **USB Product IDs:** `0xC200`, `0xC211`, `0xC39C`, `0xC291`, `0xC290`
- **USB Interfaces:** Composite Device (0: Mass Storage / 1-3: USB Audio / 4: HID)
- **Control Protocol:** Proprietary 10-byte HID `SET_REPORT` packets.

## 📂 Repository Structure

- **`01_core_firmware/`**
  - `boot_firmware_raw.bin`: Bootloader and RTC init.
  - `app_firmware_raw.bin`: Main VoIP application (SIP stack, FXS control).
- **`04_scripts/`**: Python scripts used to analyze the firmware, carve the binaries, and map Ghidra decompilation.
- **`06_python_driver/`**: **The Holy Grail.** Our custom PyUSB driver that completely replaces `TjIpSys.dll`.

## 🛠️ The USB Control Protocol (Reverse Engineered)

By decompiling `TjIpSys.dll` in Ghidra, we mapped the exact wire protocol. The magicJack uses a standard HID interface (Interface 4) to send control commands via a Control Transfer (`bmRequestType=0x21`, `bRequest=0x09`, `wValue=0x0200`).

### Packet Format

Every command is a 10-byte header followed by a variable payload:

```text
[ 04 00 00 00 ]  [ CMD ]  [ LEN ]  [ 00 55 ]  [ PAYLOAD ]
 Magic/Report    16-bit    16-bit   Sync      Data
 ID (4)        Little    Little                  
               Endian    Endian
```

### Known Commands
- `0x00`: Initialize Dongle
- `0x63`: Initialize Dongle (Secondary)
- `0x10`, `0x11`: Audio/Line setup
- `0x03`: Hook State Toggle (Off-Hook / On-Hook)

## 🚀 How to use the Python Driver

The Python driver requires `pyusb`:

```bash
sudo apt install python3-usb
```

Because it detaches the standard Linux HID driver to send raw packets, run it with appropriate permissions:

```bash
cd 06_python_driver
sudo python3 magicjack_control.py
```

## 🗺️ Roadmap to Free Calling

The control plane (Hook, Ring, DTMF) is fully cracked. The next step is bridging the USB Audio Class (UAC) interface to a SIP client.

1. **Native Linux Requirement:** WSL/USBIP cannot handle Isochronous audio transfers. This must run on native Linux or a Raspberry Pi.
2. **Audio Bridge:** Map the dongle's ALSA audio endpoints (`arecord` / `aplay`) to an Asterisk PBX.
3. **Free Backend:** Connect Asterisk to a standard SIP trunk or VoIP provider.

---
*Disclaimer: This project is for educational and interoperability purposes only. Using this to bypass magicJack's subscription infrastructure is done at your own risk.*
