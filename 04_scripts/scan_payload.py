with open("carved_tigerjet_payload.bin", "rb") as f:
    data = f.read()

signatures = {
    "ELF": b"\x7fELF",
    "GZIP": b"\x1f\x8b",
    "ZLIB": b"\x78\x01",
    "ZLIB_MED": b"\x78\x9c",
    "ZLIB_BEST": b"\x78\xda",
    "SQUASHFS": b"hsqs",
    "CRAMFS": b"cramfs",
    "LZMA": b"\x5d\x00\x00"
}

print("[*] Scanning carved payload for known signatures...")
for name, sig in signatures.items():
    pos = 0
    while True:
        pos = data.find(sig, pos)
        if pos == -1:
            break
        print(f"  [+] Found {name} at offset {hex(pos)} ({pos})")
        pos += len(sig)
