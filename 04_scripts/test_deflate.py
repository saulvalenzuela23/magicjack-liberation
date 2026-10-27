import zlib

with open("carved_tigerjet_payload.bin", "rb") as f:
    # Skip the 10-byte GZIP header (1f 8b 84 0a + 6 bytes timestamp/flags)
    f.seek(10)
    raw_stream = f.read()

print("[*] Sweeping raw DEFLATE window sizes (wbits)...")
# Try negative wbits for raw deflate (no zlib header)
for wbits in range(-8, -16, -1):
    try:
        decompressed = zlib.decompress(raw_stream, wbits)
        out_name = f"unpacked_wbits_{abs(wbits)}.bin"
        with open(out_name, "wb") as out:
            out.write(decompressed)
        print(f"[+] SUCCESS with wbits={wbits}! Saved {len(decompressed)} bytes to {out_name}")
        break
    except Exception as e:
        print(f"[-] wbits={wbits}: {e}")
