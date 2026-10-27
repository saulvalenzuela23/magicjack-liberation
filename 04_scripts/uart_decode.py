import csv, re, sys

# Extract the hex bytes from the 'Data' column of RX data rows
out = bytearray()
with open("magicjackLogic10s.csv", newline="") as f:
    r = csv.DictReader(f)
    for row in r:
        if row.get("Type","").strip() == "RX data":
            d = row.get("Data","").strip()
            if re.fullmatch(r"[0-9A-Fa-f]{2}", d):
                out.append(int(d,16))

print(f"[*] Total bytes: {len(out)}")
print("[*] ASCII dump:")
print(out.decode("latin1"))
print("\n[*] Hex dump:")
for i in range(0, len(out), 16):
    chunk = out[i:i+16]
    print(f"{i:04x}  {chunk.hex(' '):<47}  |{''.join(chr(b) if 32<=b<127 else '.' for b in chunk)}|")
