import zlib, os

with open("carved_tigerjet_payload.bin","rb") as f:
    data = f.read()

os.makedirs("extracted_parts", exist_ok=True)

def try_inflate(buf, wbits):
    try:
        d = zlib.decompressobj(wbits)
        out = d.decompress(buf)
        out += d.flush()
        if len(out) > 0:
            return out
    except Exception:
        return None
    return None

# Try both zlib-wrapped (15) and raw deflate (-15) at every 0x78 header
count = 0
for sig, name in [(b"\x78\x01","zlib01"), (b"\x78\x9c","zlib9c"),
                  (b"\x78\xda","zlibda"), (b"\x1f\x8b","gzip")]:
    pos = 0
    while True:
        pos = data.find(sig, pos)
        if pos == -1:
            break
        # gzip: skip 10-byte header, raw deflate
        for wbits in (-15, 15, 31):
            start = pos + (10 if sig == b"\x1f\x8b" else 0)
            out = try_inflate(data[start:], wbits)
            if out and len(out) > 64:
                fn = f"extracted_parts/{name}_{pos:08x}_w{wbits}_{len(out)}.bin"
                with open(fn,"wb") as w:
                    w.write(out)
                print(f"[+] {name} @ 0x{pos:x} wbits={wbits} -> {len(out)} bytes  {fn}")
                count += 1
                break
        pos += len(sig)

print(f"[*] Done. {count} streams recovered.")
