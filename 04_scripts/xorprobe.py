with open("dump1.bin","rb") as f:
    f.seek(0x281402)
    head = f.read(64)

print("raw head:", head[:8].hex())
for key in [0xFF,0xAA,0x55,0x5A,0xA5,0x84,0x0A,0x08,0x00]:
    x = bytes(b ^ key for b in head[:8])
    print(f"key={key:#04x}  -> {x.hex()}  {x[:4]}")

# Also try single-byte-XORing the whole head against gzip target
target = bytes([0x1f,0x8b,0x08,0x00])
print("\nPer-byte XOR key needed to turn raw into gzip magic:")
print([hex(head[i]^target[i]) for i in range(4)])
