with open("dump1.bin", "rb") as f:
    f.seek(0x281402)  # Skip the "ME" header and land on 1f 8b 84 0a
    payload_data = f.read(429056)

# Carve out the raw stream for offline analysis
with open("carved_tigerjet_payload.bin", "wb") as out:
    out.write(payload_data)

print(f"Successfully carved {len(payload_data)} bytes to carved_tigerjet_payload.bin")

# Print first 32 bytes of the deflate stream for inspection
print("Stream head:", payload_data[:32].hex(" "))
