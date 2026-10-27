fw = open("dump1.bin","rb").read()
IN_OFF, IN_LEN = 0x0004164c, 0x0025271e
payload = fw[IN_OFF:IN_OFF+IN_LEN]
open("tj_compressed_input.bin","wb").write(payload)
print(f"[+] Saved {len(payload)} bytes")
print(f"    head: {payload[:32].hex(' ')}")
print(f"    tail: {payload[-32:].hex(' ')}")
