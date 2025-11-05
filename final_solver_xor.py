#!/usr/bin/env python3
"""
Final Solver - Try XOR and combination methods
Based on "HALF AND BETTER HALF" hint from Phase 3.2
"""

import bitcoin
import hashlib

target_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"

# Load the decrypted Cosmic Duality data
with open('cosmic_final_decrypted.bin', 'rb') as f:
    data = f.read()

print(f"🎯 Target: {target_address}")
print(f"📊 Data length: {len(data)} bytes\n")

def test_key(key_hex):
    try:
        if len(key_hex) != 64:
            return False
        key_int = int(key_hex, 16)
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        if not (1 <= key_int < secp256k1_order):
            return False
        
        addr_c = bitcoin.privkey_to_address(key_hex)
        if addr_c == target_address:
            return ('compressed', addr_c)
        
        pubkey = bitcoin.privtopub(key_hex)
        addr_u = bitcoin.pubtoaddr(pubkey, 0)
        if addr_u == target_address:
            return ('uncompressed', addr_u)
        
        return False
    except:
        return False

# Strategy 1: XOR two halves of the data
print("🔍 Strategy 1: XOR first half with second half...")
half_len = len(data) // 2
first_half = data[:half_len]
second_half = data[half_len:half_len*2]

xor_result = bytes(a ^ b for a, b in zip(first_half, second_half))
print(f"  XOR result length: {len(xor_result)} bytes")

# Test first 32 bytes of XOR result
for offset in range(0, min(len(xor_result) - 31, 100)):
    candidate = xor_result[offset:offset+32].hex()
    result = test_key(candidate)
    if result:
        print(f"\n🎊 FOUND with XOR! Position {offset}")
        print(f"🔑 Key: {candidate}")
        print(f"Type: {result[0]}")
        exit(0)

# Strategy 2: SHA256 hash of the entire data
print("\n🔍 Strategy 2: SHA256 of decrypted data...")
hash_key = hashlib.sha256(data).hexdigest()
result = test_key(hash_key)
if result:
    print(f"🎊 FOUND with SHA256!")
    print(f"🔑 Key: {hash_key}")
    exit(0)

# Strategy 3: Take specific 32-byte sections and XOR them
print("\n🔍 Strategy 3: XOR different 32-byte sections...")
section_positions = [0, 32, 64, 128, 256, 384, 512, 640, 768, 896, 1024]

for i, pos1 in enumerate(section_positions):
    for pos2 in section_positions[i+1:]:
        if pos1 + 32 <= len(data) and pos2 + 32 <= len(data):
            section1 = data[pos1:pos1+32]
            section2 = data[pos2:pos2+32]
            xor_section = bytes(a ^ b for a, b in zip(section1, section2))
            
            candidate = xor_section.hex()
            result = test_key(candidate)
            if result:
                print(f"\n🎊 FOUND with section XOR!")
                print(f"  Positions: {pos1} XOR {pos2}")
                print(f"🔑 Key: {candidate}")
                exit(0)

# Strategy 4: First 32 bytes XOR last 32 bytes
print("\n🔍 Strategy 4: First 32 XOR Last 32...")
first_32 = data[:32]
last_32 = data[-32:]
xor_ends = bytes(a ^ b for a, b in zip(first_32, last_32))
candidate = xor_ends.hex()
result = test_key(candidate)
if result:
    print(f"🎊 FOUND with ends XOR!")
    print(f"🔑 Key: {candidate}")
    exit(0)

# Strategy 5: Maybe the data contains TWO encrypted blobs side by side?
# Try decrypting each half separately
print("\n🔍 Strategy 5: Check if halves are separately encrypted...")
# This would need passwords - let's try a few
passwords = [
    "half",
    "betterhalf",
    "GSMG",
    "enter",
    hashlib.sha256(b"half").hexdigest(),
    hashlib.sha256(b"betterhalf").hexdigest(),
]

from Crypto.Cipher import AES

def try_decrypt(blob_data, password):
    try:
        if blob_data[:8] == b'Salted__':
            salt = blob_data[8:16]
            ciphertext = blob_data[16:]
            
            d = d_i = b''
            pwd = password.encode()
            while len(d) < 48:
                d_i = hashlib.md5(d_i + pwd + salt).digest()
                d += d_i
            
            key = d[:32]
            iv = d[32:48]
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            
            padding_length = decrypted[-1]
            if 1 <= padding_length <= 16:
                return decrypted[:-padding_length]
    except:
        pass
    return None

# Check if first half looks encrypted
if first_half[:8] == b'Salted__':
    print("  ✅ First half has Salted__ header!")
    for pwd in passwords:
        result = try_decrypt(first_half, pwd)
        if result and len(result) >= 32:
            candidate = result[:32].hex()
            if test_key(candidate):
                print(f"🎊 FOUND in decrypted first half with password: {pwd}")
                print(f"🔑 Key: {candidate}")
                exit(0)

if second_half[:8] == b'Salted__':
    print("  ✅ Second half has Salted__ header!")
    for pwd in passwords:
        result = try_decrypt(second_half, pwd)
        if result and len(result) >= 32:
            candidate = result[:32].hex()
            if test_key(candidate):
                print(f"🎊 FOUND in decrypted second half with password: {pwd}")
                print(f"🔑 Key: {candidate}")
                exit(0)

# Strategy 6: Maybe combine bytes in alternating pattern
print("\n🔍 Strategy 6: Alternating byte combination...")
alternating = bytearray()
for i in range(32):
    alternating.append(first_half[i])
    if i < len(second_half):
        alternating.append(second_half[i])

if len(alternating) >= 64:
    candidate = bytes(alternating[:64]).hex()
    # This gives us 64 bytes, take first 32
    candidate = candidate[:64]
    result = test_key(candidate)
    if result:
        print(f"🎊 FOUND with alternating!")
        print(f"🔑 Key: {candidate}")
        exit(0)

print("\n❌ No private key found with XOR/combination strategies")
print("\nNext steps:")
print("- The data might need a specific transformation we haven't tried")
print("- There might be additional clues in the puzzle text")
print("- The 'four first hint is your last command' might have another meaning")
