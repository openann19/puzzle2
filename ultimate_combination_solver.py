#!/usr/bin/env python3
"""
ULTIMATE COMBINATION SOLVER
Test multi-step transformations and nested operations
"""

import hashlib
import bitcoin
import sys

target = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"

hint1_hex = "3de76451365599cd0690b23ae1865aca8e47aee6842cd7e6661ffd18ef95c942"
hint2_hex = "42f5f4b7cbf78cf078a24a6ca7179b462eac13504c9791c8f1192e29e8d4a93bdd58e5fa9d08d2a5ea57c06b8dfe32"

hint1 = bytes.fromhex(hint1_hex)
hint2 = bytes.fromhex(hint2_hex)

with open('cosmic_final_decrypted.bin', 'rb') as f:
    cosmic = f.read()

print(f"🎯 Target: {target}")
print(f"🔥 Testing NESTED and COMBINED operations...\n")

def test_key(key_hex):
    try:
        if len(key_hex) != 64:
            return False
        key_int = int(key_hex, 16)
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        if not (1 <= key_int < secp256k1_order):
            return False
        
        addr = bitcoin.privkey_to_address(key_hex)
        if addr == target:
            return ('compressed', addr)
        
        pubkey = bitcoin.privtopub(key_hex)
        addr_u = bitcoin.pubtoaddr(pubkey, 0)
        if addr_u == target:
            return ('uncompressed', addr_u)
        
        return False
    except:
        return False

def save_solution(key, method):
    print(f"\n🎊🎊🎊 PUZZLE SOLVED! 🎊🎊🎊")
    print(f"🔑 Private Key: {key}")
    print(f"📝 Method: {method}")
    
    import json
    with open('FINAL_SOLUTION_FOUND.json', 'w') as f:
        json.dump({
            'target_address': target,
            'private_key': key,
            'method': method,
            'success': True
        }, f, indent=2)
    
    print("💾 SAVED!")
    sys.exit(0)

# Generate base materials
base_materials = {
    'hint1': hint1,
    'hint2_32': hint2[:32],
    'hint2_full': hint2,
    'cosmic_first32': cosmic[:32],
    'cosmic_last32': cosmic[-32:],
    'cosmic_mid32': cosmic[len(cosmic)//2:len(cosmic)//2+32],
}

# Add XOR results
base_materials['h1_XOR_c0'] = bytes([a ^ b for a, b in zip(hint1, cosmic[:32])])
base_materials['h1_XOR_c32'] = bytes([a ^ b for a, b in zip(hint1, cosmic[32:64])])
base_materials['h1_XOR_h2'] = bytes([a ^ b for a, b in zip(hint1, hint2[:32])])

print("[1] Testing base materials...")
for name, data in base_materials.items():
    if len(data) == 32:
        result = test_key(data.hex())
        if result:
            save_solution(data.hex(), f"Base: {name}")

print("[2] Testing single-step hashes...")
for name, data in base_materials.items():
    # SHA256
    h = hashlib.sha256(data).digest()
    if len(h) == 32:
        result = test_key(h.hex())
        if result:
            save_solution(h.hex(), f"SHA256({name})")
    
    # Double SHA256
    h2 = hashlib.sha256(h).digest()
    result = test_key(h2.hex())
    if result:
        save_solution(h2.hex(), f"SHA256(SHA256({name}))")

print("[3] Testing hash + XOR combinations...")
# Hash one, XOR with another
materials_list = list(base_materials.items())
for i, (name1, data1) in enumerate(materials_list):
    h1 = hashlib.sha256(data1).digest()
    for name2, data2 in materials_list[i+1:]:
        if len(data2) >= 32:
            xor_result = bytes([a ^ b for a, b in zip(h1, data2[:32])])
            result = test_key(xor_result.hex())
            if result:
                save_solution(xor_result.hex(), f"SHA256({name1}) XOR {name2}")

print("[4] Testing XOR + hash combinations...")
for i, (name1, data1) in enumerate(materials_list):
    if len(data1) != 32:
        continue
    for name2, data2 in materials_list[i+1:]:
        if len(data2) < 32:
            continue
        # XOR then hash
        xor_result = bytes([a ^ b for a, b in zip(data1, data2[:32])])
        h = hashlib.sha256(xor_result).digest()
        result = test_key(h.hex())
        if result:
            save_solution(h.hex(), f"SHA256({name1} XOR {name2})")

print("[5] Testing concatenation + hash...")
for name1, data1 in materials_list:
    for name2, data2 in materials_list:
        if name1 != name2:
            combined = data1[:16] + data2[:16]  # Half of each
            h = hashlib.sha256(combined).digest()
            result = test_key(h.hex())
            if result:
                save_solution(h.hex(), f"SHA256({name1}[:16]+{name2}[:16])")

print("[6] Testing with string keys...")
strings = {
    'GSMG': b'GSMG',
    'enter': b'enter', 
    'matrixsumlist': b'matrixsumlist',
    'four': b'four',
    'shabef': b'shabef',
}

for str_name, str_val in strings.items():
    # Hash(string + hint1)
    h = hashlib.sha256(str_val + hint1).digest()
    result = test_key(h.hex())
    if result:
        save_solution(h.hex(), f"SHA256({str_name}+hint1)")
    
    # Hash(hint1 + string)
    h = hashlib.sha256(hint1 + str_val).digest()
    result = test_key(h.hex())
    if result:
        save_solution(h.hex(), f"SHA256(hint1+{str_name})")
    
    # XOR then hash
    xor_result = bytes([hint1[i] ^ str_val[i % len(str_val)] for i in range(32)])
    h = hashlib.sha256(xor_result).digest()
    result = test_key(h.hex())
    if result:
        save_solution(h.hex(), f"SHA256(hint1 XOR {str_name})")

print("[7] Testing modular operations on hashes...")
secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

for name, data in base_materials.items():
    h = hashlib.sha256(data).digest()
    h_int = int(h.hex(), 16)
    
    # Add hint1_int
    hint1_int = int(hint1_hex, 16)
    combined = (h_int + hint1_int) % secp256k1_order
    if 1 <= combined < secp256k1_order:
        result = test_key(format(combined, '064x'))
        if result:
            save_solution(format(combined, '064x'), f"(SHA256({name}) + hint1) mod n")
    
    # Subtract
    combined = (h_int - hint1_int) % secp256k1_order
    if 1 <= combined < secp256k1_order:
        result = test_key(format(combined, '064x'))
        if result:
            save_solution(format(combined, '064x'), f"(SHA256({name}) - hint1) mod n")
    
    # XOR as integers then mod
    combined = (h_int ^ hint1_int) % secp256k1_order
    if 1 <= combined < secp256k1_order:
        result = test_key(format(combined, '064x'))
        if result:
            save_solution(format(combined, '064x'), f"(SHA256({name}) XOR hint1) mod n")

print("[8] Testing PBKDF2 and key derivation...")
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256 as CryptoSHA256

# Use hint1 as password, cosmic as salt
try:
    derived = PBKDF2(hint1, cosmic[:16], 32, count=1000, hmac_hash_module=CryptoSHA256)
    result = test_key(derived.hex())
    if result:
        save_solution(derived.hex(), "PBKDF2(hint1, cosmic[:16], 1000)")
    
    derived = PBKDF2(hint1, cosmic[:16], 32, count=10000, hmac_hash_module=CryptoSHA256)
    result = test_key(derived.hex())
    if result:
        save_solution(derived.hex(), "PBKDF2(hint1, cosmic[:16], 10000)")
    
    # Use cosmic as password
    derived = PBKDF2(cosmic[:32], hint1, 32, count=1000, hmac_hash_module=CryptoSHA256)
    result = test_key(derived.hex())
    if result:
        save_solution(derived.hex(), "PBKDF2(cosmic[:32], hint1, 1000)")
except Exception as e:
    print(f"  PBKDF2 error: {e}")

print("[9] Testing HMAC...")
import hmac

# HMAC(hint1, cosmic)
h = hmac.new(hint1, cosmic, hashlib.sha256).digest()
result = test_key(h.hex())
if result:
    save_solution(h.hex(), "HMAC-SHA256(hint1, cosmic)")

# HMAC(cosmic[:32], hint1)
h = hmac.new(cosmic[:32], hint1, hashlib.sha256).digest()
result = test_key(h.hex())
if result:
    save_solution(h.hex(), "HMAC-SHA256(cosmic[:32], hint1)")

print("[10] Testing every 32-byte window in cosmic with transformations...")
step = 32  # Test every 32 bytes
for offset in range(0, len(cosmic) - 31, step):
    window = cosmic[offset:offset+32]
    
    # XOR with hint1, then hash
    xor_result = bytes([a ^ b for a, b in zip(hint1, window)])
    h = hashlib.sha256(xor_result).digest()
    result = test_key(h.hex())
    if result:
        save_solution(h.hex(), f"SHA256(hint1 XOR cosmic[{offset}])")
    
    # Hash window, then XOR with hint1
    h = hashlib.sha256(window).digest()
    xor_result = bytes([a ^ b for a, b in zip(h, hint1)])
    result = test_key(xor_result.hex())
    if result:
        save_solution(xor_result.hex(), f"SHA256(cosmic[{offset}]) XOR hint1")

print("\n❌ Tested hundreds of nested operations - no match")
print("\nConsider: The solution may require puzzle-specific knowledge")
print("or a transformation unique to the GSMG puzzle design.")
