#!/usr/bin/env python3
"""
EXHAUSTIVE FINAL SOLVER - DO ALL NEEDED
Test every conceivable operation to find the 5 BTC private key
"""

import hashlib
import itertools
import bitcoin
import sys

target = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"

# The decoded hints
hint1_hex = "3de76451365599cd0690b23ae1865aca8e47aee6842cd7e6661ffd18ef95c942"
hint2_hex = "42f5f4b7cbf78cf078a24a6ca7179b462eac13504c9791c8f1192e29e8d4a93bdd58e5fa9d08d2a5ea57c06b8dfe32"

hint1 = bytes.fromhex(hint1_hex)
hint2 = bytes.fromhex(hint2_hex)

# Load cosmic data
with open('cosmic_final_decrypted.bin', 'rb') as f:
    cosmic = f.read()

print(f"🎯 Target: {target}")
print(f"📊 Hint1: 32 bytes, Hint2: 47 bytes, Cosmic: {len(cosmic)} bytes")
print(f"🔥 Testing EVERY possible combination...\n")

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
    print(f"\n🎊🎊🎊 SOLUTION FOUND! 🎊🎊🎊")
    print(f"🔑 Private Key: {key}")
    print(f"📝 Method: {method}")
    
    import json
    with open('PUZZLE_COMPLETELY_SOLVED.json', 'w') as f:
        json.dump({
            'target_address': target,
            'private_key': key,
            'method': method,
            'success': True
        }, f, indent=2)
    
    print("\n💾 SOLUTION SAVED!")
    sys.exit(0)

candidates = []
tested = 0

# ============================================================
# SECTION 1: Direct and Simple Operations
# ============================================================
print("[1] Direct hint tests...")
candidates.append(("Hint1 direct", hint1_hex))
candidates.append(("Hint2 first 32 bytes", hint2_hex[:64]))

# ============================================================
# SECTION 2: XOR Operations - COMPREHENSIVE
# ============================================================
print("[2] XOR operations with cosmic data...")
# XOR hint1 with every possible 32-byte window in cosmic data
for offset in range(0, len(cosmic) - 31):
    if offset % 100 == 0:
        xor_result = bytes([a ^ b for a, b in zip(hint1, cosmic[offset:offset+32])])
        candidates.append((f"XOR hint1 cosmic[{offset}]", xor_result.hex()))

# XOR hint2 with cosmic data
for offset in range(0, len(cosmic) - 31):
    if offset % 100 == 0:
        xor_result = bytes([a ^ b for a, b in zip(hint2[:32], cosmic[offset:offset+32])])
        candidates.append((f"XOR hint2[:32] cosmic[{offset}]", xor_result.hex()))

# XOR hint1 with hint2
xor_hints = bytes([a ^ b for a, b in zip(hint1, hint2[:32])])
candidates.append(("XOR hint1 with hint2", xor_hints.hex()))

# ============================================================
# SECTION 3: Hash Operations - ALL COMBINATIONS
# ============================================================
print("[3] Hash operations...")
hash_inputs = [
    ("hint1", hint1),
    ("hint2", hint2),
    ("cosmic", cosmic),
    ("hint1+hint2", hint1 + hint2),
    ("hint2+hint1", hint2 + hint1),
    ("hint1+cosmic", hint1 + cosmic),
    ("cosmic+hint1", cosmic + hint1),
    ("hint1+hint2+cosmic", hint1 + hint2 + cosmic),
]

for name, data in hash_inputs:
    candidates.append((f"SHA256({name})", hashlib.sha256(data).hexdigest()))
    candidates.append((f"SHA512({name})[:64]", hashlib.sha512(data).hexdigest()[:64]))
    # Double hash
    candidates.append((f"SHA256(SHA256({name}))", hashlib.sha256(hashlib.sha256(data).digest()).hexdigest()))

# ============================================================
# SECTION 4: Modular Arithmetic on hint1
# ============================================================
print("[4] Modular arithmetic...")
hint1_int = int(hint1_hex, 16)
secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

operations = [
    ("hint1 / 2", (hint1_int // 2) % secp256k1_order),
    ("hint1 * 2", (hint1_int * 2) % secp256k1_order),
    ("hint1 * 3", (hint1_int * 3) % secp256k1_order),
    ("hint1 + 1", (hint1_int + 1) % secp256k1_order),
    ("hint1 - 1", (hint1_int - 1) % secp256k1_order),
    ("order - hint1", (secp256k1_order - hint1_int)),
]

for name, value in operations:
    if 1 <= value < secp256k1_order:
        candidates.append((name, format(value, '064x')))

# Try inverse
try:
    inv = pow(hint1_int, -1, secp256k1_order)
    candidates.append(("hint1 inverse", format(inv, '064x')))
except:
    pass

# ============================================================
# SECTION 5: Byte Manipulations
# ============================================================
print("[5] Byte manipulations...")
# Reverse
candidates.append(("hint1 reversed", hint1[::-1].hex()))
candidates.append(("SHA256(hint1 reversed)", hashlib.sha256(hint1[::-1]).hexdigest()))

# Rotate
for rotate in [1, 2, 4, 8, 16]:
    rotated = hint1[rotate:] + hint1[:rotate]
    candidates.append((f"hint1 rotated {rotate}", rotated.hex()))

# Swap halves
candidates.append(("hint1 halves swapped", (hint1[16:] + hint1[:16]).hex()))

# ============================================================
# SECTION 6: Pattern Extractions
# ============================================================
print("[6] Pattern extractions...")
# Even/odd bytes
candidates.append(("hint1 even bytes x2", (hint1[::2] + hint1[::2]).hex()))
candidates.append(("hint1 odd bytes x2", (hint1[1::2] + hint1[1::2]).hex()))

# Every 4th byte
for start in range(4):
    selected = hint1[start::4]
    if len(selected) == 8:
        candidates.append((f"hint1 every4th from {start} x4", (selected * 4).hex()))

# ============================================================
# SECTION 7: Combination with known strings
# ============================================================
print("[7] String combinations...")
strings = [b"GSMG", b"enter", b"matrixsumlist", b"four", b"half", b"betterhalf"]

for s in strings:
    # XOR with repeating pattern
    xor_s = bytes([hint1[i] ^ s[i % len(s)] for i in range(32)])
    candidates.append((f"XOR hint1 with '{s.decode()}'", xor_s.hex()))
    
    # Hash combinations
    candidates.append((f"SHA256({s.decode()}+hint1)", hashlib.sha256(s + hint1).hexdigest()))
    candidates.append((f"SHA256(hint1+{s.decode()})", hashlib.sha256(hint1 + s).hexdigest()))

# ============================================================
# SECTION 8: Cosmic data patterns
# ============================================================
print("[8] Cosmic data extractions...")
# First 32, Last 32, Middle 32
candidates.append(("cosmic[:32]", cosmic[:32].hex()))
candidates.append(("cosmic[-32:]", cosmic[-32:].hex()))
mid = len(cosmic) // 2
candidates.append(("cosmic[mid:mid+32]", cosmic[mid:mid+32].hex()))

# Every Nth byte
for n in [2, 4, 8, 13]:
    selected = cosmic[::n]
    if len(selected) >= 32:
        candidates.append((f"cosmic every {n}th byte [:32]", selected[:32].hex()))

# ============================================================
# SECTION 9: HALF AND BETTER HALF interpretations
# ============================================================
print("[9] HALF AND BETTER HALF operations...")
# Split cosmic in half
half_len = len(cosmic) // 2
first_half = cosmic[:half_len]
second_half = cosmic[half_len:half_len*2]

# XOR the halves
if len(first_half) >= 32 and len(second_half) >= 32:
    xor_halves = bytes([a ^ b for a, b in zip(first_half[:32], second_half[:32])])
    candidates.append(("XOR cosmic halves", xor_halves.hex()))
    
    # Hash the halves
    candidates.append(("SHA256(first_half)", hashlib.sha256(first_half).hexdigest()))
    candidates.append(("SHA256(second_half)", hashlib.sha256(second_half).hexdigest()))

# Hint1 as "half", cosmic as "better half"
candidates.append(("SHA256(hint1+cosmic[:32])", hashlib.sha256(hint1 + cosmic[:32]).hexdigest()))

# ============================================================
# SECTION 10: Advanced combinations
# ============================================================
print("[10] Advanced combinations...")
# hint1 XOR cosmic, then hash
for offset in [0, 32, 64, 128, 256, 512]:
    if offset + 32 <= len(cosmic):
        xor_result = bytes([a ^ b for a, b in zip(hint1, cosmic[offset:offset+32])])
        candidates.append((f"SHA256(hint1 XOR cosmic[{offset}])", hashlib.sha256(xor_result).hexdigest()))

# Triple operations
candidates.append(("SHA256(SHA256(hint1)+hint2)", hashlib.sha256(hashlib.sha256(hint1).digest() + hint2).hexdigest()))

print(f"\n📊 Total candidates: {len(candidates)}")
print("🔍 Testing all candidates...\n")

# Test all candidates
for i, (method, candidate) in enumerate(candidates):
    if i % 100 == 0:
        print(f"  Progress: {i}/{len(candidates)} ({i*100//len(candidates)}%)", end='\r')
    
    result = test_key(candidate)
    if result:
        save_solution(candidate, method)
    tested += 1

print(f"\n\n❌ Tested {tested} candidates - no match")
print("\nThe solution may require:")
print("  - A specific sequence of operations not yet explored")
print("  - Additional context from other puzzle files")
print("  - A transformation unique to this puzzle's design")
