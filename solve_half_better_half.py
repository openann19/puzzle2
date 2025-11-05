#!/usr/bin/env python3
"""
Test "half and better half" hypothesis
The VIC cipher result mentions: "THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF"
Maybe we need to combine keys from the SalPhaseIon decryption
"""

import hashlib
from ecdsa import SigningKey, SECP256k1
import json

TARGET = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"

def p2pkh_from_privkey(privkey_bytes):
    """Convert private key bytes to P2PKH address"""
    try:
        if len(privkey_bytes) != 32:
            return None
        
        sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
        vk = sk.get_verifying_key()
        
        # Compressed public key
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        prefix = 2 + (y & 1)
        pubkey = bytes([prefix]) + x.to_bytes(32, 'big')
        
        # Hash160
        sha = hashlib.sha256(pubkey).digest()
        ripe = hashlib.new('ripemd160', sha).digest()
        
        # Add version byte and checksum
        versioned = b'\x00' + ripe
        checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
        address_bytes = versioned + checksum
        
        # Base58 encode
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        n = int.from_bytes(address_bytes, 'big')
        result = ''
        while n > 0:
            n, r = divmod(n, 58)
            result = alphabet[r] + result
        
        # Add leading 1s for leading 0 bytes
        for byte in address_bytes:
            if byte == 0:
                result = '1' + result
            else:
                break
        
        return result
    except Exception as e:
        return None

def load_keys_from_verified_json():
    """Load keys from verified_key_*.json files"""
    import glob
    keys = []
    
    for json_file in sorted(glob.glob('verified_key_*.json')):
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                if 'private_key_hex' in data:
                    keys.append(bytes.fromhex(data['private_key_hex']))
                elif 'private_key' in data:
                    keys.append(bytes.fromhex(data['private_key']))
        except Exception as e:
            print(f"Error loading {json_file}: {e}")
    
    return keys

def test_half_combinations(keys):
    """Test different 'half and better half' combinations"""
    print(f"Testing {len(keys)} keys for 'half and better half' combinations...")
    print(f"Target: {TARGET}\n")
    
    operations = []
    
    # Test 1: First half of one key + second half of another
    for i, key1 in enumerate(keys):
        for j, key2 in enumerate(keys):
            if i != j:
                combined = key1[:16] + key2[16:]
                operations.append(('half_concat', i, j, combined))
                
                combined2 = key2[:16] + key1[16:]
                operations.append(('half_concat', j, i, combined2))
    
    # Test 2: XOR of two keys
    for i, key1 in enumerate(keys):
        for j, key2 in enumerate(keys):
            if i < j:  # Only test each pair once
                xored = bytes(a ^ b for a, b in zip(key1, key2))
                operations.append(('xor', i, j, xored))
    
    # Test 3: Addition (mod secp256k1 order)
    secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    for i, key1 in enumerate(keys):
        for j, key2 in enumerate(keys):
            if i < j:
                val1 = int.from_bytes(key1, 'big')
                val2 = int.from_bytes(key2, 'big')
                added = (val1 + val2) % secp256k1_order
                operations.append(('add_mod', i, j, added.to_bytes(32, 'big')))
    
    print(f"Testing {len(operations)} combinations...")
    
    for idx, (op, i, j, result_key) in enumerate(operations):
        address = p2pkh_from_privkey(result_key)
        
        if address == TARGET:
            print(f"\n{'='*80}")
            print(f"🎉 FOUND TARGET ADDRESS! 🎉")
            print(f"{'='*80}")
            print(f"Operation: {op}")
            print(f"Key indices: {i}, {j}")
            print(f"Private Key: {result_key.hex()}")
            print(f"Address: {address}")
            print(f"{'='*80}\n")
            
            # Save solution
            with open('SOLUTION_FOUND.txt', 'w') as f:
                f.write(f"HALF AND BETTER HALF SOLUTION\n")
                f.write(f"{'='*80}\n")
                f.write(f"Target Address: {TARGET}\n")
                f.write(f"Private Key: {result_key.hex()}\n")
                f.write(f"Operation: {op}\n")
                f.write(f"Source Keys: {i}, {j}\n")
                f.write(f"Key 1: {keys[i].hex()}\n")
                f.write(f"Key 2: {keys[j].hex()}\n")
            
            return 0
        
        if (idx + 1) % 100 == 0:
            print(f"Tested {idx + 1}/{len(operations)} combinations...", end='\r')
    
    print(f"\nTested {len(operations)} combinations - no match found")
    return 1

def main():
    print("=" * 80)
    print("HALF AND BETTER HALF SOLVER")
    print("=" * 80)
    
    keys = load_keys_from_verified_json()
    print(f"\nLoaded {len(keys)} keys from verified_key_*.json files\n")
    
    if not keys:
        print("No keys found! Looking for verified_key_*.json files...")
        return 1
    
    return test_half_combinations(keys)

if __name__ == '__main__':
    import sys
    sys.exit(main())
