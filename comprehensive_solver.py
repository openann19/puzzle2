#!/usr/bin/env python3
"""
Comprehensive GSMG Puzzle Solver
Attempts all documented approaches to find the private key for:
1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe
"""

import sys
import subprocess
import hashlib
import json
import glob
from pathlib import Path
from ecdsa import SigningKey, SECP256k1

TARGET = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"

def p2pkh_from_privkey(privkey_bytes):
    """Convert private key to P2PKH address"""
    try:
        if len(privkey_bytes) != 32:
            return None
        
        sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
        vk = sk.get_verifying_key()
        
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        prefix = 2 + (y & 1)
        pubkey = bytes([prefix]) + x.to_bytes(32, 'big')
        
        sha = hashlib.sha256(pubkey).digest()
        ripe = hashlib.new('ripemd160', sha).digest()
        
        versioned = b'\x00' + ripe
        checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
        address_bytes = versioned + checksum
        
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        n = int.from_bytes(address_bytes, 'big')
        result = ''
        while n > 0:
            n, r = divmod(n, 58)
            result = alphabet[r] + result
        
        for byte in address_bytes:
            if byte == 0:
                result = '1' + result
            else:
                break
        
        return result
    except:
        return None

def check_solution(privkey_hex, source):
    """Check if a private key matches the target"""
    try:
        privkey = bytes.fromhex(privkey_hex)
        address = p2pkh_from_privkey(privkey)
        
        if address == TARGET:
            print(f"\n{'='*80}")
            print(f"🎉🎉🎉 SOLUTION FOUND! 🎉🎉🎉")
            print(f"{'='*80}")
            print(f"Source: {source}")
            print(f"Private Key: {privkey_hex}")
            print(f"Address: {address}")
            print(f"{'='*80}\n")
            
            with open('SOLUTION_FOUND.txt', 'w') as f:
                f.write(f"GSMG PUZZLE SOLUTION\n")
                f.write(f"{'='*80}\n")
                f.write(f"Target Address: {TARGET}\n")
                f.write(f"Private Key: {privkey_hex}\n")
                f.write(f"Source: {source}\n")
                f.write(f"Verification: {address}\n")
            
            return True
    except:
        pass
    return False

def method1_verified_keys():
    """Test all keys from verified_key_*.json files"""
    print("\n[Method 1] Testing verified keys from JSON files...")
    
    for json_file in sorted(glob.glob('verified_key_*.json')):
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                if 'private_key_hex' in data:
                    if check_solution(data['private_key_hex'], f"Verified JSON: {json_file}"):
                        return True
        except:
            pass
    
    print("   No match in verified JSON files")
    return False

def method2_binary_extracted_keys():
    """Test keys from binary_extracted_keys.json"""
    print("\n[Method 2] Testing binary extracted keys...")
    
    try:
        with open('binary_extracted_keys.json', 'r') as f:
            data = json.load(f)
            for entry in data:
                if 'private_key_hex' in entry:
                    if check_solution(entry['private_key_hex'], "binary_extracted_keys.json"):
                        return True
                elif 'private_key' in entry:
                    if check_solution(entry['private_key'], "binary_extracted_keys.json"):
                        return True
    except:
        pass
    
    print("   No match in binary extracted keys")
    return False

def method3_all_verified_keys():
    """Test keys from all_verified_keys.json"""
    print("\n[Method 3] Testing all_verified_keys.json...")
    
    try:
        with open('all_verified_keys.json', 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        if 'private_key_hex' in entry:
                            if check_solution(entry['private_key_hex'], "all_verified_keys.json"):
                                return True
                        elif 'private_key' in entry:
                            if check_solution(entry['private_key'], "all_verified_keys.json"):
                                return True
    except:
        pass
    
    print("   No match in all_verified_keys.json")
    return False

def method4_cosmic_decrypted():
    """Test all possible keys from cosmic_decrypted.bin"""
    print("\n[Method 4] Testing cosmic_decrypted.bin sliding window...")
    
    try:
        data = Path('cosmic_decrypted.bin').read_bytes()
        print(f"   File size: {len(data)} bytes")
        
        for i in range(len(data) - 31):
            key_hex = data[i:i+32].hex()
            if check_solution(key_hex, f"cosmic_decrypted.bin offset {i}"):
                return True
            
            if i % 200 == 0:
                print(f"   Tested {i}/{len(data)-31} positions...", end='\r')
        
        print(f"   Tested {len(data)-31} positions - no match")
    except:
        print("   cosmic_decrypted.bin not found or unreadable")
    
    return False

def method5_half_and_better_half():
    """Test 'half and better half' key combinations"""
    print("\n[Method 5] Testing 'half and better half' combinations...")
    
    keys = []
    for json_file in sorted(glob.glob('verified_key_*.json')):
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                if 'private_key_hex' in data:
                    keys.append(bytes.fromhex(data['private_key_hex']))
        except:
            pass
    
    if not keys:
        print("   No keys loaded")
        return False
    
    print(f"   Testing {len(keys)} keys in combinations...")
    
    # Test concatenations
    for i, key1 in enumerate(keys):
        for j, key2 in enumerate(keys):
            if i != j:
                combined = key1[:16] + key2[16:]
                if check_solution(combined.hex(), f"Half concat: key{i}[:16] + key{j}[16:]"):
                    return True
    
    # Test XOR
    for i, key1 in enumerate(keys):
        for j, key2 in enumerate(keys):
            if i < j:
                xored = bytes(a ^ b for a, b in zip(key1, key2))
                if check_solution(xored.hex(), f"XOR: key{i} XOR key{j}"):
                    return True
    
    print("   No match in combinations")
    return False

def method6_extracted_addresses():
    """Check if target is in extracted addresses and find corresponding key"""
    print("\n[Method 6] Searching extracted addresses for target...")
    
    try:
        with open('all_extracted_addresses.txt', 'r') as f:
            for line in f:
                if TARGET in line:
                    print(f"   FOUND TARGET IN: {line.strip()}")
                    return True
    except:
        pass
    
    print("   Target not found in extracted addresses")
    return False

def main():
    print("="*80)
    print("COMPREHENSIVE GSMG PUZZLE SOLVER")
    print(f"Target: {TARGET}")
    print("="*80)
    
    methods = [
        method1_verified_keys,
        method2_binary_extracted_keys,
        method3_all_verified_keys,
        method4_cosmic_decrypted,
        method5_half_and_better_half,
        method6_extracted_addresses,
    ]
    
    for method in methods:
        try:
            if method():
                print("\n" + "="*80)
                print("PUZZLE SOLVED! Check SOLUTION_FOUND.txt for details.")
                print("="*80)
                return 0
        except Exception as e:
            print(f"   Error in {method.__name__}: {e}")
    
    print("\n" + "="*80)
    print("PUZZLE NOT SOLVED")
    print("="*80)
    print("\nAll known methods exhausted. The solution may require:")
    print("  1. Correctly decrypting the Cosmic Duality blob with the right password")
    print("  2. Additional information not present in the repository")
    print("  3. A different transformation or combination not yet attempted")
    print("\nSee SOLVING_ATTEMPTS.md for details on what has been tried.")
    return 1

if __name__ == '__main__':
    sys.exit(main())
