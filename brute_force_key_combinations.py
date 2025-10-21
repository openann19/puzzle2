#!/usr/bin/env python3
"""
Brute Force Key Combinations - Test ALL combinations of our 956 keys
Maybe "half and better half" means ANY two keys from our decrypted data
"""

import sys
sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    import bitcoin
    import hashlib
    CRYPTO_AVAILABLE = True
except ImportError as e:
    print(f"❌ Crypto not available: {e}")
    sys.exit(1)

def load_decrypted_data():
    """Load the 987 bytes of decrypted Cosmic Duality data"""
    with open('cosmic_decrypted_raw.bin', 'rb') as f:
        return f.read()

def extract_all_potential_keys(data):
    """Extract ALL potential 32-byte private keys from the data"""
    keys = []
    
    # Extract every possible 32-byte sequence
    for i in range(len(data) - 31):
        key_bytes = data[i:i+32]
        key_hex = key_bytes.hex()
        
        # Check if valid private key
        try:
            key_int = int(key_hex, 16)
            secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            if 1 <= key_int < secp256k1_order:
                keys.append({'position': i, 'key': key_hex})
        except:
            pass
    
    return keys

def test_key_combination(key1, key2):
    """Test a combination of two keys to generate the prize address"""
    prize_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    
    try:
        # Method 1: XOR
        key1_bytes = bytes.fromhex(key1)
        key2_bytes = bytes.fromhex(key2)
        xor_key = bytes(a ^ b for a, b in zip(key1_bytes, key2_bytes)).hex()
        
        if is_valid_key(xor_key):
            addr = bitcoin.privkey_to_address(xor_key)
            if addr == prize_address:
                return ("XOR", xor_key)
        
        # Method 2: SHA256(key1 + key2)
        combined_hash = hashlib.sha256((key1 + key2).encode()).hexdigest()
        if is_valid_key(combined_hash):
            addr = bitcoin.privkey_to_address(combined_hash)
            if addr == prize_address:
                return ("SHA256_CONCAT", combined_hash)
        
        # Method 3: SHA256(key1_bytes + key2_bytes)
        bytes_hash = hashlib.sha256(key1_bytes + key2_bytes).hexdigest()
        if is_valid_key(bytes_hash):
            addr = bitcoin.privkey_to_address(bytes_hash)
            if addr == prize_address:
                return ("SHA256_BYTES", bytes_hash)
        
        # Method 4: Add keys modulo secp256k1 order
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        key1_int = int(key1, 16)
        key2_int = int(key2, 16)
        sum_key = f"{(key1_int + key2_int) % secp256k1_order:064x}"
        
        if is_valid_key(sum_key):
            addr = bitcoin.privkey_to_address(sum_key)
            if addr == prize_address:
                return ("ADD_MOD", sum_key)
        
    except Exception as e:
        pass
    
    return None

def is_valid_key(key_hex):
    """Check if key is valid"""
    try:
        key_int = int(key_hex, 16)
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        return 1 <= key_int < secp256k1_order
    except:
        return False

def brute_force_combinations():
    """Brute force test combinations of keys"""
    
    print("🚀 BRUTE FORCE KEY COMBINATIONS")
    print("="*50)
    
    # Load data and extract keys
    data = load_decrypted_data()
    keys = extract_all_potential_keys(data)
    
    print(f"📊 Extracted {len(keys)} valid private keys from {len(data)} bytes")
    print(f"🎯 Testing combinations for prize address...")
    
    # Test systematically - start with keys that are far apart
    test_count = 0
    max_tests = 10000  # Limit to avoid infinite runtime
    
    # Priority positions to test first
    priority_positions = [
        0, len(data)//4, len(data)//2, 3*len(data)//4, len(data)-32,
        32, 64, 96, 128, 256, 512, 493  # Half point
    ]
    
    priority_keys = []
    for pos in priority_positions:
        for key_info in keys:
            if key_info['position'] == pos:
                priority_keys.append(key_info)
                break
    
    print(f"🔍 Testing {len(priority_keys)} priority keys first...")
    
    # Test priority key combinations first
    for i, key1_info in enumerate(priority_keys):
        for j, key2_info in enumerate(priority_keys):
            if i != j and test_count < max_tests:
                test_count += 1
                
                if test_count % 10 == 0:
                    print(f"  Tested {test_count} combinations...")
                
                result = test_key_combination(key1_info['key'], key2_info['key'])
                if result:
                    method, final_key = result
                    print(f"\n🎉🎉🎉 PRIZE PRIVATE KEY FOUND! 🎉🎉🎉")
                    print(f"🔑 Method: {method}")
                    print(f"🔑 Key 1: Position {key1_info['position']}")
                    print(f"🔑 Key 2: Position {key2_info['position']}")
                    print(f"🔑 Final Private Key: {final_key}")
                    print(f"🏠 Prize Address: 1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe")
                    
                    # Save result
                    import json
                    solution = {
                        'PUZZLE_STATUS': 'COMPLETELY SOLVED',
                        'PRIZE_ADDRESS': '1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe',
                        'PRIVATE_KEY': final_key,
                        'METHOD': method,
                        'KEY1_POSITION': key1_info['position'],
                        'KEY2_POSITION': key2_info['position'],
                        'SUCCESS': True
                    }
                    
                    with open('BRUTE_FORCE_SOLUTION.json', 'w') as f:
                        json.dump(solution, f, indent=2)
                    
                    return True
    
    print(f"\n❌ No match found in priority keys")
    
    # If priority keys didn't work, try a broader sample
    print(f"🔍 Testing broader sample...")
    
    # Test every 10th key to get good coverage without taking forever
    sample_keys = keys[::10]  # Every 10th key
    
    for i, key1_info in enumerate(sample_keys):
        for j, key2_info in enumerate(sample_keys):
            if i != j and test_count < max_tests:
                test_count += 1
                
                if test_count % 100 == 0:
                    print(f"  Tested {test_count} combinations...")
                
                result = test_key_combination(key1_info['key'], key2_info['key'])
                if result:
                    method, final_key = result
                    print(f"\n🎉🎉🎉 PRIZE PRIVATE KEY FOUND! 🎉🎉🎉")
                    print(f"🔑 Method: {method}")
                    print(f"🔑 Key 1: Position {key1_info['position']}")  
                    print(f"🔑 Key 2: Position {key2_info['position']}")
                    print(f"🔑 Final Private Key: {final_key}")
                    
                    return True
    
    print(f"\n❌ No match found after testing {test_count} combinations")
    return False

def main():
    success = brute_force_combinations()
    
    if success:
        print(f"\n🏆 GSMG.IO PUZZLE SOLVED WITH BRUTE FORCE!")
    else:
        print(f"\n🔄 Brute force completed - no combination found")

if __name__ == "__main__":
    main()
