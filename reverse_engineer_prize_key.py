#!/usr/bin/env python3
"""
Reverse Engineer Prize Key - Work backwards from the target Hash160
Target: a9553269572a317e39f0f518cb87c1a0ee1dbae4
"""

import sys
import hashlib
import struct

sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    import bitcoin
    CRYPTO_AVAILABLE = True
except ImportError as e:
    print(f"❌ Crypto not available: {e}")
    sys.exit(1)

def load_decrypted_data():
    """Load the 987 bytes of decrypted Cosmic Duality data"""
    with open('cosmic_decrypted_raw.bin', 'rb') as f:
        return f.read()

def analyze_target_hash160():
    """Analyze the target Hash160 for patterns"""
    
    target_hash160 = "a9553269572a317e39f0f518cb87c1a0ee1dbae4"
    prize_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    
    print("🎯 TARGET HASH160 ANALYSIS")
    print("="*50)
    print(f"Prize Address: {prize_address}")
    print(f"Target Hash160: {target_hash160}")
    print(f"Hash160 bytes: {bytes.fromhex(target_hash160)}")
    
    # Look for patterns in the hash160
    hash_bytes = bytes.fromhex(target_hash160)
    print(f"\nHash160 as integers:")
    for i in range(0, len(hash_bytes), 4):
        chunk = hash_bytes[i:i+4]
        if len(chunk) == 4:
            val = struct.unpack('>I', chunk)[0]
            print(f"  Bytes {i:2d}-{i+3:2d}: {chunk.hex()} = {val:10d} = 0x{val:08x}")
    
    return target_hash160

def test_half_better_half_data_splits():
    """Test different ways to split the decrypted data for 'half and better half'"""
    
    print("\n🔍 TESTING HALF AND BETTER HALF DATA SPLITS")
    print("="*60)
    
    data = load_decrypted_data()
    target_hash160 = "a9553269572a317e39f0f518cb87c1a0ee1dbae4"
    
    print(f"📊 Data length: {len(data)} bytes")
    
    # Method 1: Split at exact half
    half_point = len(data) // 2  # 493
    first_half = data[:half_point]
    second_half = data[half_point:]
    
    print(f"\n1️⃣ EXACT HALF SPLIT (at byte {half_point}):")
    print(f"   First half: {len(first_half)} bytes")
    print(f"   Second half: {len(second_half)} bytes")
    
    # Test various combinations of the halves
    combinations = [
        ("first_half", first_half),
        ("second_half", second_half),
        ("concatenated", first_half + second_half),
        ("reverse_concat", second_half + first_half),
        ("xor_padded", xor_bytes_with_padding(first_half, second_half)),
        ("sha256_first", hashlib.sha256(first_half).digest()),
        ("sha256_second", hashlib.sha256(second_half).digest()),
        ("sha256_both", hashlib.sha256(first_half + second_half).digest()),
        ("sha256_reverse", hashlib.sha256(second_half + first_half).digest()),
    ]
    
    for name, data_combo in combinations:
        # Ensure we have 32 bytes for a private key
        if len(data_combo) > 32:
            # Use SHA256 to reduce to 32 bytes
            key_material = hashlib.sha256(data_combo).digest()
        elif len(data_combo) < 32:
            # Pad to 32 bytes
            key_material = data_combo + b'\x00' * (32 - len(data_combo))
        else:
            key_material = data_combo
        
        key_hex = key_material.hex()
        
        # Test if this generates the target address
        if test_key_for_target(key_hex, name, target_hash160):
            return True
    
    # Method 2: Test different split points around the half
    print(f"\n2️⃣ TESTING NEARBY SPLIT POINTS:")
    for offset in range(-10, 11):  # Test ±10 bytes around half point
        split_point = half_point + offset
        if 0 < split_point < len(data):
            part1 = data[:split_point]
            part2 = data[split_point:]
            
            # Test SHA256 of each part
            key1 = hashlib.sha256(part1).hexdigest()
            key2 = hashlib.sha256(part2).hexdigest()
            
            if test_key_for_target(key1, f"sha256_part1_split{split_point}", target_hash160):
                return True
            if test_key_for_target(key2, f"sha256_part2_split{split_point}", target_hash160):
                return True
    
    return False

def xor_bytes_with_padding(data1, data2):
    """XOR two byte arrays with padding to make them same length"""
    max_len = max(len(data1), len(data2))
    padded1 = data1 + b'\x00' * (max_len - len(data1))
    padded2 = data2 + b'\x00' * (max_len - len(data2))
    
    return bytes(a ^ b for a, b in zip(padded1, padded2))

def test_key_for_target(private_key_hex, key_name, target_hash160):
    """Test if private key generates the target hash160"""
    
    try:
        # Validate the key
        if not is_valid_private_key(private_key_hex):
            return False
        
        # Generate public key
        pubkey = bitcoin.privkey_to_pubkey(private_key_hex)
        
        # Generate address
        address = bitcoin.privkey_to_address(private_key_hex)
        
        # Extract hash160 from address
        import base58
        decoded = base58.b58decode_check(address)
        hash160 = decoded[1:].hex()
        
        if hash160 == target_hash160:
            print(f"\n🎉🎉🎉 PRIZE PRIVATE KEY FOUND! 🎉🎉🎉")
            print(f"🔑 Method: {key_name}")
            print(f"🔑 Private Key: {private_key_hex}")
            print(f"🔑 Public Key: {pubkey}")
            print(f"🏠 Address: {address}")
            print(f"🎯 Hash160: {hash160}")
            
            # Save the solution
            import json
            solution = {
                'PUZZLE_STATUS': 'COMPLETELY SOLVED!',
                'PRIZE_ADDRESS': address,
                'PRIVATE_KEY': private_key_hex,
                'PUBLIC_KEY': pubkey,
                'METHOD': key_name,
                'HASH160': hash160,
                'SUCCESS': True
            }
            
            with open('PRIZE_PRIVATE_KEY_SOLUTION.json', 'w') as f:
                json.dump(solution, f, indent=2)
                
            print(f"💾 Solution saved to: PRIZE_PRIVATE_KEY_SOLUTION.json")
            return True
            
    except Exception as e:
        pass
    
    return False

def is_valid_private_key(key_hex):
    """Check if private key is in valid secp256k1 range"""
    try:
        key_int = int(key_hex, 16)
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        return 1 <= key_int < secp256k1_order
    except:
        return False

def test_pattern_based_combinations():
    """Test combinations based on the 'half and better half' phrase patterns"""
    
    print(f"\n3️⃣ TESTING PATTERN-BASED COMBINATIONS:")
    print("="*50)
    
    data = load_decrypted_data()
    target_hash160 = "a9553269572a317e39f0f518cb87c1a0ee1dbae4"
    
    # Based on successful passwords we know
    known_elements = [
        "matrixsumlist",
        "enter", 
        "lastwordsbeforearchichoice",
        "thispassword",
        "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"  # SalPhaseIon hash
    ]
    
    # Test if "half" and "better half" reference specific parts of these elements
    for element in known_elements:
        if len(element) >= 4:  # Must be splittable
            mid = len(element) // 2
            first_part = element[:mid]  # "half"
            second_part = element[mid:]  # "better half"
            
            # Test various combinations
            test_patterns = [
                ("half", hashlib.sha256(first_part.encode()).hexdigest()),
                ("better_half", hashlib.sha256(second_part.encode()).hexdigest()),
                ("half_better_combined", hashlib.sha256((first_part + second_part).encode()).hexdigest()),
                ("better_half_combined", hashlib.sha256((second_part + first_part).encode()).hexdigest()),
            ]
            
            for pattern_name, key_hex in test_patterns:
                if test_key_for_target(key_hex, f"{element}_{pattern_name}", target_hash160):
                    return True
    
    return False

def main():
    """Main execution"""
    
    print("🚀 REVERSE ENGINEERING THE PRIZE PRIVATE KEY")
    print("="*70)
    
    # Analyze the target
    target_hash160 = analyze_target_hash160()
    
    # Test various half/better half interpretations
    success = False
    
    # Test 1: Data splits
    success = test_half_better_half_data_splits()
    
    # Test 2: Pattern-based combinations  
    if not success:
        success = test_pattern_based_combinations()
    
    if success:
        print(f"\n🏆🏆🏆 GSMG.IO PUZZLE COMPLETELY SOLVED! 🏆🏆🏆")
        print(f"🎊 The 'half and better half' mystery is solved!")
    else:
        print(f"\n🔄 Continue investigating the 'half and better half' clue...")
        print(f"   Try examining the specific segments in the decrypted data")
        print(f"   Look for additional patterns in the 987-byte payload")

if __name__ == "__main__":
    main()
