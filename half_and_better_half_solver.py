#!/usr/bin/env python3
"""
HALF AND BETTER HALF SOLVER - The Missing Piece!
The puzzle text says: "THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF"
This means we need TWO keys from our 956 candidates!
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

def extract_half_and_better_half_keys(data):
    """Extract the HALF and BETTER HALF keys from specific positions"""
    
    print("🔍 EXTRACTING HALF AND BETTER HALF KEYS")
    print("="*50)
    print(f"📊 Data length: {len(data)} bytes")
    
    # Key positions to try
    half_point = len(data) // 2  # 493
    
    positions = {
        'half_at_start': 0,
        'better_half_at_middle': half_point,
        'half_at_middle': half_point, 
        'better_half_at_end': len(data) - 32,
        'half_at_256': 256,
        'better_half_at_512': 512,
    }
    
    keys = {}
    for name, pos in positions.items():
        if pos + 32 <= len(data):
            key_hex = data[pos:pos+32].hex()
            keys[name] = {
                'position': pos,
                'private_key': key_hex,
                'valid': is_valid_private_key(key_hex)
            }
            print(f"🔑 {name}: Position {pos} -> {'✅' if keys[name]['valid'] else '❌'}")
    
    return keys

def is_valid_private_key(key_hex):
    """Check if private key is in valid secp256k1 range"""
    try:
        key_int = int(key_hex, 16)
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        return 1 <= key_int < secp256k1_order
    except:
        return False

def test_private_key_for_prize(private_key_hex):
    """Test if private key generates the prize address"""
    try:
        if not is_valid_private_key(private_key_hex):
            return False
        generated_address = bitcoin.privkey_to_address(private_key_hex)
        return generated_address == "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    except:
        return False

def combine_keys_methods(half_key, better_half_key):
    """Try different methods to combine HALF and BETTER HALF keys"""
    
    print(f"\n🔗 COMBINING KEYS")
    print(f"🔑 Half key: {half_key[:16]}...{half_key[-16:]}")
    print(f"🔑 Better half key: {better_half_key[:16]}...{better_half_key[-16:]}")
    
    combinations = []
    
    try:
        # Method 1: XOR the keys
        half_bytes = bytes.fromhex(half_key)
        better_bytes = bytes.fromhex(better_half_key)
        xor_result = bytes(a ^ b for a, b in zip(half_bytes, better_bytes))
        combinations.append(("XOR", xor_result.hex()))
        
        # Method 2: Add the keys (modulo secp256k1 order)
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        half_int = int(half_key, 16)
        better_int = int(better_half_key, 16)
        sum_result = (half_int + better_int) % secp256k1_order
        combinations.append(("ADD", f"{sum_result:064x}"))
        
        # Method 3: Subtract better from half
        sub_result = (half_int - better_int) % secp256k1_order
        combinations.append(("SUBTRACT", f"{sub_result:064x}"))
        
        # Method 4: SHA256(half + better)
        concat_hash = hashlib.sha256((half_key + better_half_key).encode()).hexdigest()
        combinations.append(("SHA256_CONCAT_HEX", concat_hash))
        
        # Method 5: SHA256(half_bytes + better_bytes)
        concat_bytes_hash = hashlib.sha256(half_bytes + better_bytes).hexdigest()
        combinations.append(("SHA256_CONCAT_BYTES", concat_bytes_hash))
        
        # Method 6: SHA256(better + half) - reverse order
        reverse_hash = hashlib.sha256((better_half_key + half_key).encode()).hexdigest()
        combinations.append(("SHA256_REVERSE_HEX", reverse_hash))
        
        # Method 7: SHA256(better_bytes + half_bytes)
        reverse_bytes_hash = hashlib.sha256(better_bytes + half_bytes).hexdigest()
        combinations.append(("SHA256_REVERSE_BYTES", reverse_bytes_hash))
        
        # Method 8: MD5 combinations (puzzle used MD5 before)
        md5_concat = hashlib.md5((half_key + better_half_key).encode()).hexdigest()
        # Double MD5 to get 32 bytes
        md5_double = md5_concat + hashlib.md5(md5_concat.encode()).hexdigest()
        combinations.append(("MD5_DOUBLE", md5_double))
        
    except Exception as e:
        print(f"❌ Error combining keys: {e}")
    
    return combinations

def test_all_combinations():
    """Test all possible HALF and BETTER HALF combinations"""
    
    print("🚀 HALF AND BETTER HALF SOLVER")
    print("="*60)
    
    # Load data
    data = load_decrypted_data()
    
    # Extract potential keys at key positions
    key_candidates = extract_half_and_better_half_keys(data)
    
    # Get valid keys only
    valid_keys = {name: info for name, info in key_candidates.items() if info['valid']}
    
    if len(valid_keys) < 2:
        print(f"❌ Need at least 2 valid keys, found {len(valid_keys)}")
        return False
    
    print(f"\n🔍 Testing combinations of {len(valid_keys)} valid keys...")
    
    # Test all combinations of valid keys
    valid_key_list = list(valid_keys.items())
    
    for i, (half_name, half_info) in enumerate(valid_key_list):
        for j, (better_name, better_info) in enumerate(valid_key_list):
            if i != j:  # Don't combine key with itself
                
                print(f"\n🔗 Testing: {half_name} + {better_name}")
                
                combinations = combine_keys_methods(
                    half_info['private_key'], 
                    better_info['private_key']
                )
                
                for method, combined_key in combinations:
                    if test_private_key_for_prize(combined_key):
                        print(f"\n🎉🎉🎉 PRIZE PRIVATE KEY FOUND! 🎉🎉🎉")
                        print(f"🔑 Method: {method}")
                        print(f"🔑 Half: {half_name} (pos {half_info['position']})")
                        print(f"🔑 Better Half: {better_name} (pos {better_info['position']})")
                        print(f"🔑 Combined Private Key: {combined_key}")
                        print(f"🏠 Prize Address: 1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe")
                        
                        # Save the solution
                        import json
                        solution = {
                            'PUZZLE_STATUS': 'COMPLETELY SOLVED',
                            'PRIZE_ADDRESS': '1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe',
                            'PRIVATE_KEY': combined_key,
                            'SOLUTION_METHOD': method,
                            'HALF_KEY': {
                                'name': half_name,
                                'position': half_info['position'],
                                'private_key': half_info['private_key']
                            },
                            'BETTER_HALF_KEY': {
                                'name': better_name,
                                'position': better_info['position'],
                                'private_key': better_info['private_key']
                            },
                            'SUCCESS': True
                        }
                        
                        with open('HALF_AND_BETTER_HALF_SOLUTION.json', 'w') as f:
                            json.dump(solution, f, indent=2)
                        
                        print(f"💾 Solution saved: HALF_AND_BETTER_HALF_SOLUTION.json")
                        return True
                    else:
                        print(f"  ❌ {method}: No match")
    
    print(f"\n❌ No successful combination found")
    return False

def main():
    success = test_all_combinations()
    
    if success:
        print(f"\n🏆🏆🏆 GSMG.IO PUZZLE COMPLETELY SOLVED! 🏆🏆🏆")
        print(f"🎊 HALF AND BETTER HALF METHOD SUCCESSFUL!")
    else:
        print(f"\n🔄 Analysis complete - no matching combination found")

if __name__ == "__main__":
    main()
