#!/usr/bin/env python3
"""
DECODE HALF AND BETTER HALF KEYS - Based on GitHub documentation clue
"THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF AND THEY ALSO NEED FUNDS TO LIVE"
"""

import sys
import hashlib

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

def derive_specific_keys_from_puzzle_elements():
    """
    Derive the specific HALF and BETTER HALF keys based on puzzle elements
    From GitHub docs, we know about specific passwords: matrixsumlist, enter, etc.
    """
    
    print("🔍 DERIVING SPECIFIC HALF AND BETTER HALF KEYS")
    print("="*60)
    
    # Known puzzle elements from our successful decryption
    puzzle_elements = {
        'matrixsumlist': 'matrixsumlist',
        'enter': 'enter', 
        'lastwordsbeforearchichoice': 'lastwordsbeforearchichoice',
        'thispassword': 'thispassword',
        'salphaseion_hash': '89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32'
    }
    
    # Test various interpretations of "HALF" and "BETTER HALF"
    half_candidates = []
    better_half_candidates = []
    
    # Method 1: Direct SHA256 of "half" and "better half"
    half_key1 = hashlib.sha256("half".encode()).hexdigest()
    better_half_key1 = hashlib.sha256("better half".encode()).hexdigest()
    half_candidates.append(("sha256_half", half_key1))
    better_half_candidates.append(("sha256_better_half", better_half_key1))
    
    # Method 2: SHA256 of "HALF" and "BETTER HALF" (uppercase)
    half_key2 = hashlib.sha256("HALF".encode()).hexdigest()
    better_half_key2 = hashlib.sha256("BETTER HALF".encode()).hexdigest()
    half_candidates.append(("sha256_HALF", half_key2))
    better_half_candidates.append(("sha256_BETTER_HALF", better_half_key2))
    
    # Method 3: Combine with puzzle elements
    for element_name, element_value in puzzle_elements.items():
        # half + element
        half_combo = hashlib.sha256(("half" + element_value).encode()).hexdigest()
        half_candidates.append((f"half_{element_name}", half_combo))
        
        # better half + element  
        better_combo = hashlib.sha256(("better half" + element_value).encode()).hexdigest()
        better_half_candidates.append((f"better_half_{element_name}", better_combo))
        
        # element + half
        half_combo2 = hashlib.sha256((element_value + "half").encode()).hexdigest()
        half_candidates.append((f"{element_name}_half", half_combo2))
        
        # element + better half
        better_combo2 = hashlib.sha256((element_value + "better half").encode()).hexdigest()
        better_half_candidates.append((f"{element_name}_better_half", better_combo2))
    
    # Method 4: Use the specific password patterns from puzzle
    # If "matrixsumlist" was the key to decrypt, maybe "matrix" = half, "sumlist" = better half
    half_key4 = hashlib.sha256("matrix".encode()).hexdigest()
    better_half_key4 = hashlib.sha256("sumlist".encode()).hexdigest()  
    half_candidates.append(("matrix", half_key4))
    better_half_candidates.append(("sumlist", better_half_key4))
    
    # Method 5: Try the last successful passwords we found
    successful_passwords = [
        "matrixsumlist89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32",
        "theflowerblossomsthroughwhatseemstobeaconcretesurface"
    ]
    
    for pwd in successful_passwords:
        # First half / second half of the password
        mid = len(pwd) // 2
        first_half = pwd[:mid]
        second_half = pwd[mid:]
        
        half_key5 = hashlib.sha256(first_half.encode()).hexdigest()
        better_half_key5 = hashlib.sha256(second_half.encode()).hexdigest()
        half_candidates.append((f"first_half_{pwd[:20]}...", half_key5))
        better_half_candidates.append((f"second_half_{pwd[:20]}...", better_half_key5))
    
    print(f"📊 Generated {len(half_candidates)} HALF candidates")
    print(f"📊 Generated {len(better_half_candidates)} BETTER HALF candidates")
    
    return half_candidates, better_half_candidates

def test_key_for_prize(private_key_hex, key_name):
    """Test if a private key generates the prize address"""
    prize_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    
    try:
        if not is_valid_private_key(private_key_hex):
            return False
            
        generated_address = bitcoin.privkey_to_address(private_key_hex)
        if generated_address == prize_address:
            print(f"\n🎉🎉🎉 INDIVIDUAL PRIZE KEY FOUND! 🎉🎉🎉")
            print(f"🔑 Key Name: {key_name}")
            print(f"🔑 Private Key: {private_key_hex}")
            print(f"🏠 Address: {prize_address}")
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

def combine_half_and_better_half(half_candidates, better_half_candidates):
    """Try combinations of HALF and BETTER HALF keys for the prize"""
    
    print(f"\n🔗 TESTING HALF + BETTER HALF COMBINATIONS")
    print("="*60)
    
    test_count = 0
    max_tests = 100  # Limit to avoid excessive runtime
    
    for half_name, half_key in half_candidates[:10]:  # Test first 10 of each
        for better_name, better_key in better_half_candidates[:10]:
            if test_count >= max_tests:
                break
                
            test_count += 1
            
            # Method 1: XOR the keys  
            try:
                half_bytes = bytes.fromhex(half_key)
                better_bytes = bytes.fromhex(better_key)
                xor_result = bytes(a ^ b for a, b in zip(half_bytes, better_bytes))
                xor_hex = xor_result.hex()
                
                if test_key_for_prize(xor_hex, f"XOR({half_name}_{better_name})"):
                    return True
                    
            except Exception:
                pass
            
            # Method 2: SHA256(half + better)
            try:
                combined_hash = hashlib.sha256((half_key + better_key).encode()).hexdigest()
                if test_key_for_prize(combined_hash, f"SHA256({half_name}_{better_name})"):
                    return True
            except Exception:
                pass
            
            # Method 3: SHA256(better + half) - reverse order
            try:
                reverse_hash = hashlib.sha256((better_key + half_key).encode()).hexdigest()
                if test_key_for_prize(reverse_hash, f"SHA256_REV({half_name}_{better_name})"):
                    return True
            except Exception:
                pass
            
            if test_count % 10 == 0:
                print(f"  Tested {test_count} combinations...")
    
    print(f"\n❌ No successful combination found after {test_count} tests")
    return False

def main():
    """Main execution"""
    
    # Generate HALF and BETTER HALF key candidates
    half_candidates, better_half_candidates = derive_specific_keys_from_puzzle_elements()
    
    # Test individual keys first
    print(f"\n🔍 TESTING INDIVIDUAL KEYS FOR PRIZE ADDRESS...")
    
    success = False
    for name, key in half_candidates:
        if test_key_for_prize(key, f"HALF_{name}"):
            success = True
            break
            
    if not success:
        for name, key in better_half_candidates:
            if test_key_for_prize(key, f"BETTER_HALF_{name}"):
                success = True
                break
    
    # If no individual success, try combinations
    if not success:
        success = combine_half_and_better_half(half_candidates, better_half_candidates)
    
    if success:
        print(f"\n🏆🏆🏆 HALF AND BETTER HALF PUZZLE SOLVED! 🏆🏆🏆")
    else:
        print(f"\n🔄 Analysis complete - continue investigating the 'half and better half' clue")

if __name__ == "__main__":
    main()
