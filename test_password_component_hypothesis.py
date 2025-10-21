#!/usr/bin/env python3
"""
Test Password Component Hypothesis for HALF and BETTER HALF
HALF = "matrixsumlist"
BETTER HALF = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
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

def test_password_components_as_half_better_half():
    """Test the hypothesis that password components are HALF and BETTER HALF"""
    
    print("🧩 TESTING PASSWORD COMPONENT HYPOTHESIS")
    print("="*60)
    
    # Our successful password components
    half = "matrixsumlist"
    better_half = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
    prize_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    
    print(f"🔑 HALF: '{half}'")
    print(f"🔑 BETTER HALF: '{better_half[:32]}...' (SalPhaseIon hash)")
    print(f"🎯 Target: {prize_address}")
    print()
    
    # Test various ways to derive private key from these components
    methods_to_test = [
        # Direct hashing approaches
        ("SHA256(half)", hashlib.sha256(half.encode()).hexdigest()),
        ("SHA256(better_half)", hashlib.sha256(better_half.encode()).hexdigest()),
        ("SHA256(half + better_half)", hashlib.sha256((half + better_half).encode()).hexdigest()),
        ("SHA256(better_half + half)", hashlib.sha256((better_half + half).encode()).hexdigest()),
        
        # The better_half is already a hash, try using it directly
        ("better_half_as_key", better_half),
        
        # Combined approaches
        ("MD5(half) + MD5(better_half)", 
         hashlib.md5(half.encode()).hexdigest() + hashlib.md5(better_half.encode()).hexdigest()[:32]),
         
        # XOR approaches (convert to bytes first)
        ("SHA256_XOR", get_xor_combination(half, better_half)),
        
        # Double hashing
        ("SHA256(SHA256(half + better_half))", 
         hashlib.sha256(hashlib.sha256((half + better_half).encode()).digest()).hexdigest()),
         
        ("SHA256(SHA256(better_half + half))", 
         hashlib.sha256(hashlib.sha256((better_half + half).encode()).digest()).hexdigest()),
         
        # Use the literal combined password that worked for decryption
        ("SHA256(combined_password)", 
         hashlib.sha256((half + better_half).encode()).hexdigest()),
         
        # Special combinations based on puzzle patterns
        ("half_reversed + better_half", 
         hashlib.sha256((half[::-1] + better_half).encode()).hexdigest()),
         
        ("better_half + half_reversed", 
         hashlib.sha256((better_half + half[::-1]).encode()).hexdigest()),
         
        # Try with separators that might have been used
        ("SHA256(half + ':' + better_half)", 
         hashlib.sha256((half + ":" + better_half).encode()).hexdigest()),
         
        ("SHA256(half + '_' + better_half)", 
         hashlib.sha256((half + "_" + better_half).encode()).hexdigest()),
         
        # Truncated versions
        ("first_32_of_better_half", better_half[:32] + "0" * 32),
        ("last_32_of_better_half", "0" * 32 + better_half[-32:]),
    ]
    
    print(f"🔄 Testing {len(methods_to_test)} different combination methods...")
    print()
    
    for method_name, private_key_hex in methods_to_test:
        # Ensure key is valid length
        if len(private_key_hex) != 64:
            print(f"❌ {method_name}: Invalid key length {len(private_key_hex)}")
            continue
            
        try:
            # Test if this generates the prize address
            if test_private_key_for_prize(private_key_hex, method_name, prize_address):
                return True
                
        except Exception as e:
            print(f"❌ {method_name}: Error - {e}")
    
    print("\n❌ No direct combination of password components worked")
    return False

def get_xor_combination(half, better_half):
    """Create XOR combination of the two components"""
    try:
        # Hash both to get consistent 32-byte keys
        half_hash = hashlib.sha256(half.encode()).digest()
        better_hash = bytes.fromhex(better_half)  # better_half is already a hex hash
        
        # XOR them (pad if necessary)
        if len(half_hash) != len(better_hash):
            min_len = min(len(half_hash), len(better_hash))
            half_hash = half_hash[:min_len]
            better_hash = better_hash[:min_len]
            
        xor_result = bytes(a ^ b for a, b in zip(half_hash, better_hash))
        return xor_result.hex()
    except Exception as e:
        print(f"XOR error: {e}")
        return "0" * 64  # Return invalid key if XOR fails

def test_private_key_for_prize(private_key_hex, method_name, prize_address):
    """Test if a private key generates the prize address"""
    
    try:
        # Validate the private key
        if not is_valid_private_key(private_key_hex):
            print(f"❌ {method_name}: Invalid private key")
            return False
            
        # Generate address
        generated_address = bitcoin.privkey_to_address(private_key_hex)
        
        if generated_address == prize_address:
            print(f"\n🎉🎉🎉 PRIZE PRIVATE KEY FOUND! 🎉🎉🎉")
            print(f"🔑 Method: {method_name}")
            print(f"🔑 Private Key: {private_key_hex}")
            print(f"🏠 Address: {generated_address}")
            
            # Verify with public key
            pubkey = bitcoin.privkey_to_pubkey(private_key_hex)
            print(f"🔑 Public Key: {pubkey}")
            
            # Save the solution
            import json
            solution = {
                'PUZZLE_STATUS': 'COMPLETELY SOLVED!',
                'PRIZE_ADDRESS': prize_address,
                'PRIVATE_KEY': private_key_hex,
                'PUBLIC_KEY': pubkey,
                'METHOD': method_name,
                'HALF': 'matrixsumlist',
                'BETTER_HALF': '89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32',
                'SUCCESS': True
            }
            
            with open('PASSWORD_COMPONENT_SOLUTION.json', 'w') as f:
                json.dump(solution, f, indent=2)
            
            print(f"💾 Solution saved: PASSWORD_COMPONENT_SOLUTION.json")
            return True
        else:
            print(f"❌ {method_name}: {generated_address}")
            return False
            
    except Exception as e:
        print(f"❌ {method_name}: Error generating address - {e}")
        return False

def is_valid_private_key(key_hex):
    """Check if private key is in valid secp256k1 range"""
    try:
        key_int = int(key_hex, 16)
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        return 1 <= key_int < secp256k1_order
    except:
        return False

def main():
    """Main execution"""
    
    success = test_password_components_as_half_better_half()
    
    if success:
        print(f"\n🏆🏆🏆 GSMG.IO PUZZLE SOLVED WITH PASSWORD COMPONENTS! 🏆🏆🏆")
        print(f"🎊 The 'half and better half' referred to the password parts!")
    else:
        print(f"\n🔄 Password component hypothesis tested - continue investigation")

if __name__ == "__main__":
    main()
