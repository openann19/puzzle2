#!/usr/bin/env python3
"""
Analyze the Prize Address - Check if it's multi-signature or has special properties
1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe
"""

import sys
import base58
import hashlib

sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    import bitcoin
    CRYPTO_AVAILABLE = True
except ImportError as e:
    print(f"❌ Crypto not available: {e}")
    sys.exit(1)

def analyze_bitcoin_address(address):
    """Analyze the Bitcoin address for its type and properties"""
    
    print(f"🔍 ANALYZING PRIZE ADDRESS: {address}")
    print("="*70)
    
    try:
        # Decode the address
        decoded = base58.b58decode_check(address)
        
        # Get version byte and hash
        version = decoded[0]
        hash160 = decoded[1:]
        
        print(f"📊 Address Analysis:")
        print(f"   Version byte: 0x{version:02x}")
        print(f"   Hash160: {hash160.hex()}")
        print(f"   Hash160 length: {len(hash160)} bytes")
        
        # Determine address type
        address_types = {
            0x00: "P2PKH (Pay-to-Public-Key-Hash) - Standard address",
            0x05: "P2SH (Pay-to-Script-Hash) - Multi-sig or other scripts",
            0x6f: "Testnet P2PKH",
            0xc4: "Testnet P2SH"
        }
        
        address_type = address_types.get(version, f"Unknown address type (version 0x{version:02x})")
        print(f"   Address Type: {address_type}")
        
        # Check if it's multi-signature
        if version == 0x05:
            print(f"🔗 This is a P2SH address - likely MULTI-SIGNATURE!")
            print(f"   This could require multiple private keys to spend")
            return True
        elif version == 0x00:
            print(f"🔑 This is a standard P2PKH address")
            print(f"   Requires only one private key to spend")
            return False
        
        # Analyze the hash for patterns
        hash_hex = hash160.hex()
        print(f"\n📈 Hash160 Pattern Analysis:")
        print(f"   First 8 chars: {hash_hex[:8]}")
        print(f"   Last 8 chars: {hash_hex[-8:]}")
        
        # Look for repeating patterns
        patterns_found = []
        for i in range(2, 8):  # Look for patterns of length 2-7
            for j in range(len(hash_hex) - i):
                pattern = hash_hex[j:j+i]
                if hash_hex.count(pattern) > 1:
                    patterns_found.append((pattern, hash_hex.count(pattern)))
        
        if patterns_found:
            print(f"   Repeating patterns found:")
            for pattern, count in set(patterns_found):
                print(f"     '{pattern}' appears {count} times")
        
        return version == 0x05
        
    except Exception as e:
        print(f"❌ Error analyzing address: {e}")
        return False

def test_multisig_hypothesis():
    """Test if our 956 keys can generate the address through multisig"""
    
    print(f"\n🔍 TESTING MULTISIG HYPOTHESIS")
    print("="*50)
    
    # Load our 956 keys
    try:
        with open('cosmic_decrypted_raw.bin', 'rb') as f:
            data = f.read()
        
        # Extract first few potential keys to test
        test_keys = []
        for i in range(0, min(len(data)-31, 20), 32):  # First 20 keys
            key_hex = data[i:i+32].hex()
            if is_valid_private_key(key_hex):
                test_keys.append(key_hex)
        
        print(f"📊 Testing with first {len(test_keys)} valid keys from data")
        
        # Test 2-of-2, 2-of-3, 3-of-3 multisig combinations
        for m in [2]:  # Required signatures
            for n in [2, 3]:  # Total keys
                if n <= len(test_keys) and m <= n:
                    print(f"\n🔗 Testing {m}-of-{n} multisig...")
                    
                    # Take first n keys
                    keys_subset = test_keys[:n]
                    
                    try:
                        # Generate public keys
                        pubkeys = []
                        for key in keys_subset:
                            pubkey = bitcoin.privkey_to_pubkey(key)
                            pubkeys.append(pubkey)
                        
                        # Create multisig script (simplified version)
                        # This is a basic test - real multisig is more complex
                        script_parts = [f"OP_{m}"] + pubkeys + [f"OP_{n}", "OP_CHECKMULTISIG"]
                        
                        print(f"   Keys: {[k[:16]+'...' for k in keys_subset]}")
                        print(f"   PubKeys: {[p[:16]+'...' for p in pubkeys]}")
                        
                        # For a real implementation, we'd need to:
                        # 1. Create the proper script
                        # 2. Hash it to get the script hash
                        # 3. Create the P2SH address
                        # But this is beyond basic testing
                        
                    except Exception as e:
                        print(f"   ❌ Error testing {m}-of-{n}: {e}")
        
        print(f"\n💡 NOTE: Full multisig testing requires more complex script generation")
        print(f"   If the address is P2SH, we'd need the exact script used to create it")
        
    except Exception as e:
        print(f"❌ Error in multisig testing: {e}")

def is_valid_private_key(key_hex):
    """Check if private key is in valid secp256k1 range"""
    try:
        key_int = int(key_hex, 16)
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        return 1 <= key_int < secp256k1_order
    except:
        return False

def check_vanity_address_patterns():
    """Check if the address has vanity patterns that give us clues"""
    
    prize_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    
    print(f"\n🎯 VANITY ADDRESS PATTERN ANALYSIS")
    print("="*50)
    print(f"Address: {prize_address}")
    print(f"Pattern analysis:")
    print(f"  Starts with: '1GSMG' - Clearly references GSMG.IO")
    print(f"  After GSMG: '1JC9wtdSwfwApgj2xcmJPAwx7prBe'")
    
    # This suggests the address was intentionally generated with "1GSMG" prefix
    # Vanity address generation requires brute force searching
    print(f"\n💡 This is clearly a VANITY ADDRESS with '1GSMG' prefix")
    print(f"   The creators generated this specific address for the puzzle")
    print(f"   The private key is likely NOT derivable from standard methods")
    print(f"   It may require the specific puzzle solution to reveal")

def main():
    """Main analysis"""
    
    prize_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    
    # Analyze the address type
    is_multisig = analyze_bitcoin_address(prize_address)
    
    # Check vanity patterns
    check_vanity_address_patterns()
    
    # Test multisig hypothesis if applicable
    if is_multisig:
        test_multisig_hypothesis()
    else:
        print(f"\n📝 Since this is a standard P2PKH address:")
        print(f"   It requires only ONE private key")
        print(f"   The 'half and better half' clue must refer to:")
        print(f"   - How to derive/find this single private key")
        print(f"   - OR how to combine data to generate the key")
        
    print(f"\n💭 CONCLUSION:")
    print(f"   The puzzle solution likely involves finding the specific method")
    print(f"   to derive the private key for this vanity address")
    print(f"   'Half and better half' may be a clue about data splitting/combining")

if __name__ == "__main__":
    main()
