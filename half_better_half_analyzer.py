#!/usr/bin/env python3
"""
Analyze 'half and better half' clue - test key arithmetic operations
The VIC cipher result suggests the private keys need mathematical combination
"""
import json
import hashlib
import ecdsa
import base58

def privkey_to_address(private_key_hex, compressed=True):
    """Convert private key hex to Bitcoin address"""
    try:
        private_key_int = int(private_key_hex, 16)
        
        sk = ecdsa.SigningKey.from_string(private_key_int.to_bytes(32, 'big'), curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        
        if compressed:
            if vk.pubkey.point.y() % 2 == 0:
                public_key = b'\x02' + vk.pubkey.point.x().to_bytes(32, 'big')
            else:
                public_key = b'\x03' + vk.pubkey.point.x().to_bytes(32, 'big')
        else:
            public_key = b'\x04' + vk.to_string()
        
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        
        versioned_hash = b'\x00' + ripemd160_hash
        checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
        
        address_bytes = versioned_hash + checksum
        address = base58.b58encode(address_bytes).decode('ascii')
        
        return address
    except Exception:
        return None

def test_key_combinations():
    """Test various mathematical combinations of extracted keys"""
    target_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    
    with open('all_verified_keys.json', 'r') as f:
        keys_data = json.load(f)
    
    keys = [int(k['private_key_hex'], 16) for k in keys_data]
    
    print(f"🔑 TESTING KEY COMBINATIONS")
    print(f"Target: {target_address}")
    print(f"Keys available: {len(keys)}")
    print("=" * 60)
    
    # SECP256k1 curve order
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    operations_tested = 0
    max_operations = 10000  # Limit to prevent infinite loops
    
    # Test 1: Half operations (divide by 2)
    print("🧮 Testing HALF operations...")
    for i, key in enumerate(keys[:10]):  # Test first 10 keys
        if operations_tested >= max_operations:
            break
            
        # Half of key
        half_key = (key // 2) % n
        operations_tested += 1
        
        for compressed in [True, False]:
            addr = privkey_to_address(f"{half_key:064x}", compressed)
            if addr == target_address:
                print(f"🎉 FOUND! Half of key {i}: {half_key:064x}")
                return half_key
    
    # Test 2: Better half operations (add half to original)
    print("🧮 Testing BETTER HALF operations...")
    for i, key in enumerate(keys[:10]):
        if operations_tested >= max_operations:
            break
            
        # Better half = key + half
        half_key = key // 2
        better_half = (key + half_key) % n
        operations_tested += 1
        
        for compressed in [True, False]:
            addr = privkey_to_address(f"{better_half:064x}", compressed)
            if addr == target_address:
                print(f"🎉 FOUND! Better half of key {i}: {better_half:064x}")
                return better_half
    
    # Test 3: Pairwise combinations
    print("🧮 Testing PAIRWISE combinations...")
    for i in range(min(5, len(keys))):
        for j in range(i+1, min(5, len(keys))):
            if operations_tested >= max_operations:
                break
                
            key1, key2 = keys[i], keys[j]
            
            # Sum
            sum_key = (key1 + key2) % n
            operations_tested += 1
            
            for compressed in [True, False]:
                addr = privkey_to_address(f"{sum_key:064x}", compressed)
                if addr == target_address:
                    print(f"🎉 FOUND! Sum of keys {i}+{j}: {sum_key:064x}")
                    return sum_key
            
            # XOR
            xor_key = key1 ^ key2
            if xor_key != 0:
                operations_tested += 1
                for compressed in [True, False]:
                    addr = privkey_to_address(f"{xor_key:064x}", compressed)
                    if addr == target_address:
                        print(f"🎉 FOUND! XOR of keys {i}^{j}: {xor_key:064x}")
                        return xor_key
            
            # Difference
            diff_key = abs(key1 - key2) % n
            operations_tested += 1
            
            for compressed in [True, False]:
                addr = privkey_to_address(f"{diff_key:064x}", compressed)
                if addr == target_address:
                    print(f"🎉 FOUND! Diff of keys {i}-{j}: {diff_key:064x}")
                    return diff_key
    
    # Test 4: Sequential byte operations
    print("🧮 Testing SEQUENTIAL operations...")
    for i in range(min(3, len(keys)-1)):
        if operations_tested >= max_operations:
            break
            
        # Take first half of key[i] + second half of key[i+1]
        key1_bytes = keys[i].to_bytes(32, 'big')
        key2_bytes = keys[i+1].to_bytes(32, 'big')
        
        hybrid_key_bytes = key1_bytes[:16] + key2_bytes[16:]
        hybrid_key = int.from_bytes(hybrid_key_bytes, 'big') % n
        operations_tested += 1
        
        for compressed in [True, False]:
            addr = privkey_to_address(f"{hybrid_key:064x}", compressed)
            if addr == target_address:
                print(f"🎉 FOUND! Hybrid key {i}/{i+1}: {hybrid_key:064x}")
                return hybrid_key
    
    print(f"❌ No matches found in {operations_tested} operations")
    return None

def analyze_key_patterns():
    """Analyze patterns in the extracted keys"""
    with open('all_verified_keys.json', 'r') as f:
        keys_data = json.load(f)
    
    print("\n📊 KEY PATTERN ANALYSIS")
    print("=" * 40)
    
    keys = [int(k['private_key_hex'], 16) for k in keys_data]
    
    # Check if keys are sequential or have mathematical relationships
    print(f"Key count: {len(keys)}")
    print(f"Min key: {min(keys):064x}")
    print(f"Max key: {max(keys):064x}")
    
    # Check for arithmetic progression
    if len(keys) >= 2:
        diffs = [keys[i+1] - keys[i] for i in range(len(keys)-1)]
        print(f"First few differences: {[hex(d) for d in diffs[:5]]}")
        
        # Check if all differences are the same (arithmetic sequence)
        if len(set(diffs)) == 1:
            print(f"🎯 Keys form arithmetic sequence with diff: {hex(diffs[0])}")
        
    # Check offsets pattern
    offsets = [k['offset'] for k in keys_data]
    print(f"Offsets: {sorted(set(offsets))}")
    
    # Look for byte-level patterns
    key_bytes = [k.to_bytes(32, 'big') for k in keys]
    
    # Check if first/last 16 bytes have patterns
    first_halves = [kb[:16] for kb in key_bytes]
    second_halves = [kb[16:] for kb in key_bytes]
    
    print(f"Unique first halves: {len(set(first_halves))}")
    print(f"Unique second halves: {len(set(second_halves))}")
    
    if len(set(first_halves)) == 1:
        print("🎯 All keys share same first 16 bytes!")
    if len(set(second_halves)) == 1:
        print("🎯 All keys share same last 16 bytes!")

def main():
    analyze_key_patterns()
    winning_key = test_key_combinations()
    
    if winning_key:
        print(f"\n🏆 WINNING PRIVATE KEY: {winning_key:064x}")
        
        # Verify it generates target address
        for compressed in [True, False]:
            addr = privkey_to_address(f"{winning_key:064x}", compressed)
            print(f"Address ({'compressed' if compressed else 'uncompressed'}): {addr}")
        
        # Save the winning key
        result = {
            'private_key_hex': f"{winning_key:064x}",
            'target_address': "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
            'method': 'half_and_better_half_analysis'
        }
        
        with open('WINNING_KEY.json', 'w') as f:
            json.dump(result, f, indent=2)
        
        print("💾 Saved winning key to WINNING_KEY.json")
    else:
        print("\n💡 No direct key combinations worked")
        print("   May need to analyze the 770-byte raw data differently")
        print("   Or the target key might be in the undecrypted Cosmic Duality blob")

if __name__ == '__main__':
    main()
