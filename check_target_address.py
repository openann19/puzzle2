#!/usr/bin/env python3
"""
Check if any extracted private keys generate the target address 1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe
"""
import json
import hashlib
import ecdsa
import base58

def privkey_to_address(private_key_hex, compressed=True):
    """Convert private key hex to Bitcoin address"""
    try:
        # Convert hex to int
        private_key_int = int(private_key_hex, 16)
        
        # Generate public key
        sk = ecdsa.SigningKey.from_string(private_key_int.to_bytes(32, 'big'), curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        
        if compressed:
            if vk.pubkey.point.y() % 2 == 0:
                public_key = b'\x02' + vk.pubkey.point.x().to_bytes(32, 'big')
            else:
                public_key = b'\x03' + vk.pubkey.point.x().to_bytes(32, 'big')
        else:
            public_key = b'\x04' + vk.to_string()
        
        # Hash public key (SHA256 then RIPEMD160)
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        
        # Add version byte (0x00 for mainnet)
        versioned_hash = b'\x00' + ripemd160_hash
        
        # Double SHA256 for checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
        
        # Final address
        address_bytes = versioned_hash + checksum
        address = base58.b58encode(address_bytes).decode('ascii')
        
        return address
    except Exception as e:
        return None

def main():
    target_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    
    # Load extracted keys
    with open('all_verified_keys.json', 'r') as f:
        keys = json.load(f)
    
    print(f"🎯 TARGET: {target_address}")
    print(f"📊 CHECKING {len(keys)} EXTRACTED KEYS...")
    print("-" * 60)
    
    matches = []
    
    for i, key_data in enumerate(keys):
        private_key_hex = key_data['private_key_hex']
        
        # Check both compressed and uncompressed
        for compressed in [True, False]:
            addr = privkey_to_address(private_key_hex, compressed)
            if addr == target_address:
                matches.append({
                    'key_index': i,
                    'private_key': private_key_hex,
                    'compressed': compressed,
                    'address': addr
                })
                print(f"🎉 MATCH FOUND!")
                print(f"   Private Key: {private_key_hex}")
                print(f"   Compressed: {compressed}")
                print(f"   Address: {addr}")
    
    if not matches:
        print("❌ NO MATCHES FOUND in extracted keys")
        print("🔄 Need to decrypt Cosmic Duality blob for final solution")
    else:
        print(f"\n✅ FOUND {len(matches)} MATCHING KEY(S)!")
        with open('winning_keys.json', 'w') as f:
            json.dump(matches, f, indent=2)
        print("💾 Saved to winning_keys.json")
    
    return len(matches) > 0

if __name__ == '__main__':
    found_target = main()
    exit(0 if found_target else 1)
