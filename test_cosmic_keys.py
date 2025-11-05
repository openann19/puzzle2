#!/usr/bin/env python3
"""
Test all potential private keys from cosmic_decrypted.bin
"""

import hashlib
from ecdsa import SigningKey, SECP256k1

TARGET = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"

def p2pkh_from_privkey(privkey_hex):
    """Convert private key to P2PKH address"""
    try:
        privkey = bytes.fromhex(privkey_hex)
        if len(privkey) != 32:
            return None
        
        sk = SigningKey.from_string(privkey, curve=SECP256k1)
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

def main():
    data = open('cosmic_decrypted.bin', 'rb').read()
    hex_data = data.hex()
    
    print(f"Decrypted data length: {len(data)} bytes")
    print(f"Testing all 32-byte windows for private keys...")
    print(f"Target address: {TARGET}\n")
    
    tested = 0
    found = []
    
    # Test every possible 32-byte window
    for i in range(len(data) - 31):
        potential_key = data[i:i+32].hex()
        tested += 1
        
        try:
            address = p2pkh_from_privkey(potential_key)
            if address:
                if address == TARGET:
                    print(f"\n{'='*80}")
                    print(f"🎉 FOUND TARGET ADDRESS! 🎉")
                    print(f"{'='*80}")
                    print(f"Private Key: {potential_key}")
                    print(f"Address: {address}")
                    print(f"Position in file: {i}")
                    print(f"{'='*80}\n")
                    
                    # Save solution
                    with open('SOLUTION_FOUND.txt', 'w') as f:
                        f.write(f"COSMIC DUALITY SOLUTION\n")
                        f.write(f"{'='*80}\n")
                        f.write(f"Target Address: {TARGET}\n")
                        f.write(f"Private Key: {potential_key}\n")
                        f.write(f"Position in decrypted data: {i}\n")
                    
                    return 0
                else:
                    found.append((potential_key[:16] + "...", address))
        except:
            pass
        
        if tested % 100 == 0:
            print(f"Tested {tested} positions...", end='\r')
    
    print(f"\nTested {tested} positions")
    print(f"Found {len(found)} valid keys (but not target)")
    
    if found:
        print("\nSample of valid keys found:")
        for key, addr in found[:10]:
            print(f"  {key} -> {addr}")
    
    print(f"\nTarget address {TARGET} not found in cosmic_decrypted.bin")
    return 1

if __name__ == '__main__':
    import sys
    sys.exit(main())
