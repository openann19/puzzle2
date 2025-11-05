#!/usr/bin/env python3
"""
Solve the Cosmic Duality blob from SalPhaseIon.md
Target: 1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe
"""

import base64
import hashlib
import subprocess
import sys
from pathlib import Path
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA256, SHA1, MD5
from ecdsa import SigningKey, SECP256k1

TARGET_ADDRESS = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"

# Read the Cosmic Duality blob from SalPhaseIon.md
def extract_cosmic_blob():
    """Extract the Cosmic Duality base64 blob from SalPhaseIon.md"""
    with open('SalPhaseIon.md', 'r') as f:
        content = f.read()
    
    # Find the Cosmic Duality section
    lines = content.split('\n')
    cosmic_start = False
    blob_lines = []
    
    for line in lines:
        if 'Cosmic Duality' in line:
            cosmic_start = True
            continue
        if cosmic_start:
            # Check if line looks like base64
            stripped = line.strip()
            if stripped and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in stripped):
                blob_lines.append(stripped)
            elif blob_lines:  # Stop when we hit a non-base64 line after collecting some
                break
    
    blob = ''.join(blob_lines)
    return blob

def sha256_hash(text):
    """SHA-256 hash of text"""
    return hashlib.sha256(text.encode()).hexdigest()

def md5_hash(text):
    """MD5 hash of text"""
    return hashlib.md5(text.encode()).hexdigest()

def try_openssl_decrypt(blob_b64, password, method='aes-256-cbc', md='sha256', pbkdf2=False, iterations=10000):
    """Try to decrypt using openssl command"""
    import tempfile
    import os
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.b64', delete=False) as f:
        f.write(blob_b64)
        blob_file = f.name
    
    try:
        cmd = ['openssl', 'enc', f'-{method}', '-d', '-a', '-in', blob_file, '-pass', f'pass:{password}']
        if pbkdf2:
            cmd.extend(['-pbkdf2', '-iter', str(iterations)])
        if md:
            cmd.extend(['-md', md])
        
        result = subprocess.run(cmd, capture_output=True)
        os.unlink(blob_file)
        
        if result.returncode == 0 and result.stdout:
            return result.stdout
        return None
    except Exception as e:
        try:
            os.unlink(blob_file)
        except:
            pass
        return None

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
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
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

def extract_private_keys_from_data(data):
    """Try to extract potential private keys from decrypted data"""
    import re
    
    keys = []
    
    # Try to find hex strings that could be private keys (64 hex chars)
    hex_pattern = re.compile(r'[0-9a-fA-F]{64}')
    for match in hex_pattern.finditer(data.decode('latin-1', errors='ignore')):
        keys.append(match.group())
    
    # Also try raw bytes
    if len(data) >= 32:
        for i in range(len(data) - 31):
            key_candidate = data[i:i+32].hex()
            keys.append(key_candidate)
    
    return keys

def main():
    print("=" * 80)
    print("COSMIC DUALITY SOLVER")
    print(f"Target Address: {TARGET_ADDRESS}")
    print("=" * 80)
    
    # Extract the blob
    print("\n[1] Extracting Cosmic Duality blob from SalPhaseIon.md...")
    blob = extract_cosmic_blob()
    print(f"    Blob size: {len(blob)} characters")
    
    # Load comprehensive password list
    password_candidates = []
    try:
        with open('comprehensive_all_passwords.txt', 'r') as f:
            password_candidates = [line.strip() for line in f if line.strip()]
    except:
        pass
    
    # Also add SHA256 hashes of the passwords
    base_passwords = password_candidates.copy()
    for pw in base_passwords[:50]:  # Hash first 50 to avoid too many
        password_candidates.append(sha256_hash(pw))
    
    # Add some specific important ones
    extra_passwords = [
        "HASHTHETEXT",
        "enter",
        sha256_hash("enter"),
        # SHA256^4 hints
        sha256_hash(sha256_hash(sha256_hash(sha256_hash("CosmicDuality")))),
        sha256_hash(sha256_hash(sha256_hash(sha256_hash("matrixsumlist")))),
    ]
    password_candidates.extend(extra_passwords)
    
    print(f"\n[2] Testing {len(password_candidates)} password candidates...")
    
    methods = [
        ('aes-256-cbc', 'md5', False, 0),
        ('aes-256-cbc', 'sha256', False, 0),
        ('aes-256-cbc', 'sha256', True, 1000),
        ('aes-256-cbc', 'sha256', True, 10000),
    ]
    
    total_attempts = 0
    for pw in password_candidates:
        for method, md, pbkdf2, iterations in methods:
            total_attempts += 1
            result = try_openssl_decrypt(blob, pw, method, md, pbkdf2, iterations)
            
            if result:
                print(f"\n{'='*80}")
                print(f"✓ DECRYPTION SUCCESS!")
                print(f"{'='*80}")
                print(f"Password: {pw[:50]}...")
                print(f"Method: {method}, MD: {md}, PBKDF2: {pbkdf2}, Iterations: {iterations}")
                print(f"Decrypted size: {len(result)} bytes")
                
                # Try to extract private keys
                keys = extract_private_keys_from_data(result)
                print(f"\nFound {len(keys)} potential private keys")
                
                # Test each key
                for key in keys:
                    try:
                        address = p2pkh_from_privkey(key)
                        if address:
                            print(f"  Key: {key}")
                            print(f"  Address: {address}")
                            if address == TARGET_ADDRESS:
                                print(f"\n{'='*80}")
                                print(f"🎉 TARGET ADDRESS MATCH! 🎉")
                                print(f"{'='*80}")
                                print(f"Private Key: {key}")
                                print(f"Address: {address}")
                                
                                # Save to file
                                with open('SOLUTION_FOUND.txt', 'w') as f:
                                    f.write(f"COSMIC DUALITY SOLUTION\n")
                                    f.write(f"{'='*80}\n")
                                    f.write(f"Target Address: {TARGET_ADDRESS}\n")
                                    f.write(f"Private Key: {key}\n")
                                    f.write(f"Password: {pw}\n")
                                    f.write(f"Method: {method}, MD: {md}, PBKDF2: {pbkdf2}, Iterations: {iterations}\n")
                                
                                return 0
                    except:
                        pass
                
                # Show first 200 bytes of decrypted data
                print(f"\nFirst 200 bytes (hex): {result[:200].hex()}")
                print(f"First 200 bytes (ascii): {result[:200].decode('latin-1', errors='replace')}")
            
            if total_attempts % 10 == 0:
                print(f"  Tested {total_attempts}/{len(password_candidates) * len(methods)} combinations...", end='\r')
    
    print(f"\n\n[3] Tested {total_attempts} combinations - no success yet")
    print("\nThe password may need to be derived differently or use a combination not yet tested.")
    return 1

if __name__ == '__main__':
    sys.exit(main())
