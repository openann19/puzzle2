#!/usr/bin/env python3
"""
Solution script for the Bitcoin puzzle - Find the Key
Attempts to decrypt the Cosmic Duality blob with various password candidates
"""

import base64
import hashlib
import re
from Cryptodome.Cipher import AES
from Cryptodome.Hash import MD5

TARGET_ADDRESS = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"

def sha256(text):
    """Return SHA256 hash of text"""
    return hashlib.sha256(text.encode()).hexdigest()

def try_openssl_decrypt(blob_b64, password):
    """Try to decrypt OpenSSL format encrypted data"""
    try:
        blob = base64.b64decode(blob_b64)
        if not blob.startswith(b"Salted__"):
            return None
        
        salt = blob[8:16]
        ciphertext = blob[16:]
        
        # OpenSSL EVP KDF (MD5-based)
        key = b''
        iv = b''
        prev = b''
        pw_bytes = password.encode() if isinstance(password, str) else password
        
        while len(key) + len(iv) < 48:
            m = MD5.new(prev + pw_bytes + salt).digest()
            prev = m
            key += m
        
        key = key[:32]
        iv = key[32:48]
        
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        plaintext = cipher.decrypt(ciphertext)
        
        # Validate and remove PKCS7 padding
        try:
            pad_len = plaintext[-1]
            if 1 <= pad_len <= 16:
                padding = plaintext[-pad_len:]
                if all(b == pad_len for b in padding):
                    return plaintext[:-pad_len]
        except:
            pass
        
        return None
    except Exception:
        return None

def to_p2pkh_address(priv_hex, compressed=True):
    """Convert private key to P2PKH Bitcoin address"""
    try:
        from ecdsa import SigningKey, SECP256k1
        from Cryptodome.Hash import RIPEMD160
        
        priv = bytes.fromhex(priv_hex)
        sk = SigningKey.from_string(priv, curve=SECP256k1)
        vk = sk.get_verifying_key()
        
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        
        if compressed:
            prefix = 2 + (y & 1)
            pubkey = bytes([prefix]) + x.to_bytes(32, 'big')
        else:
            pubkey = bytes([4]) + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
        
        # Hash160 = RIPEMD160(SHA256(pubkey))
        sha = hashlib.sha256(pubkey).digest()
        ripe = RIPEMD160.new(sha).digest()
        
        # Base58Check encoding
        versioned = b'\x00' + ripe
        checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
        addr_bytes = versioned + checksum
        
        # Base58 encode
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        n = int.from_bytes(addr_bytes, 'big')
        enc = ''
        while n > 0:
            n, r = divmod(n, 58)
            enc = alphabet[r] + enc
        
        # Add leading 1s for leading zero bytes
        for byte in addr_bytes:
            if byte == 0:
                enc = '1' + enc
            else:
                break
        
        return enc
    except Exception as e:
        return None

def extract_private_keys(data):
    """Extract potential private keys from decrypted data"""
    hex_pattern = re.compile(r'\b[0-9a-fA-F]{64}\b')
    
    # Try as hex
    keys_hex = hex_pattern.findall(data.hex())
    
    # Try as text
    try:
        text = data.decode('utf-8', errors='ignore')
        keys_text = hex_pattern.findall(text)
        return list(set(keys_hex + keys_text))
    except:
        return keys_hex

def main():
    print("="*70)
    print("Bitcoin Puzzle Solver - Find the Key")
    print("="*70)
    print(f"Target Address: {TARGET_ADDRESS}\n")
    
    # Load Cosmic Duality blob
    with open('SalPhaseIon.md', 'r') as f:
        content = f.read()
    
    lines = content.strip().split('\n')
    cosmic_blob = ""
    in_cosmic = False
    
    for line in lines:
        if "Cosmic Duality" in line:
            in_cosmic = True
            continue
        if in_cosmic and line.strip():
            cosmic_blob += line.strip()
    
    print(f"Cosmic Duality blob loaded: {len(cosmic_blob)} characters\n")
    
    # Generate password candidates based on clues
    candidates = []
    
    # Direct interpretations
    candidates.extend([
        "shabefanstoo",
        "fanstoo",
        "fans",
        "shabe",
        "too",
        "fan",
        "fantoo",
    ])
    
    # SHA256 hashes
    for word in ["shabefanstoo", "fanstoo", "fans", "shabe", "fan", "too"]:
        candidates.append(sha256(word))
    
    # Reverse and variations
    candidates.extend([
        "oofsnatebahs",  # shabefanstoo reversed
        "oofstoo",       # fanstoo reversed
        "snaf",          # fans reversed
    ])
    
    # More complex combinations based on the clue structure
    candidates.extend([
        "firsthintlastcommand",
        "lastcommandfirsthint",
        "thefirsthintisyourlastcommand",
        "yourlastcommandisyourfirsthint",
    ])
    
    # Related to puzzle
    candidates.extend([
        "CosmicDuality",
        "cosmicduality",
        "cosmic",
        "duality",
    ])
    
    print(f"Testing {len(candidates)} password candidates...\n")
    
    for i, pw in enumerate(candidates, 1):
        result = try_openssl_decrypt(cosmic_blob, pw)
        
        if result:
            print(f"\n{'='*70}")
            print(f"🎉 SUCCESS! Decryption succeeded with password: '{pw}'")
            print(f"{'='*70}\n")
            print(f"Plaintext length: {len(result)} bytes")
            print(f"First 200 bytes (hex): {result[:200].hex()}\n")
            
            # Try to display as text
            try:
                as_text = result.decode('utf-8', errors='ignore')
                print(f"As text (first 500 chars):\n{as_text[:500]}\n")
            except:
                pass
            
            # Extract and test private keys
            keys = extract_private_keys(result)
            
            if keys:
                print(f"Found {len(keys)} potential private key(s):\n")
                
                for key in keys[:20]:  # Test up to 20 keys
                    addr_compressed = to_p2pkh_address(key, compressed=True)
                    addr_uncompressed = to_p2pkh_address(key, compressed=False)
                    
                    if addr_compressed or addr_uncompressed:
                        print(f"Private Key: {key}")
                        if addr_compressed:
                            print(f"  Compressed:   {addr_compressed}")
                        if addr_uncompressed:
                            print(f"  Uncompressed: {addr_uncompressed}")
                        
                        if addr_compressed == TARGET_ADDRESS:
                            print(f"\n🏆 FOUND THE WINNING KEY! (Compressed)")
                            with open('WINNING_KEY.txt', 'w') as f:
                                f.write(f"Password: {pw}\n")
                                f.write(f"Private Key (hex): {key}\n")
                                f.write(f"Address: {addr_compressed}\n")
                                f.write(f"Format: Compressed P2PKH\n")
                            return
                        
                        if addr_uncompressed == TARGET_ADDRESS:
                            print(f"\n🏆 FOUND THE WINNING KEY! (Uncompressed)")
                            with open('WINNING_KEY.txt', 'w') as f:
                                f.write(f"Password: {pw}\n")
                                f.write(f"Private Key (hex): {key}\n")
                                f.write(f"Address: {addr_uncompressed}\n")
                                f.write(f"Format: Uncompressed P2PKH\n")
                            return
                        
                        print()
            else:
                print("No hex private keys found in decrypted data")
            
            # Save the decrypted data
            with open('cosmic_duality_decrypted.bin', 'wb') as f:
                f.write(result)
            print(f"\nDecrypted data saved to: cosmic_duality_decrypted.bin")
            
            return
    
    print("No successful decryption with tested passwords.")
    print("\nThe password may need further analysis of the hidden clues.")

if __name__ == "__main__":
    main()
