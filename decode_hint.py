#!/usr/bin/env python3
"""
Decode the hint blobs from SalPhaseIon.md
"""

import hashlib
import base64
from Crypto.Cipher import AES

def evp_bytes_to_key(password, salt):
    """OpenSSL's EVP_BytesToKey algorithm using MD5"""
    d = d_i = b''
    while len(d) < 48:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d += d_i
    return d[:48]

def try_openssl_decrypt(blob_b64, password):
    """Try to decrypt OpenSSL-style AES-256-CBC encrypted data"""
    try:
        # Clean and decode the base64 blob
        clean_blob = blob_b64.replace('\n', '').replace(' ', '')
        encrypted_data = base64.b64decode(clean_blob)
        
        # Check for "Salted__" prefix
        if encrypted_data[:8] != b'Salted__':
            print(f"  Not OpenSSL format (no Salted__ prefix)")
            return None
            
        salt = encrypted_data[8:16]
        ciphertext = encrypted_data[16:]
        
        print(f"  Salt: {salt.hex()}")
        print(f"  Ciphertext length: {len(ciphertext)} bytes")
        
        # Try EVP_BytesToKey (OpenSSL default)
        key_material = evp_bytes_to_key(password.encode(), salt)
        key = key_material[:32]
        iv = key_material[32:48]
        
        # Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        
        # Remove PKCS7 padding
        padding_length = decrypted[-1]
        if 1 <= padding_length <= 16:
            decrypted = decrypted[:-padding_length]
            return decrypted
            
    except Exception as e:
        print(f"  Error: {e}")
    
    return None

def main():
    # The two base64 strings from the hint section in SalPhaseIon.md
    hint_blob_1 = "U2FsdGVkX186tYU0hVJBXXUnBUO7C0+X4KUWnWkCvoZSxbRD3wNsGWVHefvdrd9z"
    hint_blob_2 = "QvX0t8v3jPB4okpspxebRi6sE1BMl5HI8RkuKejUqTvdWOX6nQjSpepXwGuN/jJ"
    
    # Combine them as they might be one blob split for readability
    combined_blob = hint_blob_1 + hint_blob_2
    
    print("="*60)
    print("DECODING HINT BLOBS FROM SalPhaseIon.md")
    print("="*60)
    
    # Known passwords from the puzzle
    passwords = [
        "matrixsumlist",
        "lastwordsbeforearchichoice",
        "thispassword",
        "enter",
        "SalPhaseIon",
        "HASHTHETEXT",
        "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32",
        "CosmicDuality",
        "shabefanstoo",
        # Maybe the password is derived from the first 4 chars of certain hints
        "matr",  # first 4 of matrixsumlist
        "last",  # first 4 of lastwordsbeforearchichoice  
        "this",  # first 4 of thispassword
        "ente",  # first 4 of enter
        "fourfirsthintisyourlastcommand",
        # Combined first 4s
        "matrlastthisente",
        "matrlastenter",
        # Let's also try what "shabefanstoo" means
        # sha + bef + anstoo = sha256(bef) + anstoo?
        "sha",
        "bef",
        "anstoo",
    ]
    
    # Test blob 1
    print("\n📦 Testing BLOB 1...")
    print(f"Blob: {hint_blob_1}")
    for pwd in passwords:
        result = try_openssl_decrypt(hint_blob_1, pwd)
        if result:
            print(f"✅ SUCCESS with password: '{pwd}'")
            print(f"Decrypted: {result}")
            print(f"Hex: {result.hex()}")
            try:
                print(f"Text: {result.decode('utf-8', errors='ignore')}")
            except:
                pass
            break
    
    # Test blob 2  
    print("\n📦 Testing BLOB 2...")
    print(f"Blob: {hint_blob_2}")
    for pwd in passwords:
        result = try_openssl_decrypt(hint_blob_2, pwd)
        if result:
            print(f"✅ SUCCESS with password: '{pwd}'")
            print(f"Decrypted: {result}")
            print(f"Hex: {result.hex()}")
            try:
                print(f"Text: {result.decode('utf-8', errors='ignore')}")
            except:
                pass
            break
    
    # Test combined blob
    print("\n📦 Testing COMBINED BLOB...")
    print(f"Blob: {combined_blob[:50]}...")
    for pwd in passwords:
        result = try_openssl_decrypt(combined_blob, pwd)
        if result:
            print(f"✅ SUCCESS with password: '{pwd}'")
            print(f"Decrypted length: {len(result)} bytes")
            print(f"Hex: {result.hex()}")
            try:
                print(f"Text: {result.decode('utf-8', errors='ignore')}")
            except:
                pass
            break
    
    # Let's also just try to decode the base64 directly without decryption
    print("\n📝 RAW BASE64 DECODE (no decryption)...")
    try:
        raw1 = base64.b64decode(hint_blob_1)
        print(f"Blob 1 raw: {raw1[:50]}... (first 50 bytes)")
        print(f"Starts with: {raw1[:20].hex()}")
        
        raw2 = base64.b64decode(hint_blob_2)
        print(f"Blob 2 raw: {raw2[:50]}... (first 50 bytes)")
        print(f"Starts with: {raw2[:20].hex()}")
        
        combined_raw = base64.b64decode(combined_blob)
        print(f"Combined raw length: {len(combined_raw)} bytes")
        print(f"Starts with: {combined_raw[:20].hex()}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
