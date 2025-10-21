#!/usr/bin/env python3
"""
Secondary Decryption Analysis - Try to decrypt the breakthrough data further
The 1344 bytes may be another AES layer or encoded data
"""

import sys
import os
import hashlib
import base64
import re

sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
except ImportError:
    print("❌ Crypto not available")
    sys.exit(1)

def load_breakthrough_data():
    """Load our 1344-byte breakthrough data"""
    with open('capsule3_breakthrough_1755336408.txt', 'rb') as f:
        return f.read()

def try_secondary_aes_decryption(data, passwords):
    """Try AES decryption on the breakthrough data with our successful passwords"""
    print("🔄 Attempting secondary AES decryption...")
    
    results = []
    
    for i, password in enumerate(passwords):
        print(f"  Testing password {i+1}/{len(passwords)}: {password[:20]}...")
        
        # Multiple key derivation methods
        key_methods = [
            hashlib.sha256(password.encode()).digest(),
            hashlib.md5(password.encode()).digest() * 2,
            PBKDF2(password.encode(), b'', 32, count=10000, hmac_hash_module=SHA256),
            PBKDF2(password.encode(), hashlib.md5(b'matrixsumlist').digest(), 32, count=10000, hmac_hash_module=SHA256),
        ]
        
        for j, key in enumerate(key_methods):
            # Try different modes and IVs
            modes_and_ivs = [
                (AES.MODE_ECB, None),
                (AES.MODE_CBC, b'\x00' * 16),
                (AES.MODE_CBC, data[:16]),
                (AES.MODE_CBC, hashlib.md5(password.encode()).digest()),
            ]
            
            for mode, iv in modes_and_ivs:
                try:
                    if mode == AES.MODE_ECB:
                        cipher = AES.new(key[:32], mode)
                        ciphertext = data
                    else:
                        cipher = AES.new(key[:32], mode, iv)
                        if iv == data[:16]:
                            ciphertext = data[16:]
                        else:
                            ciphertext = data
                    
                    # Decrypt
                    if len(ciphertext) % 16 == 0:
                        decrypted = cipher.decrypt(ciphertext)
                        
                        # Validate
                        if is_potentially_valid(decrypted):
                            results.append({
                                'password': password,
                                'key_method': j,
                                'mode': mode,
                                'iv_method': iv,
                                'decrypted': decrypted,
                                'entropy': calculate_entropy(decrypted)
                            })
                            
                            print(f"    ✅ Potential success! Entropy: {calculate_entropy(decrypted):.2f}")
                            print(f"       Preview: {decrypted[:100]}")
                            
                except Exception as e:
                    continue
    
    return results

def try_base64_decoding(data):
    """Try various Base64 decoding approaches"""
    print("🔄 Attempting Base64 decoding...")
    
    results = []
    
    # Convert to text
    text_data = data.decode('utf-8', errors='ignore')
    
    # Extract potential base64 patterns
    base64_patterns = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text_data)
    
    for i, pattern in enumerate(base64_patterns[:10]):  # Test first 10
        try:
            decoded = base64.b64decode(pattern + '==')  # Add padding
            if is_potentially_valid(decoded):
                results.append({
                    'method': f'base64_pattern_{i}',
                    'original_pattern': pattern,
                    'decoded': decoded,
                    'entropy': calculate_entropy(decoded)
                })
                print(f"  ✅ Base64 pattern {i+1}: {len(decoded)} bytes")
                print(f"     Preview: {decoded[:100]}")
        except Exception as e:
            continue
    
    # Try treating entire data as base64
    ascii_data = ''.join(chr(b) for b in data if 32 <= b <= 126)
    if len(ascii_data) > 100:
        try:
            decoded = base64.b64decode(ascii_data + '==')
            if is_potentially_valid(decoded):
                results.append({
                    'method': 'full_ascii_base64',
                    'decoded': decoded,
                    'entropy': calculate_entropy(decoded)
                })
                print(f"  ✅ Full ASCII Base64: {len(decoded)} bytes")
        except Exception as e:
            print(f"  ❌ Full ASCII Base64 failed: {e}")
    
    return results

def try_xor_analysis(data):
    """Try XOR with common keys"""
    print("🔄 Attempting XOR analysis...")
    
    results = []
    
    # Common XOR keys to try
    xor_keys = [
        b'bitcoin',
        b'puzzle',
        b'key',
        b'matrixsumlist',
        b'SalPhaseIon',
        b'CosmicDuality',
        b'priseurl',
        bytes([i for i in range(256)]),  # Single byte XOR
    ]
    
    for key_name, xor_key in [(str(k), k) for k in xor_keys]:
        try:
            # XOR the data
            if len(xor_key) == 1:
                xored = bytes(b ^ xor_key[0] for b in data)
            else:
                xored = bytes(a ^ b for a, b in zip(data, xor_key * (len(data) // len(xor_key) + 1)))
            
            if is_potentially_valid(xored):
                results.append({
                    'method': f'xor_{key_name}',
                    'xor_key': xor_key,
                    'decoded': xored,
                    'entropy': calculate_entropy(xored)
                })
                print(f"  ✅ XOR with {key_name}: entropy {calculate_entropy(xored):.2f}")
                print(f"     Preview: {xored[:100]}")
                
        except Exception as e:
            continue
    
    return results

def calculate_entropy(data):
    """Calculate Shannon entropy"""
    if not data:
        return 0
    
    import math
    from collections import Counter
    
    byte_counts = Counter(data)
    entropy = 0
    data_len = len(data)
    
    for count in byte_counts.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

def is_potentially_valid(data):
    """Check if data looks like it could be valid decryption"""
    if not data or len(data) < 10:
        return False
    
    # Entropy check (should be reasonable for text)
    entropy = calculate_entropy(data)
    if entropy > 7.0:  # Too random
        return False
    
    # ASCII content check
    printable_count = sum(1 for b in data if 32 <= b <= 126)
    ascii_ratio = printable_count / len(data)
    
    # Check for Bitcoin/crypto indicators
    try:
        text_data = data.decode('utf-8', errors='ignore').lower()
        crypto_indicators = ['bitcoin', 'private', 'key', 'address', 'wallet', 'btc', '1a', '3', 'bc1']
        indicator_count = sum(1 for indicator in crypto_indicators if indicator in text_data)
    except:
        indicator_count = 0
    
    # Valid if good ASCII ratio OR has crypto indicators
    return ascii_ratio > 0.4 or indicator_count > 0

def analyze_ascii_patterns(data):
    """Analyze ASCII patterns in the data"""
    print("🔄 Analyzing ASCII patterns...")
    
    # Extract all ASCII characters
    ascii_chars = ''.join(chr(b) for b in data if 32 <= b <= 126)
    
    print(f"  📊 ASCII content: {len(ascii_chars)}/{len(data)} characters ({len(ascii_chars)/len(data)*100:.1f}%)")
    
    if len(ascii_chars) > 50:
        print(f"  🔍 ASCII content: {ascii_chars}")
        
        # Look for patterns
        potential_base64 = re.findall(r'[A-Za-z0-9+/]{10,}={0,2}', ascii_chars)
        potential_hex = re.findall(r'[0-9a-fA-F]{20,}', ascii_chars)
        potential_addresses = re.findall(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', ascii_chars)
        
        print(f"  🔍 Potential Base64 patterns: {len(potential_base64)}")
        print(f"  🔍 Potential hex patterns: {len(potential_hex)}")
        print(f"  🔍 Potential Bitcoin addresses: {len(potential_addresses)}")
        
        if potential_addresses:
            print(f"  💰 BITCOIN ADDRESSES FOUND: {potential_addresses}")
            
        return {
            'ascii_content': ascii_chars,
            'base64_patterns': potential_base64,
            'hex_patterns': potential_hex,
            'bitcoin_addresses': potential_addresses
        }
    
    return {}

def main():
    """Execute secondary decryption analysis"""
    
    print("🔍 SECONDARY DECRYPTION ANALYSIS")
    print("="*60)
    print("🎯 Analyzing breakthrough data for additional layers...")
    
    # Load data
    data = load_breakthrough_data()
    print(f"📊 Data size: {len(data)} bytes")
    
    # Analyze ASCII patterns first
    ascii_analysis = analyze_ascii_patterns(data)
    
    if ascii_analysis.get('bitcoin_addresses'):
        print("\n🎉 BITCOIN ADDRESSES FOUND IN ASCII TEXT!")
        for addr in ascii_analysis['bitcoin_addresses']:
            print(f"  💰 {addr}")
        return
    
    # Our successful passwords from Capsule3
    successful_passwords = [
        'priseurl',
        'prisesettingsurl', 
        'shabefourfirsthintisyourlastcommand',
        'yourfirsthintisyourlastcommand',
        'matrixsumlist',
        'SalPhaseIon',
        'CosmicDuality'
    ]
    
    all_results = []
    
    # Try secondary AES decryption
    aes_results = try_secondary_aes_decryption(data, successful_passwords)
    all_results.extend(aes_results)
    
    # Try Base64 decoding
    base64_results = try_base64_decoding(data)
    all_results.extend(base64_results)
    
    # Try XOR analysis
    xor_results = try_xor_analysis(data)
    all_results.extend(xor_results)
    
    print(f"\n📊 SECONDARY ANALYSIS RESULTS")
    print(f"   Total successful decodings: {len(all_results)}")
    
    if all_results:
        # Sort by entropy (lower = more structured)
        all_results.sort(key=lambda x: x['entropy'])
        
        for i, result in enumerate(all_results[:5], 1):
            print(f"\nResult {i}:")
            print(f"  Method: {result.get('method', 'AES')}")
            print(f"  Entropy: {result['entropy']:.2f}")
            print(f"  Length: {len(result['decoded'])} bytes")
            print(f"  Preview: {result['decoded'][:200]}")
            
            # Save promising results
            if result['entropy'] < 6.0:
                filename = f"secondary_decryption_{i}.txt"
                with open(filename, 'wb') as f:
                    f.write(result['decoded'])
                print(f"  💾 Saved to {filename}")
    
    else:
        print("❌ No additional decryptions found")
        print("💡 The breakthrough data may require manual analysis or different approach")

if __name__ == "__main__":
    main()
