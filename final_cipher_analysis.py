#!/usr/bin/env python3
"""
Final Ultra-Deep Analysis: Apply ALL cipher methods before AES
Based on puzzle hint: "23 ciphers, 16 encryptions, 7 passwords"
"""

import base64
import hashlib
import subprocess
import sys

def beaufort_decrypt(ciphertext, key):
    """Beaufort cipher decryption"""
    result = ""
    key = key.upper()
    key_len = len(key)
    
    for i, char in enumerate(ciphertext.upper()):
        if char.isalpha():
            key_char = key[i % key_len]
            # Beaufort: plaintext = key - ciphertext (mod 26)
            decrypted = chr(((ord(key_char) - ord(char)) % 26) + ord('A'))
            result += decrypted
        else:
            result += char
    return result

def analyze_cosmic_blob():
    """Analyze the cosmic duality blob with all cipher methods"""
    
    print("🔬 FINAL ULTRA-DEEP CIPHER ANALYSIS")
    print("=" * 60)
    
    # Read the blob
    try:
        with open('cosmic_duality_blob.b64', 'r') as f:
            blob_content = f.read().strip()
    except:
        print("Error: cosmic_duality_blob.b64 not found")
        return
    
    print(f"Original blob length: {len(blob_content)} characters")
    print(f"First 100 chars: {blob_content[:100]}")
    
    # Try to decode as base64 first
    try:
        decoded_bytes = base64.b64decode(blob_content)
        print(f"Base64 decoded length: {len(decoded_bytes)} bytes")
        
        # Try to interpret as text
        try:
            decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
            print(f"Decoded as text (first 200 chars): {decoded_text[:200]}")
        except:
            print("Cannot decode as UTF-8 text")
            
        # Check if it looks like another base64 layer
        if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in decoded_text):
            print("Looks like nested base64 encoding")
            try:
                double_decoded = base64.b64decode(decoded_text)
                print(f"Double base64 decoded length: {len(double_decoded)} bytes")
            except:
                print("Failed to double-decode base64")
                
    except Exception as e:
        print(f"Base64 decode failed: {e}")
    
    # Apply Beaufort cipher with known keys
    beaufort_keys = [
        "THEMATRIXHASYOU",
        "COSMICDUALTY", 
        "SALPHASEION",
        "MATRIXSUMLIST",
        "LASTWORDSBEFOREARCHICHOICE"
    ]
    
    print("\n🔑 TESTING BEAUFORT CIPHER DECRYPTION:")
    for key in beaufort_keys:
        try:
            # Convert blob to text for Beaufort
            blob_text = ''.join(c for c in blob_content if c.isalpha())
            if len(blob_text) > 0:
                beaufort_result = beaufort_decrypt(blob_text, key)
                print(f"Beaufort with '{key}': {beaufort_result[:100]}...")
                
                # Try to use Beaufort result as AES password
                test_aes_with_beaufort_result(beaufort_result)
        except Exception as e:
            print(f"Beaufort with '{key}' failed: {e}")
    
    # Check for patterns in the blob
    print("\n🔍 PATTERN ANALYSIS:")
    
    # Look for repeating patterns
    for pattern_len in [8, 16, 32, 64]:
        patterns = {}
        for i in range(0, len(blob_content) - pattern_len + 1, pattern_len):
            pattern = blob_content[i:i+pattern_len]
            patterns[pattern] = patterns.get(pattern, 0) + 1
        
        repeated = {k: v for k, v in patterns.items() if v > 1}
        if repeated:
            print(f"Repeated {pattern_len}-char patterns: {len(repeated)}")
            for pattern, count in list(repeated.items())[:3]:
                print(f"  '{pattern}': {count} times")
    
    # Try interpreting as hex
    try:
        if all(c in '0123456789ABCDEFabcdef' for c in blob_content):
            hex_decoded = bytes.fromhex(blob_content)
            print(f"Hex decoded length: {len(hex_decoded)} bytes")
    except:
        pass
    
    print("\n💡 RECOMMENDATIONS:")
    print("1. The blob might need Beaufort/VIC cipher decryption FIRST")
    print("2. Then apply AES decryption to the result")
    print("3. Consider the blob might be multiple layers of encoding")
    print("4. The '23 ciphers, 16 encryptions' hint suggests complex layering")

def test_aes_with_beaufort_result(beaufort_text):
    """Test AES decryption using Beaufort result as password"""
    try:
        # Use first 32 chars as password
        password = beaufort_text[:32] if len(beaufort_text) >= 32 else beaufort_text
        
        cmd = [
            'openssl', 'enc', '-aes-256-cbc', '-d', '-a',
            '-in', 'cosmic_duality_blob.b64',
            '-pass', f'pass:{password}',
            '-out', 'beaufort_test.bin'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            try:
                with open('beaufort_test.bin', 'rb') as f:
                    content = f.read()
                if len(content) > 0:
                    print(f"  ✅ AES SUCCESS with Beaufort password: {password[:20]}...")
                    print(f"  Content: {content[:100]}")
                    return True
            except:
                pass
    except:
        pass
    return False

if __name__ == "__main__":
    analyze_cosmic_blob()
