#!/usr/bin/env python3
"""
ULTIMATE FINAL SOLUTION
The blob is confirmed OpenSSL AES (starts with "Salted__")
We need to derive the password using ALL cipher methods from the puzzle
"""

import hashlib
import subprocess
import base64

def beaufort_decrypt(ciphertext, key):
    """Beaufort cipher decryption"""
    result = ""
    key = key.upper()
    key_len = len(key)
    
    for i, char in enumerate(ciphertext.upper()):
        if char.isalpha():
            key_char = key[i % key_len]
            decrypted = chr(((ord(key_char) - ord(char)) % 26) + ord('A'))
            result += decrypted
        else:
            result += char
    return result

def generate_cipher_derived_passwords():
    """Generate passwords using ALL cipher methods from the puzzle"""
    
    base_phrases = [
        "fourfirsthintisyourlastcommand",
        "averyspecialdessert", 
        "CosmicDuality",
        "lastwordsbeforearchichoice",
        "theseedisplanted",
        "matrixsumlist",
        "SalPhaseIon",
        "THEMATRIXHASYOU",
        "causality",
        "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"
    ]
    
    cipher_keys = [
        "THEMATRIXHASYOU",
        "COSMICDUALTY", 
        "SALPHASEION",
        "MATRIXSUMLIST"
    ]
    
    derived_passwords = []
    
    # 1. Original phrases
    derived_passwords.extend(base_phrases)
    
    # 2. SHA256 of phrases
    for phrase in base_phrases:
        derived_passwords.append(hashlib.sha256(phrase.encode()).hexdigest())
    
    # 3. Beaufort cipher applied to phrases
    for phrase in base_phrases:
        for key in cipher_keys:
            try:
                beaufort_result = beaufort_decrypt(phrase, key)
                derived_passwords.append(beaufort_result)
                # Also try SHA256 of Beaufort result
                derived_passwords.append(hashlib.sha256(beaufort_result.encode()).hexdigest())
            except:
                pass
    
    # 4. Binary interpretation (from diagram's 64 zeros)
    # The 64 zeros might mean: use 64-character passwords or 64-bit keys
    for phrase in base_phrases:
        # Pad to 64 characters
        if len(phrase) < 64:
            padded = phrase + '0' * (64 - len(phrase))
            derived_passwords.append(padded)
    
    # 5. Hex interpretation of phrases
    for phrase in base_phrases:
        try:
            hex_phrase = phrase.encode().hex()
            derived_passwords.append(hex_phrase)
        except:
            pass
    
    # 6. Base64 interpretation
    for phrase in base_phrases:
        try:
            b64_phrase = base64.b64encode(phrase.encode()).decode()
            derived_passwords.append(b64_phrase)
        except:
            pass
    
    # 7. Combinations with cipher results
    beaufort_results = []
    for phrase in ["CosmicDuality", "lastwordsbeforearchichoice"]:
        for key in cipher_keys:
            try:
                result = beaufort_decrypt(phrase, key)
                beaufort_results.append(result)
            except:
                pass
    
    # Combine Beaufort results
    for i, result1 in enumerate(beaufort_results):
        for j, result2 in enumerate(beaufort_results):
            if i != j:
                derived_passwords.append(result1 + result2)
    
    return list(set(derived_passwords))  # Remove duplicates

def test_ultimate_decryption():
    """Test ultimate decryption with cipher-derived passwords"""
    
    print("🔥 ULTIMATE FINAL SOLUTION ATTEMPT")
    print("=" * 60)
    
    passwords = generate_cipher_derived_passwords()
    print(f"Generated {len(passwords)} cipher-derived passwords")
    
    # All salt sources from puzzle
    salt_sources = [
        "the seed is planted",
        "matrixsumlist", 
        "lastwordsbeforearchichoice",
        "CosmicDuality",
        "SalPhaseIon",
        "thispassword"
    ]
    
    # Test each combination
    for i, password in enumerate(passwords):
        if i % 100 == 0:
            print(f"Testing password {i+1}/{len(passwords)}: {password[:30]}...")
        
        for salt_source in salt_sources:
            salt = hashlib.md5(salt_source.encode()).hexdigest()
            
            # Test PBKDF2 (most likely based on SalPhaseIon success)
            for iterations in [10000, 1048576, 100000]:
                try:
                    cmd = [
                        'openssl', 'enc', '-aes-256-cbc', '-d', '-a',
                        '-in', 'cosmic_duality_blob.b64',
                        '-pass', f'pass:{password}',
                        '-pbkdf2', '-iter', str(iterations),
                        '-md', 'sha256',
                        '-S', salt,
                        '-out', 'final_test.bin'
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        try:
                            with open('final_test.bin', 'rb') as f:
                                content = f.read()
                            
                            if len(content) > 0:
                                print(f"\n🎉 ULTIMATE SUCCESS! 🎉")
                                print(f"Password: {password}")
                                print(f"Salt source: {salt_source}")
                                print(f"Salt: {salt}")
                                print(f"Iterations: {iterations}")
                                print(f"Content length: {len(content)} bytes")
                                
                                try:
                                    content_str = content.decode('utf-8', errors='ignore')
                                    print(f"Content: {content_str}")
                                    
                                    # Look for Bitcoin private key
                                    lines = content_str.split('\n')
                                    for line in lines:
                                        line = line.strip()
                                        if len(line) == 64 and all(c in '0123456789abcdefABCDEF' for c in line):
                                            print(f"🔑 POTENTIAL PRIVATE KEY: {line}")
                                        elif len(line) == 51 and line[0] in '5KL':
                                            print(f"🔑 POTENTIAL WIF KEY: {line}")
                                            
                                except:
                                    print("Binary content - checking for key patterns...")
                                    hex_content = content.hex()
                                    print(f"Hex: {hex_content[:200]}...")
                                
                                return True
                                
                        except:
                            pass
                        finally:
                            try:
                                subprocess.run(['rm', '-f', 'final_test.bin'], capture_output=True)
                            except:
                                pass
                                
                except Exception as e:
                    pass
    
    print("No successful decryption found with cipher-derived passwords")
    return False

if __name__ == "__main__":
    test_ultimate_decryption()
