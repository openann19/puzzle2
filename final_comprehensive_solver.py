#!/usr/bin/env python3
"""
Final comprehensive Cosmic Duality solver
Extract ALL possible passwords from every decrypted phase and test multiple cipher methods
"""
import subprocess
import tempfile
import os
import re
import hashlib
from pathlib import Path
import json

def extract_all_possible_passwords():
    """Extract every possible password from all decrypted content"""
    passwords = set()
    
    print("🔍 EXTRACTING PASSWORDS FROM ALL SOURCES")
    print("=" * 50)
    
    # 1. From SalPhaseIon.md content analysis
    salphase_content = Path('SalPhaseIon.md').read_text()
    
    # Extract all letter sequences and number sequences
    letter_sequences = re.findall(r'[A-Za-z]{3,}', salphase_content)
    number_sequences = re.findall(r'\d{3,}', salphase_content)
    
    passwords.update(letter_sequences)
    passwords.update(number_sequences)
    
    # 2. From phase2_decrypted.bin
    if Path('phase2_decrypted.bin').exists():
        phase2_content = Path('phase2_decrypted.bin').read_text(errors='ignore')
        phase2_words = re.findall(r'[A-Za-z]{3,}', phase2_content)
        phase2_numbers = re.findall(r'\d{3,}', phase2_content)
        passwords.update(phase2_words)
        passwords.update(phase2_numbers)
        
        # Extract specific references
        passwords.update(['BV80605001911AP', 'eps3.4', 'runtime-error', 'Phillip'])
    
    # 3. From the 770-byte raw data as hex strings
    if Path('solution_pbkdf2_SalPhaseIon_10000.txt').exists():
        raw_data = Path('solution_pbkdf2_SalPhaseIon_10000.txt').read_bytes()
        raw_hex = raw_data.hex()
        
        # Extract hex patterns
        for length in [8, 16, 32, 64]:
            for i in range(0, len(raw_hex) - length, 2):
                hex_chunk = raw_hex[i:i+length]
                passwords.add(hex_chunk)
    
    # 4. From all verified keys JSON
    if Path('all_verified_keys.json').exists():
        with open('all_verified_keys.json', 'r') as f:
            keys_data = json.load(f)
        
        for key_info in keys_data:
            passwords.add(key_info['private_key_hex'])
            passwords.add(key_info['compressed_address'])
            passwords.add(key_info['uncompressed_address'])
    
    # 5. Mathematical combinations based on puzzle clues
    base_words = ['SalPhaseIon', 'CosmicDuality', 'matrixsumlist', 'enter', 'GSMG']
    for word in base_words:
        passwords.add(word)
        passwords.add(word.lower())
        passwords.add(word.upper())
        passwords.add(hashlib.sha256(word.encode()).hexdigest())
        passwords.add(hashlib.md5(word.encode()).hexdigest())
    
    # 6. Target address components
    target = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    passwords.add(target)
    passwords.add(target[1:])  # Without prefix
    passwords.add('GSMG')
    passwords.add('1GSMG')
    
    # 7. From any other decrypted files
    for bin_file in Path('.').glob('*.bin'):
        if bin_file.stat().st_size > 0:
            try:
                content = bin_file.read_text(errors='ignore')
                words = re.findall(r'[A-Za-z0-9]{4,}', content)
                passwords.update(words)
            except:
                pass
    
    # 8. VIC cipher result variations
    vic_result = "INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALF"
    passwords.add(vic_result)
    passwords.add(vic_result.lower())
    passwords.add('HALFANDBETTERHALF')
    passwords.add('halfandbetterhalf')
    
    # Filter and clean
    cleaned_passwords = set()
    for pw in passwords:
        if isinstance(pw, str) and len(pw) >= 3 and len(pw) <= 128:
            cleaned_passwords.add(pw)
    
    print(f"📊 Extracted {len(cleaned_passwords)} unique password candidates")
    return sorted(list(cleaned_passwords))

def test_alternative_ciphers(blob_b64, password):
    """Test alternative cipher methods beyond AES-CBC"""
    cipher_methods = [
        # AES variants
        'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc',
        'aes-128-ecb', 'aes-192-ecb', 'aes-256-ecb',
        'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
        'aes-128-ofb', 'aes-192-ofb', 'aes-256-ofb',
        
        # Other ciphers
        'des-cbc', 'des3-cbc', 'blowfish-cbc',
        'camellia-128-cbc', 'camellia-192-cbc', 'camellia-256-cbc',
        'cast5-cbc', 'idea-cbc', 'rc2-cbc', 'rc4'
    ]
    
    kdf_options = [
        [],  # default
        ['-md', 'md5'],
        ['-md', 'sha1'], 
        ['-md', 'sha256'],
        ['-pbkdf2'],
        ['-pbkdf2', '-iter', '1000'],
        ['-pbkdf2', '-iter', '10000'],
        ['-pbkdf2', '-iter', '100000']
    ]
    
    for cipher in cipher_methods:
        for kdf in kdf_options:
            try:
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                    f.write(blob_b64)
                    blob_file = f.name
                
                cmd = ['openssl', 'enc', f'-{cipher}', '-d', '-a', '-in', blob_file, '-pass', f'pass:{password}']
                cmd.extend(kdf)
                
                result = subprocess.run(cmd, capture_output=True, timeout=3)
                os.unlink(blob_file)
                
                if result.returncode == 0 and result.stdout:
                    data = result.stdout
                    # Check if result looks valid
                    printable_ratio = sum(1 for b in data if 32 <= b <= 126 or b in [9,10,13]) / max(1, len(data))
                    
                    if (printable_ratio > 0.6 or 
                        b'private' in data.lower() or 
                        b'key' in data.lower() or
                        b'bitcoin' in data.lower() or
                        len(data) > 100):
                        
                        return cipher, kdf, data
                        
            except Exception:
                continue
    
    return None, None, None

def comprehensive_cosmic_test():
    """Comprehensive test of all passwords with all cipher methods"""
    
    # Get Cosmic Duality blob
    content = Path('SalPhaseIon.md').read_text()
    lines = content.strip().split('\n')
    
    cosmic_start = False
    blob_lines = []
    
    for line in lines:
        if 'Cosmic Duality' in line:
            cosmic_start = True
            continue
        if cosmic_start and line.startswith('U2FsdGVk'):
            blob_lines.append(line.strip())
        elif cosmic_start and blob_lines and line.strip():
            if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in line.strip()):
                blob_lines.append(line.strip())
    
    blob = ''.join(blob_lines)
    
    # Extract all passwords
    passwords = extract_all_possible_passwords()
    
    print(f"\n🚀 COMPREHENSIVE COSMIC DUALITY TEST")
    print(f"🎯 Testing {len(passwords)} passwords with multiple cipher methods")
    print("=" * 60)
    
    total_attempts = 0
    max_attempts = 50000  # Reasonable limit
    
    for i, password in enumerate(passwords):
        if total_attempts >= max_attempts:
            print(f"Reached maximum attempts limit ({max_attempts})")
            break
            
        if i % 500 == 0:
            print(f"Progress: {i}/{len(passwords)} passwords ({total_attempts} total attempts)")
        
        # Test this password with alternative ciphers
        cipher, kdf, data = test_alternative_ciphers(blob, password)
        total_attempts += 1
        
        if cipher:
            print(f"\n🎉 BREAKTHROUGH!")
            print(f"Password: {password}")
            print(f"Cipher: {cipher}")
            print(f"KDF: {' '.join(kdf) if kdf else 'default'}")
            print(f"Result length: {len(data)} bytes")
            print(f"Data preview: {data[:200]}")
            
            # Save the result
            with open('cosmic_final_success.bin', 'wb') as f:
                f.write(data)
            
            # Look for Bitcoin private key in the result
            hex_data = data.hex()
            print(f"Hex preview: {hex_data[:128]}...")
            
            # Check if it contains valid private key patterns
            key_patterns = re.findall(r'[0-9a-fA-F]{64}', hex_data)
            if key_patterns:
                print(f"Found potential private keys: {len(key_patterns)}")
                for j, key_hex in enumerate(key_patterns[:5]):
                    print(f"  Key {j+1}: {key_hex}")
            
            success_info = {
                'password': password,
                'cipher': cipher,
                'kdf': kdf,
                'data_length': len(data),
                'hex_preview': hex_data[:256],
                'potential_keys': key_patterns[:10] if key_patterns else []
            }
            
            with open('cosmic_success_info.json', 'w') as f:
                json.dump(success_info, f, indent=2)
            
            return True
    
    print(f"\n❌ No success after {total_attempts} attempts")
    print("💡 The password may require a different derivation method")
    return False

def main():
    print("🌌 FINAL COMPREHENSIVE COSMIC DUALITY SOLVER")
    print("=" * 60)
    
    success = comprehensive_cosmic_test()
    
    if success:
        print("\n🏆 COSMIC DUALITY SUCCESSFULLY DECRYPTED!")
        print("Check cosmic_final_success.bin and cosmic_success_info.json for details")
    else:
        print("\n🔍 Consider these final approaches:")
        print("1. Manual cryptanalysis of the Cosmic Duality structure")  
        print("2. Brute force with custom character sets")
        print("3. Analysis of puzzle creator's other works for patterns")
        print("4. Community collaboration for additional insights")

if __name__ == '__main__':
    main()
