#!/usr/bin/env python3
"""
Deep analysis of the 770-byte SalPhaseIon decrypted data
Look for embedded strings, patterns, or clues for Cosmic Duality password
"""
import hashlib
import base64
import binascii
from pathlib import Path
import re
import subprocess
import tempfile

def analyze_raw_data():
    """Analyze the 770-byte raw decrypted data"""
    data = Path('solution_pbkdf2_SalPhaseIon_10000.txt').read_bytes()
    
    print(f"📊 ANALYZING 770-byte DECRYPTED DATA")
    print(f"Length: {len(data)} bytes")
    print("=" * 50)
    
    # 1. Look for ASCII strings
    printable_chars = []
    for i, b in enumerate(data):
        if 32 <= b <= 126:  # Printable ASCII
            printable_chars.append((i, chr(b)))
    
    if printable_chars:
        print(f"🔤 PRINTABLE CHARACTERS FOUND: {len(printable_chars)}")
        ascii_string = ''.join([c for _, c in printable_chars])
        print(f"ASCII sequence: {ascii_string[:100]}...")
        
        # Look for words in the ASCII
        words = re.findall(r'[A-Za-z]{4,}', ascii_string)
        if words:
            print(f"Words found: {words}")
    
    # 2. Entropy analysis - look for patterns
    print(f"\n🧮 ENTROPY ANALYSIS")
    hex_data = data.hex()
    print(f"Hex representation: {hex_data[:64]}...")
    
    # Check for repeating patterns
    patterns_found = []
    for length in [4, 8, 16, 32]:
        for i in range(0, len(hex_data) - length, 2):
            pattern = hex_data[i:i+length]
            count = hex_data.count(pattern)
            if count > 1 and len(pattern) >= 4:
                patterns_found.append((pattern, count))
    
    if patterns_found:
        patterns_found = list(set(patterns_found))
        patterns_found.sort(key=lambda x: -x[1])
        print(f"Repeating patterns: {patterns_found[:5]}")
    
    # 3. Look for embedded base64 or other encodings
    print(f"\n🔍 ENCODING ANALYSIS")
    
    # Try interpreting sections as base64
    for chunk_size in [4, 8, 16, 32, 64]:
        for i in range(0, len(data) - chunk_size, chunk_size):
            chunk = data[i:i+chunk_size]
            
            # Try base64
            try:
                # Convert to potential base64 characters
                b64_chars = ''.join([chr(b) for b in chunk if 65 <= b <= 90 or 97 <= b <= 122 or 48 <= b <= 57 or b in [43, 47, 61]])
                if len(b64_chars) >= 4 and len(b64_chars) % 4 == 0:
                    decoded = base64.b64decode(b64_chars)
                    if decoded and len(decoded) > 0:
                        print(f"Potential B64 at offset {i}: {b64_chars} → {decoded.hex()[:32]}...")
            except:
                pass
    
    # 4. Mathematical analysis - look for key relationships
    print(f"\n🔢 MATHEMATICAL ANALYSIS")
    
    # Interpret as series of 32-byte keys (like we extracted)
    keys = []
    for i in range(0, len(data) - 32, 8):  # 8-byte overlap like our extracted keys
        key_bytes = data[i:i+32]
        if all(b != 0 for b in key_bytes):  # Skip null keys
            keys.append(key_bytes.hex())
    
    print(f"Potential 32-byte keys found: {len(keys)}")
    
    # Look for hidden strings in the data
    print(f"\n🔎 HIDDEN STRING SEARCH")
    
    # Try different interpretations
    interpretations = [
        ("Direct ASCII", ''.join([chr(b) if 32 <= b <= 126 else '.' for b in data])),
        ("XOR 0xFF", ''.join([chr(b ^ 0xFF) if 32 <= (b ^ 0xFF) <= 126 else '.' for b in data])),
        ("Reverse", ''.join([chr(b) if 32 <= b <= 126 else '.' for b in data[::-1]])),
    ]
    
    for name, interpretation in interpretations:
        # Look for meaningful words
        words = re.findall(r'[A-Za-z]{5,}', interpretation)
        if words:
            print(f"{name} words: {words[:10]}")
    
    # 5. Generate password candidates from the raw data
    print(f"\n🔑 GENERATING PASSWORD CANDIDATES")
    
    password_candidates = set()
    
    # Hash sections of the data
    for i in range(0, len(data), 32):
        section = data[i:i+32]
        if len(section) == 32:
            password_candidates.add(hashlib.sha256(section).hexdigest())
            password_candidates.add(hashlib.md5(section).hexdigest())
    
    # Use the full data hash
    password_candidates.add(hashlib.sha256(data).hexdigest())
    password_candidates.add(hashlib.md5(data).hexdigest())
    
    # Try the hex representation
    password_candidates.add(hex_data)
    password_candidates.add(hex_data[:64])  # First 32 bytes
    password_candidates.add(hex_data[-64:])  # Last 32 bytes
    
    # Add any ASCII words we found
    ascii_sequence = ''.join([chr(b) if 32 <= b <= 126 else '' for b in data])
    if ascii_sequence:
        password_candidates.add(ascii_sequence.strip())
        words = re.findall(r'[A-Za-z]{4,}', ascii_sequence)
        password_candidates.update(words)
    
    return sorted(list(password_candidates))

def test_cosmic_with_raw_passwords(candidates):
    """Test Cosmic Duality blob with passwords derived from raw data"""
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
    
    print(f"🚀 TESTING {len(candidates)} RAW-DERIVED PASSWORDS")
    print("=" * 50)
    
    methods = ['aes-256-cbc', 'aes-128-cbc']
    kdf_variants = ['', '-md sha256', '-pbkdf2 -iter 10000']
    
    for i, password in enumerate(candidates):
        if i % 20 == 0:
            print(f"Progress: {i}/{len(candidates)}")
        
        for method in methods:
            for kdf in kdf_variants:
                try:
                    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                        f.write(blob)
                        blob_file = f.name
                    
                    cmd = ['openssl', 'enc', f'-{method}', '-d', '-a', '-in', blob_file, '-pass', f'pass:{password}']
                    if kdf:
                        cmd.extend(kdf.split())
                    
                    result = subprocess.run(cmd, capture_output=True, timeout=5)
                    Path(blob_file).unlink()
                    
                    if result.returncode == 0 and result.stdout:
                        data = result.stdout
                        printable_ratio = sum(1 for b in data if 32 <= b <= 126 or b in [9,10,13]) / max(1, len(data))
                        
                        if printable_ratio > 0.6 or b'private' in data.lower() or b'key' in data.lower():
                            print(f"\n🎉 SUCCESS WITH RAW-DERIVED PASSWORD!")
                            print(f"Password: {password}")
                            print(f"Method: {method} {kdf}")
                            print(f"Result length: {len(data)}")
                            print(f"Preview: {data[:200]}")
                            
                            with open(f'cosmic_raw_success.bin', 'wb') as f:
                                f.write(data)
                            
                            return password, data
                except Exception:
                    continue
    
    return None, None

def main():
    # Analyze the raw 770-byte data
    password_candidates = analyze_raw_data()
    
    print(f"\n📋 TOP PASSWORD CANDIDATES FROM RAW DATA:")
    for i, candidate in enumerate(password_candidates[:15]):
        print(f"{i+1:2d}. {candidate[:64]}{'...' if len(candidate) > 64 else ''}")
    
    # Test these passwords on Cosmic Duality
    success_password, decrypted_data = test_cosmic_with_raw_passwords(password_candidates)
    
    if success_password:
        print(f"\n🏆 FINAL SUCCESS!")
        print(f"Winning password: {success_password}")
        
        # Look for Bitcoin private key in the result
        if decrypted_data:
            print("Analyzing decrypted Cosmic Duality data for target private key...")
            # This would be the final step to extract the 5 BTC private key
        
    else:
        print(f"\n❌ Raw data analysis didn't yield Cosmic Duality password")
        print(f"   Tested {len(password_candidates)} candidates derived from 770-byte data")

if __name__ == '__main__':
    main()
