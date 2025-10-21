#!/usr/bin/env python3
"""
Analyze Phase 2 decrypted clues to derive Cosmic Duality password
"""
import re
import hashlib
import math

def analyze_clues():
    """Analyze the mathematical clues from phase2_decrypted.bin"""
    print("🔍 ANALYZING PHASE 2 CLUES")
    print("=" * 40)
    
    # The clues from phase2_decrypted.bin
    clues = {
        'Q': "extend the name of a hackers' swordless fish, the I and W are below",
        'B': "((BV80605001911AP)- (sqrt(-1)))^2", 
        'H': "(Answer to only this puzzle but nothing else) * -1",
        'S': "cha' + (vagh * jav)"
    }
    
    print("📝 CLUE ANALYSIS:")
    print("-" * 20)
    
    # Analyze Q: "hackers' swordless fish"
    print("Q - 'hackers swordless fish':")
    print("  - Hackers often associated with 'phishing' -> 'fish'")
    print("  - Swordless fish could be 'phish' (without sword/s)")
    print("  - Or could be 'tuna', 'shark', 'bass', etc.")
    print("  - 'extend the name' might mean add characters")
    
    # Analyze B: Mathematical expression
    print("\nB - Mathematical:")
    print("  - BV80605001911AP likely a processor code (Intel)")
    print("  - sqrt(-1) = i (imaginary unit)")
    print("  - Need to interpret BV80605001911AP as number")
    
    # Analyze H: Recursive reference
    print("\nH - Recursive:")
    print("  - 'Answer to only this puzzle' suggests self-reference")
    print("  - Could be related to the target address or final answer")
    print("  - Multiplied by -1")
    
    # Analyze S: Klingon numbers
    print("\nS - Klingon numbers:")
    print("  - cha' = 2 in Klingon")
    print("  - vagh = 5 in Klingon") 
    print("  - jav = 6 in Klingon")
    print("  - So: 2 + (5 * 6) = 2 + 30 = 32")
    
    print("\n🧮 COMPUTATIONAL ATTEMPTS:")
    print("-" * 30)
    
    # Try to compute B
    try:
        # Interpret BV80605001911AP as hex or decimal
        # BV80605001911AP might be processor model, try different interpretations
        
        # Try as hex (removing non-hex chars)
        hex_part = "80605001911"  # Remove B, V, A, P
        if hex_part:
            b_value = int(hex_part, 16) - 1j  # subtract i (imaginary unit)
            b_squared = b_value ** 2
            print(f"B (hex interpretation): {abs(b_squared)}")
        
        # Try as decimal
        dec_part = "80605001911"
        b_decimal = int(dec_part) - 1j
        b_decimal_sq = b_decimal ** 2
        print(f"B (decimal interpretation): {abs(b_decimal_sq)}")
        
    except Exception as e:
        print(f"B calculation error: {e}")
    
    # S calculation
    s_value = 2 + (5 * 6)  # cha' + (vagh * jav)
    print(f"S = 2 + (5 * 6) = {s_value}")
    
    # Generate potential passwords based on clues
    password_candidates = []
    
    # Fish-related words for Q
    fish_words = ['phish', 'tuna', 'shark', 'bass', 'cod', 'salmon']
    for fish in fish_words:
        password_candidates.extend([
            fish,
            fish.upper(),
            f"hacker{fish}",
            f"{fish}hacker"
        ])
    
    # Number combinations
    password_candidates.extend([
        f"{s_value}",  # 32
        f"S{s_value}",
        f"klingon{s_value}",
        "80605001911",
        "BV80605001911AP"
    ])
    
    # Movie/show references (eps3.4 suggests Mr. Robot)
    tv_refs = [
        "mrrobot",
        "elliot", 
        "fsociety",
        "eps3.4",
        "runtime-error",
        "phillip",
        "valleys"
    ]
    password_candidates.extend(tv_refs)
    
    # Keymaker references (Matrix)
    matrix_refs = [
        "keymaker",
        "keymakers", 
        "theKeymaker",
        "digitalpower",
        "digitalpowers"
    ]
    password_candidates.extend(matrix_refs)
    
    return password_candidates

def test_cosmic_passwords(candidates):
    """Test password candidates on Cosmic Duality blob"""
    import subprocess
    import tempfile
    import os
    from pathlib import Path
    
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
    
    print(f"\n🔑 TESTING {len(candidates)} DERIVED PASSWORDS")
    print("-" * 40)
    
    methods = ['aes-256-cbc', 'aes-128-cbc']
    kdf_opts = ['', '-md sha256', '-pbkdf2 -iter 10000']
    
    for i, password in enumerate(candidates):
        if i % 10 == 0:
            print(f"Progress: {i}/{len(candidates)}")
            
        for method in methods:
            for kdf in kdf_opts:
                try:
                    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                        f.write(blob)
                        blob_file = f.name
                    
                    cmd = ['openssl', 'enc', f'-{method}', '-d', '-a', '-in', blob_file, '-pass', f'pass:{password}']
                    if kdf:
                        cmd.extend(kdf.split())
                    
                    result = subprocess.run(cmd, capture_output=True, timeout=5)
                    os.unlink(blob_file)
                    
                    if result.returncode == 0 and result.stdout:
                        data = result.stdout
                        printable_ratio = sum(1 for b in data if 32 <= b <= 126 or b in [9,10,13]) / max(1, len(data))
                        
                        if printable_ratio > 0.6 or b'private' in data.lower():
                            print(f"\n🎉 POTENTIAL SUCCESS!")
                            print(f"Password: {password}")
                            print(f"Method: {method} {kdf}")
                            print(f"Result length: {len(data)}")
                            print(f"Preview: {data[:100]}")
                            
                            with open(f'cosmic_success_{password}.bin', 'wb') as f:
                                f.write(data)
                                
                            return True
                            
                except Exception:
                    continue
    
    return False

def main():
    candidates = analyze_clues()
    
    print(f"\n📋 GENERATED {len(candidates)} PASSWORD CANDIDATES:")
    for i, pw in enumerate(candidates[:20]):  # Show first 20
        print(f"  {i+1:2d}. {pw}")
    if len(candidates) > 20:
        print(f"  ... and {len(candidates)-20} more")
    
    # Test the candidates
    success = test_cosmic_passwords(candidates)
    
    if not success:
        print("\n❌ No matches found with derived passwords")
        print("💡 May need deeper analysis of the mathematical clues")

if __name__ == '__main__':
    main()
