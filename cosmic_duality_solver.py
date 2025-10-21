#!/usr/bin/env python3
"""
Comprehensive Cosmic Duality blob decryptor
Tests all known passwords and variations systematically
"""
import subprocess
import hashlib
import base64
import tempfile
import os
import json
from pathlib import Path

def get_cosmic_duality_blob():
    """Extract the Cosmic Duality blob from SalPhaseIon.md"""
    content = Path('SalPhaseIon.md').read_text()
    lines = content.strip().split('\n')
    
    # Find the blob starting after "Cosmic Duality"
    cosmic_start = False
    blob_lines = []
    
    for line in lines:
        if 'Cosmic Duality' in line:
            cosmic_start = True
            continue
        if cosmic_start and line.startswith('U2FsdGVk'):
            blob_lines.append(line.strip())
        elif cosmic_start and blob_lines and not line.startswith('U2FsdGVk') and line.strip():
            # Continue collecting if it looks like base64
            if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in line.strip()):
                blob_lines.append(line.strip())
    
    return ''.join(blob_lines)

def generate_password_candidates():
    """Generate comprehensive password list from all puzzle sources"""
    candidates = set()
    
    # Known extracted passwords
    base_passwords = [
        'SalPhaseIon',
        'matrixsumlist', 
        'enter',
        'lastwordsbeforearchichoice',
        'thispassword',
        'averyspecialdessert',
        'causality',
        'CosmicDuality',
        'THEMATRIXHASYOU',
        'theflowerblossomsthroughwhatseemstobeaconcretesurface',
        'HASHTHETEXT',
        'GSMG',
        'bitcoin',
        'halfandbetterhalf',
        'choiceisanillusion',
        'Architect',
        'Neo',
        'Matrix'
    ]
    
    # Add base passwords
    for pw in base_passwords:
        candidates.add(pw)
        candidates.add(pw.lower())
        candidates.add(pw.upper())
        candidates.add(pw.title())
    
    # Add SHA256 hashes of key words
    key_phrases = [
        'matrixsumlist',
        'SalPhaseIon',
        'CosmicDuality',
        'lastwordsbeforearchichoice',
        'thispassword',
        'averyspecialdessert'
    ]
    
    for phrase in key_phrases:
        sha = hashlib.sha256(phrase.encode()).hexdigest()
        candidates.add(sha)
        candidates.add(sha.upper())
    
    # Phase-related combinations
    phase_combinations = [
        'SalPhaseIonCosmicDuality',
        'CosmicDualitySalPhaseIon',
        'matrixsumlistenter',
        'entermatrixsumlist',
        'SalPhaseIon' + hashlib.md5(b'matrixsumlist').hexdigest(),
        'CosmicDuality' + hashlib.md5(b'matrixsumlist').hexdigest(),
    ]
    
    for combo in phase_combinations:
        candidates.add(combo)
        candidates.add(hashlib.sha256(combo.encode()).hexdigest())
    
    # VIC cipher result variations
    vic_result = "INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALF ANDBETTERHALF ANDTHEYALSONEEDFUNDSTOLIVE"
    vic_words = vic_result.replace(' ', '').lower()
    candidates.add(vic_words)
    candidates.add('halfandbetterhalf')
    candidates.add('HALFANDBETTERHALF')
    
    return sorted(list(candidates))

def test_openssl_decrypt(blob_b64, password, method='aes-256-cbc', kdf_opts=''):
    """Test OpenSSL decryption with given parameters"""
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(blob_b64)
            blob_file = f.name
        
        cmd = [
            'openssl', 'enc', f'-{method}', '-d', '-a',
            '-in', blob_file,
            '-pass', f'pass:{password}'
        ]
        
        if kdf_opts:
            if 'pbkdf2' in kdf_opts:
                cmd.extend(['-pbkdf2'])
                if 'iter' in kdf_opts:
                    iterations = kdf_opts.split('iter:')[1]
                    cmd.extend(['-iter', iterations])
            elif 'md' in kdf_opts:
                md_type = kdf_opts.split('md:')[1]
                cmd.extend(['-md', md_type])
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            timeout=10,
            text=False
        )
        
        os.unlink(blob_file)
        
        if result.returncode == 0 and result.stdout:
            # Check if result looks like valid data
            data = result.stdout
            printable_ratio = sum(1 for b in data if 32 <= b <= 126 or b in [9, 10, 13]) / max(1, len(data))
            
            if printable_ratio > 0.6 or b'private' in data.lower() or b'key' in data.lower():
                return data
        
        return None
        
    except Exception:
        return None

def main():
    print("🚀 COSMIC DUALITY BLOB DECRYPTOR")
    print("=" * 50)
    
    # Get the blob
    blob = get_cosmic_duality_blob()
    print(f"📊 Blob size: {len(blob)} characters")
    
    # Generate password candidates
    passwords = generate_password_candidates()
    print(f"🔑 Testing {len(passwords)} password candidates...")
    
    # Test methods and KDF options
    methods = ['aes-256-cbc', 'aes-192-cbc', 'aes-128-cbc']
    kdf_options = [
        '',  # default
        'md:md5',
        'md:sha1', 
        'md:sha256',
        'pbkdf2',
        'pbkdf2 iter:1000',
        'pbkdf2 iter:10000'
    ]
    
    results = []
    total_attempts = len(passwords) * len(methods) * len(kdf_options)
    attempt = 0
    
    for password in passwords:
        for method in methods:
            for kdf in kdf_options:
                attempt += 1
                if attempt % 100 == 0:
                    print(f"Progress: {attempt}/{total_attempts} ({100*attempt/total_attempts:.1f}%)")
                
                result = test_openssl_decrypt(blob, password, method, kdf)
                
                if result:
                    print(f"\n🎉 SUCCESS!")
                    print(f"Password: {password}")
                    print(f"Method: {method}")
                    print(f"KDF: {kdf}")
                    print(f"Result length: {len(result)} bytes")
                    
                    # Save result
                    result_info = {
                        'password': password,
                        'method': method,
                        'kdf': kdf,
                        'result_length': len(result),
                        'result_hex': result.hex() if len(result) < 1000 else result[:500].hex() + "...",
                        'printable_preview': result[:200].decode('utf-8', errors='ignore')
                    }
                    
                    results.append(result_info)
                    
                    with open(f'cosmic_decrypted_{len(results)}.bin', 'wb') as f:
                        f.write(result)
                    
                    print(f"💾 Saved to cosmic_decrypted_{len(results)}.bin")
                    print("Preview:", result[:100])
    
    if results:
        with open('cosmic_duality_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n✅ Found {len(results)} successful decryptions!")
    else:
        print("\n❌ No successful decryptions found")
        print("💡 May need additional password candidates or different approach")

if __name__ == '__main__':
    main()
