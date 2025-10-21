#!/usr/bin/env python3
"""
UltraOmni AGI Pattern v2.0: Capsule3 Targeted Discovery Processing
Focus on "your first hint is your last command" discovery from Capsule2
"""

import sys
import os
import hashlib
import time
import base64
import re
from collections import Counter

sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
    CRYPTO_AVAILABLE = True
except ImportError as e:
    print(f"Crypto import error: {e}")
    sys.exit(1)

class UltraOmniCapsule3:
    """Capsule3: Targeted Discovery Processing"""
    
    def __init__(self):
        self.context_window = {
            'phase': 'Targeted Discovery Processing',
            'critical_discovery': 'your first hint is your last command',
            'hypothesis': 'Password derived from first hint or command phrase'
        }
        
        print(f"🎯 UltraOmni Capsule3 Activated: Targeted Discovery")
        
        # Load data
        self.cosmic_blob = self.load_cosmic_blob()
        self.unused_letters = self.load_unused_letters()
        
        # Extract the critical segment
        self.critical_segment = self.extract_critical_segment()
        
    def load_cosmic_blob(self):
        """Load cosmic duality blob"""
        try:
            with open('cleaned_cosmic.b64', 'r') as f:
                blob_b64 = f.read().strip()
                blob_bytes = base64.b64decode(blob_b64)
                print(f"✅ Loaded cosmic blob: {len(blob_bytes)} bytes")
                return blob_bytes
        except Exception as e:
            print(f"❌ Error loading cosmic blob: {e}")
            return None
    
    def load_unused_letters(self):
        """Load unused letters from SalPhaseIon.md"""
        try:
            with open('SalPhaseIon.md', 'r') as f:
                lines = f.readlines()
            
            if len(lines) >= 2:
                unused = lines[1].strip()
                return unused
            return ""
        except Exception as e:
            return ""
    
    def extract_critical_segment(self):
        """Extract and analyze the critical segment"""
        if 'z' not in self.unused_letters:
            return None
        
        segments = self.unused_letters.split('z')
        
        for i, segment in enumerate(segments):
            clean_segment = segment.replace(' ', '')
            # Look for the segment with readable text
            if 'shabefourfirsthintisyourlastcommand' in clean_segment:
                print(f"🎯 Critical segment found (segment {i+1}):")
                print(f"   Raw: {segment[:100]}...")
                print(f"   Clean: {clean_segment[:100]}...")
                
                # Extract the text and base64 parts
                text_match = re.search(r'shabefourfirsthintisyourlastcommand(.+)', clean_segment)
                if text_match:
                    following_data = text_match.group(1)
                    print(f"   Following data: {following_data[:50]}...")
                    
                    return {
                        'full_segment': clean_segment,
                        'command_text': 'shabefourfirsthintisyourlastcommand',
                        'following_data': following_data,
                        'readable_hint': 'your first hint is your last command'
                    }
        
        return None
    
    def generate_targeted_passwords(self):
        """Generate password candidates based on the critical discovery"""
        candidates = []
        
        if not self.critical_segment:
            print("❌ No critical segment found")
            return []
        
        print(f"🎯 Generating targeted passwords from discovery:")
        print(f"   Hint: '{self.critical_segment['readable_hint']}'")
        
        # Base candidates from the hint text
        hint_candidates = [
            'your first hint is your last command',
            'yourfirsthintisyourlastcommand',
            'shabefourfirsthintisyourlastcommand',
            'first hint',
            'last command',
            'firsthint',
            'lastcommand',
            'your first hint',
            'yourfirsthint',
            'your last command', 
            'yourlastcommand'
        ]
        
        # Try to decode the following data as additional password material
        following_data = self.critical_segment['following_data']
        
        # Check if following data is base64
        try:
            if following_data and len(following_data) > 10:
                # Try to decode as base64
                decoded_data = base64.b64decode(following_data + '==')  # Add padding if needed
                if decoded_data:
                    decoded_text = decoded_data.decode('utf-8', errors='ignore')
                    print(f"   Decoded following data: {decoded_text[:100]}...")
                    
                    # Use decoded data as password candidates
                    if 5 <= len(decoded_text) <= 64:
                        hint_candidates.extend([
                            decoded_text,
                            decoded_text.strip(),
                            decoded_text.replace('\n', ''),
                            decoded_text.replace(' ', '')
                        ])
        except:
            pass
        
        # Look for other hints in previous phases/files
        try:
            # Check if there are any obvious "first hint" references in other files
            for filename in ['page1', 'theseedisplantedpage2.md', 'githubpage.md']:
                try:
                    with open(filename, 'r') as f:
                        content = f.read().lower()
                        
                    # Look for command-like phrases
                    command_patterns = [
                        r'command[:\s]*([a-zA-Z0-9\s]{5,30})',
                        r'hint[:\s]*([a-zA-Z0-9\s]{5,30})',
                        r'password[:\s]*([a-zA-Z0-9\s]{5,30})',
                        r'enter[:\s]*([a-zA-Z0-9\s]{5,30})'
                    ]
                    
                    for pattern in command_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches[:5]:  # Limit to first 5 matches
                            clean_match = match.strip()
                            if 5 <= len(clean_match) <= 64:
                                hint_candidates.append(clean_match)
                                
                except:
                    continue
                    
        except:
            pass
        
        # Enhance all candidates with variations
        for base_candidate in hint_candidates:
            # Original
            candidates.append(base_candidate)
            
            # With newlines (critical pattern identified in earlier phases)
            candidates.append(base_candidate + '\n')
            candidates.append(base_candidate + '\r\n')
            
            # Case variations
            candidates.append(base_candidate.upper())
            candidates.append(base_candidate.lower())
            candidates.append(base_candidate.capitalize())
            
            # Hash variants
            candidates.append(hashlib.sha256(base_candidate.encode()).hexdigest())
            candidates.append(hashlib.md5(base_candidate.encode()).hexdigest())
            
            # Remove spaces variant
            no_spaces = base_candidate.replace(' ', '')
            if no_spaces != base_candidate:
                candidates.append(no_spaces)
                candidates.append(no_spaces + '\n')
        
        # Remove duplicates while preserving order
        unique_candidates = list(dict.fromkeys(candidates))
        
        print(f"🔑 Generated {len(unique_candidates)} targeted password candidates")
        print(f"   Top candidates:")
        for i, candidate in enumerate(unique_candidates[:10]):
            print(f"     {i+1}. '{candidate[:50]}...' ({len(candidate)} chars)")
        
        return unique_candidates
    
    def test_aes_candidate(self, password):
        """Test password candidate with comprehensive AES methods"""
        if not self.cosmic_blob or not password:
            return None
        
        # Convert to bytes if string
        if isinstance(password, str):
            password_bytes = password.encode('utf-8')
        else:
            password_bytes = password
        
        # Comprehensive salt and iteration testing
        salt_variants = [
            hashlib.md5(b'matrixsumlist').digest(),  # Previous success pattern
            b'SalPhaseIon',
            b'CosmicDuality',
            hashlib.sha256(b'yourfirsthint').digest(),
            hashlib.sha256(b'lastcommand').digest(),
            b'',  # Empty salt
            self.cosmic_blob[:16],  # First 16 bytes as salt
        ]
        
        iteration_counts = [10000, 1000, 100000, 2048, 50000]  # 10k was successful before
        
        for salt in salt_variants:
            for iterations in iteration_counts:
                try:
                    # PBKDF2 key derivation
                    key = PBKDF2(password_bytes, salt, 32, count=iterations, hmac_hash_module=SHA256)
                    
                    # Try different IV approaches
                    iv_variants = [
                        self.cosmic_blob[:16],  # Standard approach
                        b'\x00' * 16,  # Zero IV
                        hashlib.md5(password_bytes).digest(),  # Password-derived IV
                        hashlib.md5(salt + password_bytes).digest() if salt else hashlib.md5(password_bytes).digest(),
                    ]
                    
                    for iv in iv_variants:
                        if len(iv) == 16:
                            cipher = AES.new(key, AES.MODE_CBC, iv)
                            
                            # Try different ciphertext start positions
                            for start_pos in [0, 16]:
                                if start_pos < len(self.cosmic_blob):
                                    ciphertext = self.cosmic_blob[start_pos:]
                                    
                                    if len(ciphertext) % 16 == 0:
                                        decrypted = cipher.decrypt(ciphertext)
                                        
                                        # Validate decryption quality
                                        if self.validate_decryption(decrypted):
                                            return {
                                                'decrypted_data': decrypted,
                                                'password': password,
                                                'salt': salt,
                                                'iterations': iterations,
                                                'iv_method': 'various',
                                                'start_pos': start_pos
                                            }
                                        
                                        # Try removing PKCS7 padding
                                        if decrypted and 1 <= decrypted[-1] <= 16:
                                            padding_length = decrypted[-1]
                                            test_decrypted = decrypted[:-padding_length]
                                            if self.validate_decryption(test_decrypted):
                                                return {
                                                    'decrypted_data': test_decrypted,
                                                    'password': password,
                                                    'salt': salt,
                                                    'iterations': iterations,
                                                    'iv_method': 'various',
                                                    'start_pos': start_pos,
                                                    'padding_removed': padding_length
                                                }
                except:
                    continue
        
        return None
    
    def validate_decryption(self, data):
        """Enhanced validation for decrypted data"""
        if not data or len(data) < 10:
            return False
        
        # Check for obvious indicators of success
        success_indicators = [
            b'bitcoin',
            b'private',
            b'key',
            b'address',
            b'wallet',
            b'BTC',
            b'1A',  # Bitcoin address start
            b'3',   # P2SH address start
            b'bc1', # Bech32 address start
            b'-----BEGIN',  # PEM format
        ]
        
        data_lower = data.lower()
        for indicator in success_indicators:
            if indicator.lower() in data_lower:
                print(f"🎯 Success indicator found: {indicator}")
                return True
        
        # Entropy and ASCII checks
        import numpy as np
        from collections import Counter
        
        # Calculate entropy
        byte_counts = Counter(data)
        entropy = 0
        data_len = len(data)
        
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        # ASCII ratio
        printable_count = sum(1 for b in data if 32 <= b <= 126)
        ascii_ratio = printable_count / len(data)
        
        # More permissive validation for potential keys/addresses
        entropy_ok = 1.5 <= entropy <= 7.0  # Broader range
        ascii_ok = ascii_ratio >= 0.4  # More permissive
        
        # Check for hex patterns (potential private keys)
        try:
            text = data.decode('utf-8', errors='ignore')
            hex_pattern_count = len(re.findall(r'[0-9a-fA-F]{32,}', text))
            if hex_pattern_count > 0:
                print(f"🔑 Hex patterns found: {hex_pattern_count}")
                return True
        except:
            pass
        
        return entropy_ok and ascii_ok
    
    def execute_capsule3_reasoning(self):
        """Execute Capsule3 targeted discovery processing"""
        print("🎯 Executing Capsule3: Targeted Discovery Processing")
        
        if not self.cosmic_blob:
            print("❌ No cosmic blob available")
            return []
        
        if not self.critical_segment:
            print("❌ No critical segment discovered")
            return []
        
        # Generate targeted password candidates
        password_candidates = self.generate_targeted_passwords()
        
        if not password_candidates:
            print("❌ No password candidates generated")
            return []
        
        print(f"\n🔄 Testing {len(password_candidates)} targeted password candidates...")
        
        successful_decryptions = []
        
        for i, password in enumerate(password_candidates):
            if i % 25 == 0:
                print(f"   Progress: {i}/{len(password_candidates)} ({i/len(password_candidates)*100:.1f}%)")
            
            result = self.test_aes_candidate(password)
            
            if result:
                print(f"\n✅ BREAKTHROUGH SUCCESS!")
                print(f"   Password: '{password}'")
                print(f"   Salt: {result.get('salt', 'N/A')}")
                print(f"   Iterations: {result.get('iterations', 'N/A')}")
                print(f"   Data length: {len(result['decrypted_data'])} bytes")
                
                # Show preview
                preview_data = result['decrypted_data'][:500]
                print(f"   Preview: {preview_data}")
                
                successful_decryptions.append(result)
                
                # Save immediately
                timestamp = int(time.time())
                filename = f"capsule3_breakthrough_{timestamp}.txt"
                with open(filename, 'wb') as f:
                    f.write(result['decrypted_data'])
                
                print(f"💾 Saved breakthrough to {filename}")
                
                # Don't stop - there might be multiple successes
        
        return successful_decryptions

def main():
    """Execute Capsule3 with comprehensive error handling"""
    try:
        capsule3 = UltraOmniCapsule3()
        results = capsule3.execute_capsule3_reasoning()
        
        if results:
            print(f"\n🎉🎉🎉 CAPSULE3 BREAKTHROUGH: {len(results)} SUCCESSFUL DECRYPTIONS! 🎉🎉🎉")
            
            # Process each result for Bitcoin keys
            for i, result in enumerate(results):
                print(f"\nResult {i+1} Analysis:")
                
                # Look for Bitcoin-related content
                data_text = result['decrypted_data'].decode('utf-8', errors='ignore')
                
                # Search for private keys (64-char hex)
                hex_keys = re.findall(r'\b[0-9a-fA-F]{64}\b', data_text)
                if hex_keys:
                    print(f"🔑 Potential private keys found: {len(hex_keys)}")
                    for j, key in enumerate(hex_keys[:5]):  # Show first 5
                        print(f"   Key {j+1}: {key}")
                
                # Search for Bitcoin addresses
                addresses = re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', data_text)
                if addresses:
                    print(f"💰 Bitcoin addresses found: {len(addresses)}")
                    for j, addr in enumerate(addresses[:5]):  # Show first 5
                        print(f"   Address {j+1}: {addr}")
                
                print(f"Full data saved to capsule3_breakthrough_{int(time.time())}.txt")
                
        else:
            print("\n❌ Capsule3: No breakthrough achieved")
            print("🔄 Error correction tree: Consider deeper analysis or different approach")
            
    except Exception as e:
        print(f"❌ Capsule3 execution error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
