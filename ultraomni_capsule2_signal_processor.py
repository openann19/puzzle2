#!/usr/bin/env python3
"""
UltraOmni AGI Pattern v2.0: Capsule2 Advanced Signal Vector Processing
Processing unused letters as quantum-inspired signal patterns
"""

import sys
import os
import hashlib
import time
import re
from collections import Counter
import numpy as np
from itertools import combinations, permutations

# Add btc_venv path for crypto libraries  
sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
    import base64
    CRYPTO_AVAILABLE = True
except ImportError as e:
    print(f"Crypto import error: {e}")
    sys.exit(1)

class UltraOmniCapsule2:
    """Capsule2: Advanced Signal Vector Processing for Unused Letters"""
    
    def __init__(self):
        self.context_window = {
            'phase': 'Unused Letter Signal Processing',
            'prior_capsule1': 'AES trials failed - 134 candidates tested',
            'signal_hypothesis': 'Unused letters contain encoded password/key data'
        }
        
        print(f"🧠 UltraOmni Capsule2 Activated: Signal Vector Processing")
        
        # Load data
        self.unused_letters = self.load_unused_letters()
        self.cosmic_blob = self.load_cosmic_blob()
        
        # Signal processing parameters
        self.base10_mapping = {chr(ord('a') + i): str(i+1) for i in range(9)}
        self.base10_mapping['o'] = '0'
        
        # Polybius square (5x5 grid)
        self.polybius_grid = self.create_polybius_grid()
        
    def load_unused_letters(self):
        """Load unused letters from SalPhaseIon.md"""
        try:
            with open('SalPhaseIon.md', 'r') as f:
                lines = f.readlines()
            
            if len(lines) >= 2:
                unused = lines[1].strip()
                print(f"✅ Loaded unused letters: {len(unused)} characters")
                return unused
            return ""
        except Exception as e:
            print(f"❌ Error loading unused letters: {e}")
            return ""
    
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
    
    def create_polybius_grid(self):
        """Create Polybius square mapping (5x5 grid)"""
        grid = {}
        alphabet = 'abcdefghiklmnopqrstuvwxyz'  # Standard: skip 'j' or combine with 'i'
        
        for i, letter in enumerate(alphabet):
            row = (i // 5) + 1
            col = (i % 5) + 1
            grid[letter] = f"{row}{col}"
            
        return grid
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy"""
        if not data:
            return 0
        
        if isinstance(data, str):
            data = data.encode('utf-8', errors='ignore')
            
        byte_counts = Counter(data)
        entropy = 0
        data_len = len(data)
        
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
                
        return entropy
    
    def advanced_frequency_analysis(self):
        """Advanced frequency analysis with pattern detection"""
        if not self.unused_letters:
            return {}
        
        # Remove spaces for analysis
        clean_letters = self.unused_letters.replace(' ', '')
        
        # Basic frequency
        frequency = Counter(clean_letters)
        total_chars = len(clean_letters)
        
        # Bigram analysis
        bigrams = Counter(clean_letters[i:i+2] for i in range(len(clean_letters)-1))
        
        # Trigram analysis  
        trigrams = Counter(clean_letters[i:i+3] for i in range(len(clean_letters)-2))
        
        # Pattern detection
        patterns = {
            'frequency_distribution': frequency,
            'bigram_analysis': bigrams.most_common(20),
            'trigram_analysis': trigrams.most_common(20),
            'total_length': total_chars,
            'unique_chars': len(frequency),
            'entropy': self.calculate_entropy(clean_letters)
        }
        
        print(f"📊 Advanced frequency analysis:")
        print(f"   Total chars: {total_chars}, Unique: {len(frequency)}")
        print(f"   Entropy: {patterns['entropy']:.3f} bits")
        print(f"   Top letters: {frequency.most_common(10)}")
        print(f"   Top bigrams: {bigrams.most_common(5)}")
        
        return patterns
    
    def signal_vector_base10_processing(self):
        """Process as base10 signal vector with advanced techniques"""
        if not self.unused_letters:
            return []
        
        clean_letters = self.unused_letters.replace(' ', '')
        candidates = []
        
        # Convert to digit sequence
        digit_sequence = ''.join(self.base10_mapping.get(letter, '') 
                               for letter in clean_letters)
        
        if not digit_sequence:
            return []
        
        print(f"🔢 Base10 digit sequence: {len(digit_sequence)} digits")
        print(f"   First 150: {digit_sequence[:150]}...")
        
        # Advanced chunking with multiple strategies
        chunking_strategies = [
            # Basic chunk sizes
            (2, 0, 'hex_pairs'),
            (3, 0, 'hex_triplets'), 
            (4, 0, 'hex_quads'),
            (8, 0, 'hex_octets'),
            
            # Offset variations
            (2, 1, 'hex_pairs_off1'),
            (2, 2, 'hex_pairs_off2'),
            (4, 1, 'hex_quads_off1'),
            (4, 2, 'hex_quads_off2'),
            
            # ASCII-focused
            (3, 0, 'ascii_triplets'),
            (2, 0, 'ascii_pairs'),
        ]
        
        for chunk_size, offset, method_name in chunking_strategies:
            try:
                # Apply offset and chunk
                offset_digits = digit_sequence[offset:]
                chunks = [offset_digits[i:i+chunk_size] 
                         for i in range(0, len(offset_digits), chunk_size)]
                
                # Convert chunks based on method
                if 'hex' in method_name:
                    # Convert to hex bytes
                    hex_candidate = ''
                    for chunk in chunks[:64]:  # Limit for memory
                        if chunk.isdigit() and len(chunk) == chunk_size:
                            try:
                                # Convert to hex byte
                                val = int(chunk) % 256  # Modulo to keep in byte range
                                hex_candidate += f"{val:02x}"
                            except:
                                continue
                    
                    if len(hex_candidate) >= 16:  # Minimum 8 bytes
                        candidates.append((method_name, hex_candidate, 'hex_string'))
                        
                        # Try as password candidate
                        candidates.append((f"{method_name}_pw", hex_candidate, 'password'))
                
                elif 'ascii' in method_name:
                    # Convert to ASCII characters
                    ascii_candidate = ''
                    for chunk in chunks[:100]:  # Limit length
                        if chunk.isdigit() and len(chunk) == chunk_size:
                            try:
                                val = int(chunk)
                                if 32 <= val <= 126:  # Printable ASCII range
                                    ascii_candidate += chr(val)
                            except:
                                continue
                    
                    if len(ascii_candidate) >= 8:
                        candidates.append((method_name, ascii_candidate, 'ascii_string'))
                        candidates.append((f"{method_name}_pw", ascii_candidate, 'password'))
            
            except Exception as e:
                continue
        
        print(f"🎯 Generated {len(candidates)} signal vector candidates")
        
        return candidates
    
    def polybius_square_processing(self):
        """Process using Polybius square encoding"""
        if not self.unused_letters:
            return []
        
        clean_letters = self.unused_letters.replace(' ', '')
        candidates = []
        
        # Convert letters to Polybius coordinates
        polybius_sequence = ''
        for letter in clean_letters:
            if letter in self.polybius_grid:
                polybius_sequence += self.polybius_grid[letter]
        
        if not polybius_sequence:
            return []
        
        print(f"🔲 Polybius sequence: {len(polybius_sequence)} digits")
        print(f"   First 100: {polybius_sequence[:100]}...")
        
        # Try different interpretations
        interpretations = [
            ('polybius_hex', 2, 'hex'),
            ('polybius_decimal', 3, 'decimal'),
            ('polybius_ascii', 2, 'ascii'),
            ('polybius_offset', 3, 'decimal_offset')
        ]
        
        for method_name, chunk_size, decode_type in interpretations:
            try:
                chunks = [polybius_sequence[i:i+chunk_size] 
                         for i in range(0, len(polybius_sequence), chunk_size)]
                
                if decode_type == 'hex':
                    hex_result = ''
                    for chunk in chunks[:64]:
                        if chunk.isdigit() and len(chunk) == chunk_size:
                            val = int(chunk) % 256
                            hex_result += f"{val:02x}"
                    
                    if len(hex_result) >= 16:
                        candidates.append((method_name, hex_result, 'hex_string'))
                        candidates.append((f"{method_name}_pw", hex_result, 'password'))
                
                elif decode_type == 'ascii':
                    ascii_result = ''
                    for chunk in chunks[:100]:
                        if chunk.isdigit() and len(chunk) == chunk_size:
                            val = int(chunk)
                            if 32 <= val <= 126:
                                ascii_result += chr(val)
                    
                    if len(ascii_result) >= 8:
                        candidates.append((method_name, ascii_result, 'ascii_string'))
                        candidates.append((f"{method_name}_pw", ascii_result, 'password'))
            
            except Exception as e:
                continue
        
        print(f"🔲 Polybius candidates: {len(candidates)} generated")
        
        return candidates
    
    def z_separator_analysis(self):
        """Analyze segments separated by 'z' characters"""
        if not self.unused_letters or 'z' not in self.unused_letters:
            return []
        
        # Split by 'z' separator
        segments = self.unused_letters.split('z')
        segments = [seg.strip().replace(' ', '') for seg in segments if seg.strip()]
        
        print(f"🧩 Found {len(segments)} z-separated segments")
        
        candidates = []
        
        for i, segment in enumerate(segments):
            if len(segment) < 3:  # Skip very short segments
                continue
                
            print(f"   Segment {i+1}: {len(segment)} chars - {segment[:50]}...")
            
            # Process each segment as potential encoded data
            # Base10 mapping
            digit_seq = ''.join(self.base10_mapping.get(c, '') for c in segment)
            if digit_seq:
                # Try as hex
                try:
                    if len(digit_seq) % 2 == 0:
                        hex_candidate = ''
                        for j in range(0, len(digit_seq), 2):
                            chunk = digit_seq[j:j+2]
                            if chunk.isdigit():
                                val = int(chunk) % 256
                                hex_candidate += f"{val:02x}"
                        
                        if len(hex_candidate) >= 8:
                            candidates.append((f"z_segment_{i+1}_hex", hex_candidate, 'hex_string'))
                            candidates.append((f"z_segment_{i+1}_pw", hex_candidate, 'password'))
                except:
                    pass
            
            # Try segment as direct password candidate
            if 5 <= len(segment) <= 64:  # Reasonable password length
                candidates.append((f"z_segment_{i+1}_direct", segment, 'password'))
        
        print(f"🧩 Z-segment candidates: {len(candidates)} generated")
        
        return candidates
    
    def test_aes_candidate(self, password):
        """Test a password candidate against the cosmic blob"""
        if not self.cosmic_blob or not password:
            return None
        
        # Multiple key derivation methods from Capsule1
        salt_variants = [
            hashlib.md5(b'matrixsumlist').digest(),
            b'SalPhaseIon',
            b'CosmicDuality',
            b'',
            self.cosmic_blob[:16],
        ]
        
        iteration_counts = [10000, 1000, 100000]
        
        for salt in salt_variants:
            for iterations in iteration_counts:
                try:
                    key = PBKDF2(password, salt, 32, count=iterations, hmac_hash_module=SHA256)
                    
                    # Try different IV approaches
                    iv_variants = [
                        self.cosmic_blob[:16],
                        b'\x00' * 16,
                        hashlib.md5(password.encode() if isinstance(password, str) else password).digest(),
                    ]
                    
                    for iv in iv_variants:
                        if len(iv) == 16:
                            cipher = AES.new(key, AES.MODE_CBC, iv)
                            
                            for start_pos in [0, 16]:
                                if start_pos < len(self.cosmic_blob):
                                    ciphertext = self.cosmic_blob[start_pos:]
                                    
                                    if len(ciphertext) % 16 == 0:
                                        decrypted = cipher.decrypt(ciphertext)
                                        
                                        # Validate decryption
                                        if decrypted and self.validate_decryption(decrypted):
                                            return decrypted
                                        
                                        # Try removing padding
                                        if decrypted and 1 <= decrypted[-1] <= 16:
                                            padding_length = decrypted[-1]
                                            test_decrypted = decrypted[:-padding_length]
                                            if self.validate_decryption(test_decrypted):
                                                return test_decrypted
                except:
                    continue
        
        return None
    
    def validate_decryption(self, data):
        """Enhanced validation of decrypted data"""
        if not data or len(data) < 10:
            return False
        
        # Entropy check
        entropy = self.calculate_entropy(data)
        if entropy > 6.5:  # Too random
            return False
        
        # ASCII ratio check
        printable_count = sum(1 for b in data if 32 <= b <= 126)
        ascii_ratio = printable_count / len(data)
        
        # Combined validation (more lenient than Capsule1)
        return entropy < 6.5 and ascii_ratio > 0.3
    
    async def execute_capsule2_reasoning(self):
        """Execute Capsule2 comprehensive signal processing"""
        print("🧠 Executing Capsule2: Advanced Signal Vector Processing")
        
        if not self.unused_letters or not self.cosmic_blob:
            print("❌ Missing data for processing")
            return []
        
        all_candidates = []
        
        # Step 1: Advanced frequency analysis
        print("\n🔍 Step 1: Advanced Frequency Analysis")
        freq_analysis = self.advanced_frequency_analysis()
        
        # Step 2: Base10 signal vector processing
        print("\n🔢 Step 2: Base10 Signal Vector Processing")
        base10_candidates = self.signal_vector_base10_processing()
        all_candidates.extend(base10_candidates)
        
        # Step 3: Polybius square processing
        print("\n🔲 Step 3: Polybius Square Processing")
        polybius_candidates = self.polybius_square_processing()
        all_candidates.extend(polybius_candidates)
        
        # Step 4: Z-separator analysis
        print("\n🧩 Step 4: Z-Separator Analysis")
        z_candidates = self.z_separator_analysis()
        all_candidates.extend(z_candidates)
        
        print(f"\n🎯 Total candidates generated: {len(all_candidates)}")
        
        # Step 5: Test promising candidates
        print("\n🔄 Step 5: Testing Password Candidates")
        successful_decryptions = []
        
        password_candidates = [cand for method, cand, ctype in all_candidates if ctype == 'password']
        
        for i, password in enumerate(password_candidates):
            if i % 20 == 0:
                print(f"   Progress: {i}/{len(password_candidates)} ({i/len(password_candidates)*100:.1f}%)")
            
            decrypted = self.test_aes_candidate(password)
            if decrypted:
                result = {
                    'password': password,
                    'decrypted_data': decrypted,
                    'length': len(decrypted),
                    'entropy': self.calculate_entropy(decrypted),
                    'method': 'capsule2_signal_processing'
                }
                
                successful_decryptions.append(result)
                
                print(f"✅ SUCCESS! Password: {password}")
                print(f"   Length: {len(decrypted)} bytes")
                print(f"   Entropy: {result['entropy']:.2f} bits/char")
                print(f"   Preview: {decrypted[:200]}")
        
        # Save results
        if successful_decryptions:
            timestamp = int(time.time())
            for i, result in enumerate(successful_decryptions):
                filename = f"capsule2_success_{timestamp}_{i}.txt"
                with open(filename, 'wb') as f:
                    f.write(result['decrypted_data'])
                print(f"💾 Saved result to {filename}")
        
        return successful_decryptions

import asyncio

async def main():
    """Execute Capsule2 with error handling"""
    try:
        capsule2 = UltraOmniCapsule2()
        results = await capsule2.execute_capsule2_reasoning()
        
        if results:
            print(f"\n🎉 Capsule2 Complete: {len(results)} successful decryptions")
        else:
            print("\n❌ Capsule2: No successful decryptions found")
            print("🔄 Error correction tree: Consider Capsule3 (hybrid approaches)")
            
    except Exception as e:
        print(f"❌ Capsule2 execution error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
