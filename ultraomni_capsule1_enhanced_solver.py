#!/usr/bin/env python3
"""
UltraOmni AGI Pattern v2.0: Capsule1 Enhanced AES Solver
Implementing the weak AI developer's framework with precision validation
"""

import sys
import os
import hashlib
import base64
import time
import asyncio
from concurrent.futures import ProcessPoolExecutor
from collections import Counter
import numpy as np

# Add btc_venv path for crypto libraries
sys.path.append('/home/ben/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
    CRYPTO_AVAILABLE = True
except ImportError as e:
    print(f"Crypto import error: {e}")
    print("Make sure to activate btc_venv: source btc_venv/bin/activate")
    sys.exit(1)

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    print("PyTorch not available - GPU detection disabled")

class UltraOmniCapsule1:
    """Capsule1: Enhanced AES Solver with Recursive Intelligence"""
    
    def __init__(self):
        self.context_window = {
            'phase': 'Cosmic Duality AES Decryption',
            'prior_success': 'PBKDF2-SHA256 10k iterations + MD5(matrixsumlist)',
            'current_bottleneck': 'Blob corruption + password variants'
        }
        
        # Auto-Elevate: GPU detection
        self.gpu_available = TORCH_AVAILABLE and torch.cuda.is_available() if TORCH_AVAILABLE else False
        self.device_capability = torch.cuda.device_count() if self.gpu_available else 0
        
        print(f"🚀 UltraOmni Capsule1 Activated")
        print(f"GPU Available: {self.gpu_available} ({self.device_capability} devices)")
        
        # Load and clean Cosmic Duality blob
        self.cosmic_duality_blob = self.load_and_clean_blob()
        self.unused_letters = self.load_unused_letters()
        
    def load_and_clean_blob(self):
        """Load Cosmic Duality blob using existing cleaned file"""
        try:
            # Try existing cleaned blob files first
            for blob_file in ['cleaned_cosmic.b64', 'cosmic_duality_blob.b64', 'cleaned_blob.b64']:
                try:
                    with open(blob_file, 'r') as f:
                        blob_b64 = f.read().strip()
                        blob_bytes = base64.b64decode(blob_b64)
                        
                        print(f"✅ Loaded cleaned blob from {blob_file}: {len(blob_bytes)} bytes")
                        print(f"Base64 length: {len(blob_b64)} chars")
                        
                        return blob_bytes
                except FileNotFoundError:
                    continue
                except Exception as e:
                    print(f"Error with {blob_file}: {e}")
                    continue
            
            # Fallback: Extract from SalPhaseIon.md
            with open('SalPhaseIon.md', 'r') as f:
                content = f.read()
                
            lines = content.split('\n')
            blob_lines = []
            in_blob = False
            
            for line in lines:
                if 'Cosmic Duality' in line:
                    in_blob = True
                    continue
                if in_blob and line.strip():
                    # Clean the blob: remove spaces that corrupt base64
                    cleaned_line = line.replace(' ', '').strip()
                    if cleaned_line:
                        blob_lines.append(cleaned_line)
                elif in_blob and not line.strip():
                    break
                    
            blob_b64 = ''.join(blob_lines)
            blob_bytes = base64.b64decode(blob_b64)
            
            print(f"✅ Extracted Cosmic Duality blob: {len(blob_bytes)} bytes")
            print(f"Base64 length: {len(blob_b64)} chars")
            
            return blob_bytes
            
        except Exception as e:
            print(f"❌ Error loading blob: {e}")
            return None
    
    def load_unused_letters(self):
        """Load unused letters sequence for frequency analysis"""
        try:
            with open('SalPhaseIon.md', 'r') as f:
                lines = f.readlines()
                
            # Line 2 contains the unused letters
            if len(lines) >= 2:
                unused = lines[1].strip()
                print(f"✅ Loaded unused letters: {len(unused)} characters")
                return unused
            
            return ""
            
        except Exception as e:
            print(f"❌ Error loading unused letters: {e}")
            return ""
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy for validation"""
        if not data:
            return 0
        
        # Convert to bytes if string
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
    
    def precision_validate_decryption(self, data):
        """Precision-Aware validation with entropy threshold"""
        if not data or len(data) < 10:
            return False, 0.0
        
        # Entropy check: Valid plaintext typically 2.0-6.0 bits/char
        entropy = self.calculate_entropy(data)
        if entropy > 6.0:  # Too random
            return False, 0.0
        
        # ASCII ratio check
        printable_count = sum(1 for b in data if 32 <= b <= 126)
        ascii_ratio = printable_count / len(data)
        
        # Combined validation score
        entropy_score = max(0, 1.0 - abs(entropy - 4.0) / 4.0)  # Peak at entropy=4.0
        ascii_score = ascii_ratio
        
        combined_score = (entropy_score * 0.6 + ascii_score * 0.4)
        is_valid = combined_score > 0.5
        
        return is_valid, combined_score
    
    def generate_enhanced_password_candidates(self):
        """Generate password candidates using the AI framework insights"""
        candidates = []
        
        # Base passwords from previous success patterns
        base_passwords = [
            'SalPhaseIon',
            'CosmicDuality', 
            'matrixsumlistenter',
            'matrixsumlist',
            'thispassword',
            'enter',
            'causality',  # From Phase 2 success
        ]
        
        # Process unused letters as base10 signal vector (a=1...i=9,o=0)
        if self.unused_letters:
            frequency_analysis = Counter(self.unused_letters.replace(' ', ''))
            print(f"📊 Letter frequency analysis: {frequency_analysis.most_common(10)}")
            
            # Map letters to digits
            digit_mapping = {chr(ord('a') + i): str(i+1) for i in range(9)}
            digit_mapping['o'] = '0'
            
            # Generate digit sequences
            digit_sequence = ''.join(digit_mapping.get(letter, '') 
                                    for letter in self.unused_letters.replace(' ', ''))
            
            if digit_sequence:
                print(f"🔢 Digit sequence (first 100): {digit_sequence[:100]}...")
                
                # Try different chunk sizes and offsets
                for chunk_size in [2, 3, 4, 6, 8]:
                    for offset in [0, 1, 2]:
                        chunks = [digit_sequence[i+offset:i+offset+chunk_size] 
                                 for i in range(0, len(digit_sequence)-offset, chunk_size)]
                        
                        # Convert to hex/ascii candidates
                        try:
                            hex_candidate = ''.join(f"{int(chunk):02x}" if chunk.isdigit() and chunk else "00" 
                                                   for chunk in chunks[:20])  # Limit length
                            if len(hex_candidate) >= 8:  # Minimum reasonable length
                                base_passwords.append(hex_candidate)
                                
                        except ValueError:
                            continue
        
        # Enhanced variants with AI-identified patterns
        for base_pw in base_passwords:
            # Original
            candidates.append(base_pw)
            
            # With '\n' suffix (identified by AI as critical pattern)
            candidates.append(base_pw + '\n')
            candidates.append(base_pw + '\r\n')
            
            # Case variations
            candidates.append(base_pw.upper())
            candidates.append(base_pw.lower())
            
            # Hash variants (from previous phase success)
            candidates.append(hashlib.sha256(base_pw.encode()).hexdigest())
            candidates.append(hashlib.md5(base_pw.encode()).hexdigest())
            
        # Remove duplicates while preserving order
        unique_candidates = list(dict.fromkeys(candidates))
        print(f"🔑 Generated {len(unique_candidates)} password candidates")
        
        return unique_candidates
    
    def decrypt_aes_blob(self, blob, password):
        """Enhanced AES decryption with multiple methods"""
        if not blob or not password:
            return None
            
        try:
            # Method 1: OpenSSL format detection
            if blob.startswith(b'Salted__'):
                return self.decrypt_openssl_format(blob, password)
                
            # Method 2: Raw AES with PBKDF2 (successful in previous phases)
            return self.decrypt_pbkdf2_variants(blob, password)
            
        except Exception as e:
            return None
    
    def decrypt_openssl_format(self, blob, password):
        """OpenSSL format decryption"""
        if not blob.startswith(b'Salted__'):
            return None
            
        salt = blob[8:16]
        ciphertext = blob[16:]
        
        # OpenSSL key derivation
        key_iv = self.openssl_derive_key_iv(password.encode(), salt)
        key = key_iv[:32]
        iv = key_iv[32:48]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        
        # Remove PKCS7 padding
        if decrypted:
            padding_length = decrypted[-1]
            if 1 <= padding_length <= 16:
                decrypted = decrypted[:-padding_length]
                
        return decrypted
    
    def decrypt_pbkdf2_variants(self, blob, password):
        """PBKDF2 variants (successful method from previous phases)"""
        # Salt variants from previous success
        salt_variants = [
            hashlib.md5(b'matrixsumlist').digest(),  # Previous success
            b'SalPhaseIon',
            b'CosmicDuality',
            b'',  # Empty salt
            blob[:16] if len(blob) >= 16 else b'',  # First 16 bytes as salt
        ]
        
        iteration_counts = [10000, 1000, 100000]  # 10k was successful before
        
        for salt in salt_variants:
            for iterations in iteration_counts:
                try:
                    key = PBKDF2(password, salt, 32, count=iterations, hmac_hash_module=SHA256)
                    
                    # Try different IV approaches
                    iv_variants = [
                        blob[:16] if len(blob) >= 16 else b'\x00' * 16,
                        b'\x00' * 16,
                        hashlib.md5(password.encode()).digest(),
                    ]
                    
                    for iv in iv_variants:
                        if len(iv) == 16:
                            cipher = AES.new(key, AES.MODE_CBC, iv)
                            
                            # Try different ciphertext start positions
                            for start_pos in [0, 16]:
                                if start_pos < len(blob):
                                    ciphertext = blob[start_pos:]
                                    
                                    if len(ciphertext) % 16 == 0:
                                        decrypted = cipher.decrypt(ciphertext)
                                        
                                        # Try removing padding
                                        if decrypted and 1 <= decrypted[-1] <= 16:
                                            padding_length = decrypted[-1]
                                            test_decrypted = decrypted[:-padding_length]
                                            is_valid, score = self.precision_validate_decryption(test_decrypted)
                                            if is_valid:
                                                return test_decrypted
                                        
                                        # Try without padding removal
                                        is_valid, score = self.precision_validate_decryption(decrypted)
                                        if is_valid:
                                            return decrypted
                                            
                except Exception:
                    continue
        
        return None
    
    def openssl_derive_key_iv(self, password, salt):
        """OpenSSL key derivation (MD5 based)"""
        key_iv = b''
        prev = b''
        
        while len(key_iv) < 48:  # 32 bytes key + 16 bytes IV
            hasher = hashlib.md5()
            hasher.update(prev + password + salt)
            prev = hasher.digest()
            key_iv += prev
            
        return key_iv
    
    async def execute_capsule_reasoning(self):
        """Execute Capsule1 reasoning with auto-elevate capabilities"""
        print("🧠 Executing Capsule1: Enhanced AES Decryption")
        
        if not self.cosmic_duality_blob:
            print("❌ No blob data available")
            return None
        
        password_candidates = self.generate_enhanced_password_candidates()
        successful_decryptions = []
        
        print(f"🔄 Testing {len(password_candidates)} password candidates...")
        
        # Progress tracking
        for i, password in enumerate(password_candidates):
            if i % 50 == 0:
                print(f"Progress: {i}/{len(password_candidates)} ({i/len(password_candidates)*100:.1f}%)")
            
            decrypted = self.decrypt_aes_blob(self.cosmic_duality_blob, password)
            
            if decrypted:
                is_valid, score = self.precision_validate_decryption(decrypted)
                
                if is_valid:
                    # Calculate input checksum for validation
                    input_checksum = hashlib.sha256(f"{password}{len(decrypted)}".encode()).hexdigest()[:16]
                    
                    result = {
                        'password': password,
                        'decrypted_data': decrypted,
                        'validation_score': score,
                        'entropy': self.calculate_entropy(decrypted),
                        'length': len(decrypted),
                        'input_checksum': input_checksum
                    }
                    
                    successful_decryptions.append(result)
                    
                    print(f"✅ SUCCESS! Password: {password}")
                    print(f"   Validation score: {score:.3f}")
                    print(f"   Entropy: {result['entropy']:.2f} bits/char")
                    print(f"   Length: {len(decrypted)} bytes")
                    print(f"   Preview: {decrypted[:200]}")
                    print(f"   Checksum: {input_checksum}")
        
        # Save results
        if successful_decryptions:
            timestamp = int(time.time())
            
            for i, result in enumerate(successful_decryptions):
                filename = f"capsule1_success_{timestamp}_{i}.txt"
                with open(filename, 'wb') as f:
                    f.write(result['decrypted_data'])
                    
                print(f"💾 Saved result {i+1} to {filename}")
        
        return successful_decryptions

async def main():
    """Main execution with error correction tree"""
    try:
        capsule1 = UltraOmniCapsule1()
        results = await capsule1.execute_capsule_reasoning()
        
        if results:
            print(f"\n🎉 Capsule1 Complete: {len(results)} successful decryptions")
            
            # Update todo status
            print("✅ Capsule1 AES retry completed successfully")
            
        else:
            print("\n❌ No successful decryptions found")
            print("🔄 Error correction tree: Try Capsule2 (unused letter processing)")
            
    except Exception as e:
        print(f"❌ Capsule1 execution error: {e}")
        print("🔄 Rollback condition triggered")

if __name__ == "__main__":
    asyncio.run(main())
