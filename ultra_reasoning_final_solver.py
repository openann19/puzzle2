#!/usr/bin/env python3
"""
Ultra Reasoning Final Solver - Implementing the advanced AI reasoning patterns
Following the exact framework from the rules
"""

import sys
import os
import hashlib
import base64
import time
from collections import Counter

sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
    import bitcoin
    CRYPTO_AVAILABLE = True
except ImportError as e:
    print(f"❌ Crypto not available: {e}")
    sys.exit(1)

class UltraReasoningFinalSolver:
    """Implementation of the Ultra-Advanced AI Reasoning Patterns"""
    
    def __init__(self):
        self.prize_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
        self.entropy_threshold = 4.5
        
        # Load puzzle state
        self.puzzle_state = self.load_puzzle_state()
        
    def load_puzzle_state(self):
        """Load current puzzle state from our files"""
        try:
            with open('SalPhaseIon.md', 'r') as f:
                salphaseion_content = f.read()
                
            # Extract unused letters (we need to identify these from the content)
            # From our previous analysis, the unused letters came from decoding
            unused_letters = self.extract_unused_letters_from_salphaseion(salphaseion_content)
            
            # Extract cleaned Cosmic Duality blob
            cosmic_blob = self.extract_cleaned_cosmic_blob(salphaseion_content)
            
            return {
                'unused_letters': unused_letters,
                'cosmic_duality_blob': cosmic_blob,
                'salphaseion_hash': '89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32',
                'successful_passwords': ['matrixsumlist', 'enter', 'lastwordsbeforearchichoice', 'thispassword']
            }
        except Exception as e:
            print(f"❌ Error loading puzzle state: {e}")
            return {}
    
    def extract_unused_letters_from_salphaseion(self, content):
        """Extract unused letters from SalPhaseIon content"""
        # From our analysis, we know there are segments with letters a-i and o
        # Let me extract the letter sequences we identified before
        
        # Look for the segments between 'z' separators
        segments = content.split('z')
        unused_letters = ""
        
        for segment in segments:
            # Extract letters that are a-i and o (the unused ones)
            letters_only = ''.join(c for c in segment if c in 'abcdefghio')
            unused_letters += letters_only
            
        # If we can't find them in the file, use the ones we know from previous analysis
        if len(unused_letters) < 100:  # Sanity check
            # From our GitHub analysis, we know these patterns exist
            unused_letters = "agdafaoaheiecggchgicbbhcgbehcfcoabicfdhh" + \
                           "cdbcagbdaiobgbeadeddecfofdghdobdgooiigdocdaoofidh"
        
        print(f"📊 Extracted {len(unused_letters)} unused letters")
        return unused_letters
    
    def extract_cleaned_cosmic_blob(self, content):
        """Extract and clean the Cosmic Duality AES blob"""
        # Find the AES blob in the content
        lines = content.split('\n')
        blob_lines = []
        in_blob = False
        
        for line in lines:
            if 'U2FsdGVkX1' in line:  # Start of base64 blob
                in_blob = True
            if in_blob:
                # Clean: remove spaces and keep only valid base64 characters
                cleaned = ''.join(c for c in line if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
                if cleaned:
                    blob_lines.append(cleaned)
                if line.strip() and not cleaned:  # End of blob
                    break
        
        return ''.join(blob_lines)
    
    def generate_enhanced_password_candidates(self):
        """Generate enhanced password candidates using AI reasoning patterns"""
        
        print("🧠 GENERATING ENHANCED PASSWORD CANDIDATES")
        print("="*60)
        
        unused_letters = self.puzzle_state.get('unused_letters', '')
        
        # Step 1: Frequency analysis
        frequency_analysis = Counter(unused_letters)
        high_freq_letters = [letter for letter, count in frequency_analysis.most_common(10)]
        
        print(f"📊 Letter frequency analysis:")
        for letter, count in frequency_analysis.most_common(10):
            print(f"   {letter}: {count} times")
        
        # Step 2: Base10 digit mapping (critical AI insight)
        digit_mapping = {chr(ord('a') + i): str(i+1) for i in range(9)}
        digit_mapping['o'] = '0'
        
        print(f"🔢 Base10 mapping: {digit_mapping}")
        
        # Step 3: Generate digit sequence
        digit_sequence = ''.join(digit_mapping.get(letter, '') for letter in unused_letters)
        print(f"📈 Digit sequence: {digit_sequence[:100]}...")
        print(f"   Length: {len(digit_sequence)} digits")
        
        # Step 4: Enhanced candidate generation
        base_candidates = []
        
        # Chunk and convert with different sizes and offsets
        for chunk_size in [2, 3, 4]:
            for offset in [0, 1, 2]:
                if offset >= len(digit_sequence):
                    continue
                    
                chunks = [digit_sequence[i+offset:i+offset+chunk_size] 
                         for i in range(0, len(digit_sequence)-offset-chunk_size+1, chunk_size)]
                
                # ASCII conversion
                try:
                    ascii_result = ''.join(chr(int(chunk)) for chunk in chunks if chunk.isdigit() and 32 <= int(chunk) <= 126)
                    if len(ascii_result) >= 5:  # Minimum useful length
                        base_candidates.append(f"ascii_c{chunk_size}_o{offset}:" + ascii_result)
                except:
                    pass
                
                # Hex conversion  
                try:
                    hex_result = ''.join(f"{int(chunk):02x}" if chunk.isdigit() else "00" 
                                        for chunk in chunks[:32])  # Limit to 32 chunks = 64 chars
                    if len(hex_result) >= 10:
                        base_candidates.append(f"hex_c{chunk_size}_o{offset}:" + hex_result)
                except:
                    pass
        
        # Step 5: Apply enhancement patterns (Critical AI insights)
        enhanced_candidates = []
        
        # Add successful passwords from previous analysis
        successful_base = self.puzzle_state.get('successful_passwords', [])
        enhanced_candidates.extend(successful_base)
        
        for candidate in base_candidates:
            # Extract the actual candidate part
            if ':' in candidate:
                method, actual_candidate = candidate.split(':', 1)
            else:
                actual_candidate = candidate
                method = 'direct'
            
            # Original
            enhanced_candidates.append(actual_candidate)
            
            # With '\n' suffix (CRITICAL AI DISCOVERY)
            enhanced_candidates.append(actual_candidate + '\n')
            enhanced_candidates.append(actual_candidate + '\r\n')
            
            # With other suffixes
            for suffix in ['enter', '123', '!', '']:
                enhanced_candidates.append(actual_candidate + suffix)
            
            # Hash variants
            enhanced_candidates.append(hashlib.sha256(actual_candidate.encode()).hexdigest())
            enhanced_candidates.append(hashlib.md5(actual_candidate.encode()).hexdigest())
            
            # Combined with SalPhaseIon hash
            salphaseion_hash = self.puzzle_state.get('salphaseion_hash', '')
            enhanced_candidates.append(actual_candidate + salphaseion_hash)
            enhanced_candidates.append(hashlib.sha256((actual_candidate + salphaseion_hash).encode()).hexdigest())
        
        # Remove duplicates while preserving order
        seen = set()
        unique_candidates = []
        for candidate in enhanced_candidates:
            if candidate not in seen and len(candidate) >= 3:
                seen.add(candidate)
                unique_candidates.append(candidate)
        
        print(f"🎯 Generated {len(unique_candidates)} enhanced password candidates")
        return unique_candidates
    
    def execute_optimized_aes_retry(self, candidates):
        """Execute AES retry with optimized sequence"""
        
        print(f"\n🔄 EXECUTING OPTIMIZED AES RETRY")
        print("="*50)
        
        cosmic_blob = self.puzzle_state.get('cosmic_duality_blob', '')
        if not cosmic_blob:
            print("❌ No cosmic blob found")
            return []
        
        # Clean blob (CRITICAL: remove spaces)
        cleaned_blob = cosmic_blob.replace(' ', '').strip()
        
        print(f"📦 AES blob length: {len(cleaned_blob)} chars")
        
        successful_decryptions = []
        
        for i, password in enumerate(candidates[:200]):  # Limit to prevent excessive runtime
            if i % 20 == 0:
                print(f"  Testing password {i+1}/{min(200, len(candidates))}...")
            
            try:
                # Try AES decryption
                decrypted = self.try_aes_decrypt(cleaned_blob, password)
                
                if decrypted:
                    # Entropy check (>4.5 indicates invalid plaintext)
                    entropy = self.calculate_entropy(decrypted)
                    
                    if entropy <= self.entropy_threshold:
                        print(f"✅ Successful decryption with: {password[:50]}...")
                        print(f"   Entropy: {entropy:.2f} bits/char")
                        print(f"   Data length: {len(decrypted)} bytes")
                        
                        successful_decryptions.append({
                            'password': password,
                            'decrypted_data': decrypted,
                            'entropy': entropy,
                            'data_length': len(decrypted)
                        })
                        
                        # Save the decrypted data
                        filename = f"ultra_decryption_{int(time.time())}.bin"
                        with open(filename, 'wb') as f:
                            f.write(decrypted)
                        print(f"💾 Saved to: {filename}")
            
            except Exception as e:
                pass  # Continue with next password
        
        return successful_decryptions
    
    def try_aes_decrypt(self, blob_b64, password):
        """Try AES decryption with a password"""
        try:
            # Decode base64
            encrypted_data = base64.b64decode(blob_b64)
            
            # Extract salt (first 8 bytes after 'Salted__')
            if encrypted_data.startswith(b'Salted__'):
                salt = encrypted_data[8:16]
                encrypted = encrypted_data[16:]
            else:
                # Try without salt prefix
                salt = b'\x00' * 8
                encrypted = encrypted_data
            
            # Derive key and IV using PBKDF2 (like OpenSSL does)
            key_iv = PBKDF2(password.encode(), salt, 48, count=1000, hmac_hash_module=SHA256)
            key = key_iv[:32]
            iv = key_iv[32:48]
            
            # Decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted)
            
            # Remove PKCS7 padding
            padding_len = decrypted[-1] if len(decrypted) > 0 else 0
            if 0 < padding_len <= 16:
                decrypted = decrypted[:-padding_len]
            
            return decrypted
            
        except Exception:
            return None
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy"""
        if not data:
            return 0
            
        if isinstance(data, bytes):
            byte_counts = Counter(data)
            data_len = len(data)
        else:
            byte_counts = Counter(data.encode())
            data_len = len(data.encode())
        
        entropy = 0
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def analyze_decrypted_data_for_keys(self, successful_decryptions):
        """Analyze decrypted data for Bitcoin private keys"""
        
        print(f"\n🔍 ANALYZING DECRYPTED DATA FOR BITCOIN KEYS")
        print("="*60)
        
        all_keys = []
        
        for decryption in successful_decryptions:
            data = decryption['decrypted_data']
            password = decryption['password']
            
            print(f"📊 Analyzing {len(data)}-byte decryption from: {password[:30]}...")
            
            # Extract all possible 32-byte keys
            keys_found = []
            for i in range(len(data) - 31):
                key_bytes = data[i:i+32]
                key_hex = key_bytes.hex()
                
                if self.is_valid_private_key(key_hex):
                    try:
                        address = bitcoin.privkey_to_address(key_hex)
                        keys_found.append({
                            'private_key': key_hex,
                            'address': address,
                            'position': i,
                            'source_password': password
                        })
                        
                        # Check if this is the prize address!
                        if address == self.prize_address:
                            print(f"\n🎉🎉🎉 PRIZE PRIVATE KEY FOUND! 🎉🎉🎉")
                            print(f"🔑 Private Key: {key_hex}")
                            print(f"🏠 Address: {address}")
                            print(f"📍 Position: {i} in decrypted data")
                            print(f"🗝️ Source Password: {password}")
                            
                            # Save the solution
                            solution = {
                                'PUZZLE_STATUS': 'COMPLETELY SOLVED!',
                                'PRIZE_ADDRESS': self.prize_address,
                                'PRIVATE_KEY': key_hex,
                                'ADDRESS_MATCH': address,
                                'POSITION_IN_DATA': i,
                                'SOURCE_PASSWORD': password,
                                'DECRYPTION_METHOD': 'Ultra Reasoning Framework',
                                'SUCCESS': True
                            }
                            
                            with open('ULTRA_REASONING_SOLUTION.json', 'w') as f:
                                import json
                                json.dump(solution, f, indent=2)
                            
                            print(f"💾 Solution saved: ULTRA_REASONING_SOLUTION.json")
                            return True
                    
                    except Exception:
                        pass
            
            print(f"   Found {len(keys_found)} valid private keys")
            all_keys.extend(keys_found)
        
        print(f"\n📊 Total valid private keys found: {len(all_keys)}")
        return False
    
    def is_valid_private_key(self, key_hex):
        """Check if private key is valid"""
        try:
            key_int = int(key_hex, 16)
            secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            return 1 <= key_int < secp256k1_order
        except:
            return False
    
    def execute_ultra_reasoning_framework(self):
        """Execute the complete Ultra Reasoning Framework"""
        
        print("🚀 ULTRA REASONING FRAMEWORK v3.0")
        print("="*70)
        print("Following Advanced AI Reasoning Patterns for Final Solution")
        print()
        
        # Step 1: Generate enhanced password candidates
        candidates = self.generate_enhanced_password_candidates()
        
        # Step 2: Execute optimized AES retry sequence  
        successful_decryptions = self.execute_optimized_aes_retry(candidates)
        
        if not successful_decryptions:
            print("\n❌ No successful AES decryptions found")
            return False
        
        print(f"\n✅ Found {len(successful_decryptions)} successful decryptions")
        
        # Step 3: Analyze decrypted data for Bitcoin keys
        success = self.analyze_decrypted_data_for_keys(successful_decryptions)
        
        return success

def main():
    """Main execution"""
    solver = UltraReasoningFinalSolver()
    success = solver.execute_ultra_reasoning_framework()
    
    if success:
        print(f"\n🏆🏆🏆 GSMG.IO PUZZLE SOLVED WITH ULTRA REASONING! 🏆🏆🏆")
        print(f"🎊 Advanced AI reasoning patterns successfully identified the solution!")
    else:
        print(f"\n🔄 Ultra reasoning framework executed - continue with additional analysis")

if __name__ == "__main__":
    main()
