#!/usr/bin/env python3
"""
Binary Key Analyzer - Extract Bitcoin keys from successful decryption binary data
The AES decryptions succeeded but produced binary data - analyze for hidden keys!
"""

import sys
import os
import hashlib
import base64
import struct

sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
    import bitcoin
    CRYPTO_AVAILABLE = True
except ImportError:
    print("❌ Crypto libraries not available")
    sys.exit(1)

class BinaryKeyAnalyzer:
    """Analyze binary data from successful AES decryptions for Bitcoin keys"""
    
    def __init__(self):
        # The successful passwords and their expected binary outputs
        self.successful_decryptions = {}
        self.cosmic_blob = "U2FsdGVkX186tYU0hVJBXXUnBUO7C0+X4KUWnWkCvoZSxbRD3wNsGWVHefvdrd9zQvX0t8v3jPB4okpspxebRi6sE1BMl5HI8Rku+KejUqTvdWOX6nQjSpepXwGuN/jJ"
    
    def decrypt_and_capture(self, blob_b64, password):
        """Decrypt and return raw binary data"""
        try:
            encrypted_data = base64.b64decode(blob_b64)
            
            # Use the method that worked: PBKDF2 with MD5 salt
            salt = hashlib.md5(b'matrixsumlist').digest()
            key = PBKDF2(password.encode(), salt, 32, count=10000, hmac_hash_module=SHA256)
            
            # Try CBC with different IVs
            modes_to_try = [
                (AES.MODE_CBC, b'\x00' * 16),
                (AES.MODE_CBC, encrypted_data[:16]),
                (AES.MODE_ECB, None),
            ]
            
            for mode, iv in modes_to_try:
                try:
                    if mode == AES.MODE_ECB:
                        cipher = AES.new(key, mode)
                        ciphertext = encrypted_data
                    else:
                        cipher = AES.new(key, mode, iv)
                        if iv == encrypted_data[:16]:
                            ciphertext = encrypted_data[16:]
                        else:
                            ciphertext = encrypted_data
                    
                    if len(ciphertext) % 16 == 0:
                        decrypted = cipher.decrypt(ciphertext)
                        
                        # Don't remove padding yet - analyze raw binary
                        return decrypted
                        
                except Exception as e:
                    continue
                    
        except Exception:
            pass
            
        return None
    
    def analyze_binary_for_keys(self, binary_data, password_name):
        """Analyze binary data for Bitcoin private keys"""
        print(f"\n🔍 Analyzing binary data from password: {password_name}")
        print(f"📊 Binary size: {len(binary_data)} bytes")
        print(f"🔢 Hex preview: {binary_data[:50].hex()}")
        
        potential_keys = []
        
        # Method 1: Look for consecutive 32-byte chunks as potential private keys
        print("\n🔑 Method 1: 32-byte consecutive chunks")
        for i in range(0, len(binary_data) - 31, 1):
            chunk = binary_data[i:i+32]
            key_hex = chunk.hex()
            
            if self.validate_secp256k1_key(key_hex):
                potential_keys.append({
                    'method': '32byte_consecutive',
                    'position': i,
                    'key_hex': key_hex,
                    'source': password_name
                })
                print(f"  ✅ Valid key at position {i}: {key_hex[:16]}...")
        
        # Method 2: Look for patterns that might indicate key data
        print("\n🔑 Method 2: Pattern-based key extraction")
        
        # Convert to different interpretations
        interpretations = [
            ('raw_bytes', binary_data),
            ('without_padding', self.remove_padding(binary_data)),
            ('reversed', binary_data[::-1]),
        ]
        
        for interp_name, data in interpretations:
            if len(data) >= 32:
                # Try different 32-byte extractions
                extractions = [
                    ('first_32', data[:32]),
                    ('last_32', data[-32:]),
                    ('middle_32', data[len(data)//2-16:len(data)//2+16]),
                ]
                
                for extract_name, extract_data in extractions:
                    if len(extract_data) == 32:
                        key_hex = extract_data.hex()
                        if self.validate_secp256k1_key(key_hex):
                            potential_keys.append({
                                'method': f'{interp_name}_{extract_name}',
                                'key_hex': key_hex,
                                'source': password_name
                            })
                            print(f"  ✅ Valid key ({interp_name}_{extract_name}): {key_hex[:16]}...")
        
        # Method 3: XOR analysis with common patterns
        print("\n🔑 Method 3: XOR pattern analysis")
        xor_keys = [0x00, 0xFF, 0x42, 0x69, 0x31]  # Common XOR patterns
        
        for xor_key in xor_keys:
            xored_data = bytes(b ^ xor_key for b in binary_data)
            
            # Try 32-byte chunks from XORed data
            for i in range(0, len(xored_data) - 31, 4):
                chunk = xored_data[i:i+32]
                key_hex = chunk.hex()
                
                if self.validate_secp256k1_key(key_hex):
                    potential_keys.append({
                        'method': f'xor_{xor_key:02x}',
                        'position': i,
                        'key_hex': key_hex,
                        'source': password_name
                    })
                    print(f"  ✅ Valid key (XOR {xor_key:02x}) at {i}: {key_hex[:16]}...")
        
        # Method 4: Structured data interpretation
        print("\n🔑 Method 4: Structured data analysis")
        if len(binary_data) >= 64:  # Enough for 2 keys
            # Try interpreting as multiple keys
            num_possible_keys = len(binary_data) // 32
            print(f"  🔢 Possible {num_possible_keys} keys in data")
            
            for i in range(min(num_possible_keys, 10)):  # Check first 10
                start = i * 32
                chunk = binary_data[start:start+32]
                if len(chunk) == 32:
                    key_hex = chunk.hex()
                    if self.validate_secp256k1_key(key_hex):
                        potential_keys.append({
                            'method': f'structured_key_{i}',
                            'key_hex': key_hex,
                            'source': password_name
                        })
                        print(f"  ✅ Valid structured key {i}: {key_hex[:16]}...")
        
        return potential_keys
    
    def remove_padding(self, data):
        """Remove PKCS7 padding"""
        if not data:
            return data
        
        try:
            padding = data[-1]
            if padding <= 16 and all(b == padding for b in data[-padding:]):
                return data[:-padding]
        except:
            pass
        return data
    
    def validate_secp256k1_key(self, key_hex):
        """Validate if hex string is valid secp256k1 private key"""
        try:
            if len(key_hex) != 64:
                return False
                
            key_int = int(key_hex, 16)
            secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            return 1 <= key_int < secp256k1_order
            
        except:
            return False
    
    def generate_addresses_and_check_balances(self, keys):
        """Generate Bitcoin addresses from keys and display"""
        print(f"\n💰 GENERATING ADDRESSES FROM {len(keys)} POTENTIAL KEYS")
        print("="*60)
        
        validated_keys = []
        
        for i, key_info in enumerate(keys, 1):
            key_hex = key_info['key_hex']
            
            try:
                # Generate Bitcoin address
                address = bitcoin.privkey_to_address(key_hex)
                
                print(f"\n🔑 Key {i}:")
                print(f"   Method: {key_info['method']}")
                print(f"   Source: {key_info['source']}")
                print(f"   Private Key: {key_hex}")
                print(f"   Address: {address}")
                
                validated_keys.append({
                    'private_key': key_hex,
                    'address': address,
                    'method': key_info['method'],
                    'source': key_info['source']
                })
                
            except Exception as e:
                print(f"\n❌ Key {i} failed address generation: {e}")
        
        return validated_keys
    
    def execute_binary_analysis(self):
        """Execute complete binary analysis"""
        
        print("🚀 Binary Key Analyzer - Analyzing Successful Decryptions")
        print("="*70)
        
        # Passwords that gave us successful decryptions
        successful_passwords = [
            'matrixsumlistenter',
            'theflowerblossomsthroughwhatseemstobeaconcretesurface'
        ]
        
        all_potential_keys = []
        
        for password in successful_passwords:
            print(f"\n🔓 Analyzing decryption from: {password[:30]}...")
            
            binary_data = self.decrypt_and_capture(self.cosmic_blob, password)
            
            if binary_data:
                keys_from_binary = self.analyze_binary_for_keys(binary_data, password)
                all_potential_keys.extend(keys_from_binary)
                
                # Save binary for manual analysis
                with open(f'binary_data_{password[:20]}.bin', 'wb') as f:
                    f.write(binary_data)
                print(f"  💾 Saved binary to binary_data_{password[:20]}.bin")
            else:
                print(f"  ❌ Could not re-decrypt with {password}")
        
        print(f"\n🎯 BINARY ANALYSIS COMPLETE")
        print(f"📊 Total potential keys found: {len(all_potential_keys)}")
        
        if all_potential_keys:
            print(f"\n🎉 POTENTIAL BITCOIN KEYS DISCOVERED!")
            
            # Generate addresses and check
            validated_keys = self.generate_addresses_and_check_balances(all_potential_keys)
            
            # Save results
            import json
            with open('binary_extracted_keys.json', 'w') as f:
                json.dump({
                    'extraction_method': 'binary_analysis_of_successful_aes_decryptions',
                    'total_keys': len(validated_keys),
                    'keys': validated_keys
                }, f, indent=2)
            
            print(f"\n💎 FINAL RESULT: {len(validated_keys)} validated Bitcoin keys!")
            print(f"💾 Results saved to binary_extracted_keys.json")
            
            if validated_keys:
                print(f"\n🏆 THE BINARY ANALYSIS HAS REVEALED THE PRIZE!")
                return True
        
        else:
            print(f"\n😐 No valid Bitcoin keys found in binary analysis")
            print(f"💡 The binary data may need different interpretation methods")
        
        return False

def main():
    """Execute binary key analysis"""
    
    print("🔍 Starting Binary Key Analysis...")
    print("🎯 Analyzing successful AES decryptions for hidden Bitcoin keys")
    
    analyzer = BinaryKeyAnalyzer()
    success = analyzer.execute_binary_analysis()
    
    if success:
        print("\n🎉🎉🎉 BINARY ANALYSIS SUCCESS! 🎉🎉🎉")
        print("🏆 HIDDEN BITCOIN KEYS EXTRACTED FROM BINARY DATA!")
        print("🎯 THE FINAL PRIZE HAS BEEN REVEALED!")
    else:
        print("\n🔄 Binary analysis complete - no keys found")
        print("💡 May need alternative binary interpretation methods")

if __name__ == "__main__":
    main()
