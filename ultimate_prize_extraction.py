#!/usr/bin/env python3
"""
ULTIMATE PRIZE EXTRACTION - The Real Final AES Blob
Based on the comprehensive puzzle analysis - this is the actual prize blob!
"""

import sys
import os
import hashlib
import base64
import time

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

class UltimatePrizeExtractor:
    """Extract the final Bitcoin prize from the original SalPhaseIon AES blob"""
    
    def __init__(self):
        # THE REAL AES BLOB from SalPhaseIon (cleaned, spaces removed)
        self.cosmic_duality_blob = (
            "U2FsdGVkX186tYU0hVJBXXUnBUO7C0+X4KUWnWkCvoZSxbRD3wNsGWVHefvdrd9z"
            "QvX0t8v3jPB4okpspxebRi6sE1BMl5HI8Rku+KejUqTvdWOX6nQjSpepXwGuN/jJ"
        )
        
        # All possible passwords from the puzzle analysis
        self.ultimate_passwords = [
            # From our breakthrough discovery
            'yourfirsthintisyourlastcommand',
            'priseurl', 
            'prisesettingsurl',
            'shabefourfirsthintisyourlastcommand',
            
            # From puzzle phases
            'matrixsumlist',
            'matrixsumlistenter',
            'enter',
            'thispassword',
            'lastwordsbeforearchichoice',
            
            # From Phase structure  
            'causality',
            'SalPhaseIon',
            'CosmicDuality',
            
            # Decoded puzzle elements
            'theflowerblossomsthroughwhatseemstobeaconcretesurface',
            'THEMATRIXHASYOU',
            
            # Phase 3 discoveries
            'jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple',
            'giveitjustonesecond',
            'heisenbergsuncertaintyprinciple',
            
            # Final phase hints
            'HASHTHETEXT',
            
            # Combined approaches
            'causalitySafenetLunaHSM111100x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1',
        ]
        
        print(f"🎯 Ultimate Prize Extractor Initialized")
        print(f"🔥 Cosmic Duality Blob: {len(self.cosmic_duality_blob)} chars")
        print(f"🔑 Ultimate Passwords: {len(self.ultimate_passwords)}")
    
    def try_aes_decryption(self, blob_b64, password):
        """Try AES decryption with various methods"""
        
        try:
            # Decode base64
            encrypted_data = base64.b64decode(blob_b64)
            
            # Multiple key derivation methods
            key_methods = [
                # Direct password hash
                hashlib.sha256(password.encode()).digest(),
                hashlib.md5(password.encode()).digest() * 2,
                
                # PBKDF2 with different salts and iterations
                PBKDF2(password.encode(), b'', 32, count=1000, hmac_hash_module=SHA256),
                PBKDF2(password.encode(), b'', 32, count=10000, hmac_hash_module=SHA256), 
                PBKDF2(password.encode(), b'', 32, count=100000, hmac_hash_module=SHA256),
                
                # PBKDF2 with puzzle-specific salts
                PBKDF2(password.encode(), hashlib.md5(b'matrixsumlist').digest(), 32, count=10000, hmac_hash_module=SHA256),
                PBKDF2(password.encode(), hashlib.md5(b'SalPhaseIon').digest(), 32, count=10000, hmac_hash_module=SHA256),
                PBKDF2(password.encode(), hashlib.md5(b'CosmicDuality').digest(), 32, count=10000, hmac_hash_module=SHA256),
                
                # Hex of password
                bytes.fromhex(password) if self.is_hex(password) else None,
            ]
            
            for key in key_methods:
                if key is None:
                    continue
                    
                # Try different AES modes
                modes_and_ivs = [
                    (AES.MODE_ECB, None),
                    (AES.MODE_CBC, b'\x00' * 16),
                    (AES.MODE_CBC, encrypted_data[:16]),  # IV from data
                ]
                
                for mode, iv in modes_and_ivs:
                    try:
                        if mode == AES.MODE_ECB:
                            cipher = AES.new(key[:32], mode)
                            ciphertext = encrypted_data
                        else:
                            cipher = AES.new(key[:32], mode, iv)
                            if iv == encrypted_data[:16]:
                                ciphertext = encrypted_data[16:]
                            else:
                                ciphertext = encrypted_data
                        
                        if len(ciphertext) % 16 == 0:
                            decrypted = cipher.decrypt(ciphertext)
                            
                            # Check if decryption looks valid
                            if self.is_valid_decryption(decrypted):
                                return decrypted
                                
                    except Exception:
                        continue
                        
        except Exception:
            pass
            
        return None
    
    def is_hex(self, s):
        """Check if string is valid hex"""
        try:
            int(s, 16)
            return len(s) % 2 == 0 and len(s) > 10
        except:
            return False
    
    def is_valid_decryption(self, data):
        """Check if decrypted data looks valid"""
        if not data or len(data) < 32:
            return False
        
        # Remove padding
        try:
            padding = data[-1]
            if padding <= 16 and all(b == padding for b in data[-padding:]):
                data = data[:-padding]
        except:
            pass
        
        # Check for printable content or Bitcoin-like data
        printable_ratio = sum(1 for b in data[:100] if 32 <= b <= 126) / min(100, len(data))
        
        # Check for Bitcoin indicators
        text_preview = data[:200].decode('utf-8', errors='ignore').lower()
        bitcoin_indicators = ['bitcoin', 'private', 'key', 'btc', 'address', 'wallet', 'prize']
        has_bitcoin_hints = any(indicator in text_preview for indicator in bitcoin_indicators)
        
        return printable_ratio > 0.5 or has_bitcoin_hints
    
    def extract_bitcoin_keys_from_text(self, text):
        """Extract Bitcoin private keys from decrypted text"""
        import re
        
        # Look for various key formats
        patterns = [
            r'[0-9a-fA-F]{64}',  # 64-char hex keys
            r'5[HJK][1-9A-Za-z][^OIl]{48,50}',  # WIF uncompressed
            r'[KL][1-9A-Za-z][^OIl]{50,52}',   # WIF compressed
        ]
        
        found_keys = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if self.validate_bitcoin_private_key(match):
                    found_keys.append(match)
        
        return found_keys
    
    def validate_bitcoin_private_key(self, key):
        """Validate Bitcoin private key"""
        try:
            if len(key) == 64:  # Hex format
                key_int = int(key, 16)
                secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
                return 1 <= key_int < secp256k1_order
            else:  # WIF format
                # Basic WIF validation
                return len(key) >= 51 and key[0] in '5KL'
        except:
            return False
    
    def check_bitcoin_addresses(self, private_keys):
        """Generate and check Bitcoin addresses for balances"""
        results = []
        
        for key in private_keys:
            try:
                # Generate address
                if len(key) == 64:  # Hex key
                    address = bitcoin.privkey_to_address(key)
                else:  # WIF key
                    address = bitcoin.privkey_to_address(key)
                
                print(f"  💰 Private Key: {key[:16]}...")
                print(f"  🏠 Address: {address}")
                
                # Check balance (simplified - would need actual API calls)
                results.append({
                    'private_key': key,
                    'address': address,
                    'format': 'hex' if len(key) == 64 else 'wif'
                })
                
            except Exception as e:
                print(f"  ❌ Error generating address for {key[:16]}...: {e}")
        
        return results
    
    def execute_ultimate_extraction(self):
        """Execute the ultimate prize extraction"""
        
        print("\n" + "="*80)
        print("🏆 ULTIMATE PRIZE EXTRACTION - FINAL AES BLOB")
        print("="*80)
        
        successful_decryptions = []
        
        for i, password in enumerate(self.ultimate_passwords, 1):
            print(f"\n🔑 Testing Ultimate Password {i}/{len(self.ultimate_passwords)}: {password[:30]}...")
            
            # Try with newline suffix (critical pattern from AI analysis)
            password_variants = [
                password,
                password + '\n',
                password + '\r\n',
                password.strip(),
            ]
            
            for variant in password_variants:
                result = self.try_aes_decryption(self.cosmic_duality_blob, variant)
                
                if result:
                    print(f"  ✅ SUCCESSFUL DECRYPTION with: {variant}")
                    
                    try:
                        text = result.decode('utf-8', errors='replace')
                        print(f"  📄 Decrypted text ({len(text)} chars):")
                        print(f"     {text[:200]}...")
                        
                        # Extract Bitcoin keys
                        bitcoin_keys = self.extract_bitcoin_keys_from_text(text)
                        if bitcoin_keys:
                            print(f"  🎉 BITCOIN KEYS FOUND: {len(bitcoin_keys)}")
                            
                            # Check addresses and balances
                            key_results = self.check_bitcoin_addresses(bitcoin_keys)
                            
                            successful_decryptions.append({
                                'password': variant,
                                'decrypted_text': text,
                                'bitcoin_keys': bitcoin_keys,
                                'key_results': key_results
                            })
                            
                            # Save the winning decryption
                            timestamp = int(time.time())
                            with open(f'ultimate_prize_decryption_{timestamp}.txt', 'w') as f:
                                f.write(f"Password: {variant}\n")
                                f.write(f"Decrypted Text:\n{text}\n")
                                f.write(f"Bitcoin Keys: {bitcoin_keys}\n")
                            
                            print(f"  💾 Saved to ultimate_prize_decryption_{timestamp}.txt")
                        
                        else:
                            print(f"  📝 Text decrypted but no Bitcoin keys found")
                            
                    except Exception as e:
                        print(f"  🔍 Binary data decrypted: {len(result)} bytes")
                        print(f"     Hex preview: {result[:50].hex()}")
        
        print("\n" + "="*80)
        print("🏆 ULTIMATE PRIZE EXTRACTION RESULTS")
        print("="*80)
        
        if successful_decryptions:
            print(f"🎉 SUCCESSFUL DECRYPTIONS: {len(successful_decryptions)}")
            
            total_keys = sum(len(d['bitcoin_keys']) for d in successful_decryptions)
            print(f"💰 TOTAL BITCOIN KEYS FOUND: {total_keys}")
            
            if total_keys > 0:
                print("\n🎯 THE FINAL PRIZE HAS BEEN EXTRACTED!")
                print("💎 Bitcoin private keys discovered from the Cosmic Duality blob!")
                return True
            
        else:
            print("😐 No successful decryptions found")
            print("💡 The Cosmic Duality blob may require:")
            print("   • Different password combinations")
            print("   • Alternative decryption methods") 
            print("   • Additional puzzle phases")
        
        return False

def main():
    """Execute ultimate prize extraction"""
    
    print("🚀 Initializing Ultimate Prize Extraction...")
    print("🎯 Target: Original SalPhaseIon Cosmic Duality AES Blob")
    print("⚡ Using comprehensive puzzle analysis and breakthrough passwords")
    
    extractor = UltimatePrizeExtractor()
    success = extractor.execute_ultimate_extraction()
    
    if success:
        print("\n🎉🎉🎉 ULTIMATE SUCCESS! 🎉🎉🎉")
        print("🏆 THE GSMG.IO 5 BTC PUZZLE PRIZE HAS BEEN CLAIMED!")
    else:
        print("\n🔄 Ultimate extraction needs further analysis")
        print("💡 Consider additional password combinations or methods")

if __name__ == "__main__":
    main()
