#!/usr/bin/env python3
"""
SalPhaseIon Final Decryption - Using the derived hash to decrypt the final AES blob
This should lead us to the actual private key for the prize address
"""

import sys
import hashlib
import base64

sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
    import bitcoin
    CRYPTO_AVAILABLE = True
except ImportError as e:
    print(f"❌ Crypto import error: {e}")
    sys.exit(1)

class SalPhaseionFinalDecryption:
    def __init__(self):
        self.prize_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
        # The hash derived from GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe
        self.salphaseion_key = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
        
        # The final AES blob from SalPhaseIon (from the GitHub documentation)
        self.final_aes_blob = (
            "U2FsdGVkX186tYU0hVJBXXUnBUO7C0+X4KUWnWkCvoZSxbRD3wNsGWVHefvdrd9z"
            "QvX0t8v3jPB4okpspxebRi6sE1BMl5HI8Rku+KejUqTvdWOX6nQjSpepXwGuN/jJ"
        )
        
    def try_openssl_style_decryption(self, blob_data, password):
        """Try OpenSSL-style AES decryption with the given password"""
        try:
            # Remove spaces and clean the base64 data
            clean_blob = blob_data.replace(' ', '').replace('\n', '')
            encrypted_data = base64.b64decode(clean_blob)
            
            # OpenSSL format: "Salted__" + 8 bytes salt + encrypted data
            if encrypted_data[:8] != b'Salted__':
                print(f"⚠️  Not in OpenSSL format")
                return None
                
            salt = encrypted_data[8:16]
            ciphertext = encrypted_data[16:]
            
            # Derive key and IV using EVP_BytesToKey algorithm (like OpenSSL)
            key_iv = self.evp_bytes_to_key(password.encode(), salt, 48)  # 32 bytes key + 16 bytes IV
            key = key_iv[:32]
            iv = key_iv[32:48]
            
            # Decrypt using AES-256-CBC
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            
            # Remove PKCS7 padding
            padding_length = decrypted[-1]
            decrypted = decrypted[:-padding_length]
            
            return decrypted
            
        except Exception as e:
            print(f"Decryption error with {password}: {e}")
            return None
    
    def evp_bytes_to_key(self, password, salt, key_len):
        """Implement OpenSSL's EVP_BytesToKey algorithm"""
        d = d_i = b''
        while len(d) < key_len:
            d_i = hashlib.md5(d_i + password + salt).digest()
            d += d_i
        return d[:key_len]
    
    def analyze_decrypted_data_for_private_key(self, data):
        """Analyze decrypted data for potential Bitcoin private keys"""
        if not data:
            return []
            
        potential_keys = []
        
        # Try to interpret as text first
        try:
            text = data.decode('utf-8', errors='ignore')
            print(f"📝 Decrypted text preview: {text[:200]}...")
            
            # Look for hex patterns that could be private keys
            import re
            hex_patterns = re.findall(r'\b[a-fA-F0-9]{64}\b', text)
            for hex_key in hex_patterns:
                potential_keys.append(hex_key.lower())
                
        except:
            pass
        
        # Try to extract 32-byte sequences as potential private keys
        hex_data = data.hex()
        for i in range(0, len(hex_data) - 64, 2):  # Step by 2 (1 byte)
            potential_key = hex_data[i:i+64]
            potential_keys.append(potential_key)
            
        return potential_keys
    
    def test_private_key_for_prize_address(self, private_key_hex):
        """Test if a private key generates the prize address"""
        try:
            if len(private_key_hex) != 64:
                return False
                
            # Validate key is in secp256k1 range
            key_int = int(private_key_hex, 16)
            secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            
            if not (1 <= key_int < secp256k1_order):
                return False
                
            # Generate address
            generated_address = bitcoin.privkey_to_address(private_key_hex)
            
            if generated_address == self.prize_address:
                print(f"\n🎉🎉🎉 PRIZE PRIVATE KEY FOUND! 🎉🎉🎉")
                print(f"🔑 Private Key: {private_key_hex}")
                print(f"🏠 Prize Address: {self.prize_address}")
                print(f"✅ Address Match: {generated_address}")
                
                # Save the result
                import json
                result = {
                    'PUZZLE_STATUS': 'COMPLETELY SOLVED',
                    'PRIZE_ADDRESS': self.prize_address,
                    'PRIVATE_KEY': private_key_hex,
                    'DERIVATION_METHOD': 'SalPhaseIon AES decryption with derived hash',
                    'SALPHASEION_PASSWORD': self.salphaseion_key,
                    'BLOCKCHAIN_EXPLORER': f'https://blockchain.com/explorer/addresses/btc/{self.prize_address}',
                    'INSTRUCTIONS': 'Import the private key into a Bitcoin wallet to claim the prize'
                }
                
                with open('PRIZE_PRIVATE_KEY_FOUND.json', 'w') as f:
                    json.dump(result, f, indent=2)
                    
                print(f"💾 Solution saved to: PRIZE_PRIVATE_KEY_FOUND.json")
                return True
                
            return False
            
        except Exception as e:
            return False
    
    def execute_final_decryption(self):
        """Execute the final SalPhaseIon decryption to find the prize private key"""
        
        print("🚀 SALPHASEION FINAL DECRYPTION")
        print("="*60)
        print(f"🎯 Target Prize Address: {self.prize_address}")
        print(f"🔑 SalPhaseIon Password: {self.salphaseion_key}")
        print("")
        
        # Try decryption with the derived hash
        print("🔓 Attempting AES decryption of final blob...")
        decrypted_data = self.try_openssl_style_decryption(self.final_aes_blob, self.salphaseion_key)
        
        if decrypted_data:
            print("✅ AES decryption successful!")
            print(f"📊 Decrypted data length: {len(decrypted_data)} bytes")
            
            # Analyze for private keys
            potential_keys = self.analyze_decrypted_data_for_private_key(decrypted_data)
            print(f"🔍 Found {len(potential_keys)} potential private keys to test")
            
            # Test each potential key
            for i, key in enumerate(potential_keys[:50]):  # Test first 50 to avoid infinite loop
                if self.test_private_key_for_prize_address(key):
                    print(f"\n🏆 SUCCESS! Prize private key found at position {i}")
                    return True
                    
            print("❌ No matching private keys found in decrypted data")
            
            # Try other password variations
            print("\n🔄 Trying password variations...")
            password_variations = [
                self.salphaseion_key,
                self.salphaseion_key + "enter",
                "matrixsumlist" + self.salphaseion_key,
                "lastwordsbeforeaichocice" + self.salphaseion_key,
                "thispassword" + self.salphaseion_key
            ]
            
            for password in password_variations:
                print(f"🔓 Trying password variation: {password[:20]}...")
                alt_data = self.try_openssl_style_decryption(self.final_aes_blob, password)
                if alt_data and alt_data != decrypted_data:
                    print("✅ Alternative decryption successful!")
                    alt_keys = self.analyze_decrypted_data_for_private_key(alt_data)
                    for key in alt_keys[:20]:
                        if self.test_private_key_for_prize_address(key):
                            print(f"🏆 SUCCESS with password variation!")
                            return True
            
            return False
        else:
            print("❌ AES decryption failed")
            return False

def main():
    print("🎯 Starting SalPhaseIon Final Decryption")
    print("")
    
    decryptor = SalPhaseionFinalDecryption()
    success = decryptor.execute_final_decryption()
    
    if success:
        print("\n🎊🎊🎊 ULTIMATE VICTORY! 🎊🎊🎊")
        print("🔑 PRIVATE KEY FOR GSMG.IO PRIZE ADDRESS FOUND!")
        print("💰 READY TO CLAIM THE BITCOIN PRIZE!")
    else:
        print("\n🔄 Analysis complete - may need additional puzzle phases")

if __name__ == "__main__":
    main()
