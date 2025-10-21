#!/usr/bin/env python3
"""
Cosmic Duality Final Decryption - Using the derived SalPhaseIon hash
to decrypt the actual Cosmic Duality blob for the prize private key
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

class CosmicDualityDecryptor:
    def __init__(self):
        self.prize_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
        # The derived SalPhaseIon hash
        self.salphaseion_password = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
        
        # The actual Cosmic Duality blob from SalPhaseIon.md
        self.cosmic_duality_blob = """U2FsdGVkX18tP2/gbclQ5tNZuD4shoV3axuUd8J8aycGCAMoYfhZK0JecHTDpTFe
dGJh4SJIP66qRtXvo7PTpvsIjwO8prLiC/sNHthxiGMuqIrKoO224rOisFJZgARi
c7PaJPne4nab8XCFuV3NbfxGX2BUjNkef5hg7nsoadZx08dNyU2b6eiciWiUvu7D
SATSFO7IFBiAMz7dDqIETKuGlTAP4EmMQUZrQNtfbJsURATW6V5VSbtZB5RFk0O+
IymhstzrQHsU0Bugjv2nndmOEhCxGi/lqK2rLNdOOLutYGnA6RDDbFJUattggELh
2SZx+SBpCdbSGjxOap27l9FOyl02r0HU6UxFdcsbfZ1utTqVEyNs91emQxtpgt+6
BPZisil74Jv4EmrpRDC3ufnkmWwR8NfqVPIKhUiGDu5QflYjczT6DrA9vLQZu3ko
k+/ZurtRYnqqsj49UhwEF9GfUfl7uQYm0UunatW43C3Z1tyFRGAzAHQUFS6jRCd+
vZGyoTlOsThjXDDCSAwoX2M+yM+oaEQoVvDwVkIqRhfDNuBmEfi+HpXuJLPBS1Pb
UjrgoG/Uv7o8IeyST4HBv8+5KLx7IKQS8f1kPZ2YUME+8XJx0caFYs+JS2Jdm0oj
Jm3JJEcYXdKEzOQvRzi4k+6dNlJ05TRZNTJvn0fPG5cM80aQb/ckUHsLsw9a4Wzh
HsrzBQRTIhog9sTm+k+LkXzIJiFfSzRgf250pbviFGoQaIFl1CTQPT2w29DLP900
6bSiliywwnxXOor03Hn+7MJL27YxeaGQn0sFGgP5X0X4jm3vEBkWvtF4PZl0bXWZ
LvVL/zTn87+2Zi/u7LA6y6b2yt7YVMkpheeOL0japXaiAf3bSPeUPGz/eu8ZX/Nn
O3259hG1XwoEVcGdDBV0Nh0A4/phPCR0x5BG04U0OeWAT/5Udc/gGM0TT2FrEzs/
AJKtmsnj31OSsqWb9wD+CoduYY2JrkzJYihE3ZcgcvqqffZXqxQkaI/83ro6JZ4P
ubml0PUnAnkdmnBCpbClbZMzmo3ELZ0EQwsvkJFDMQmiRhda4nBooUW7zXOIb7Wx
bE9THrt3cdZP5uAgVfgguUNE4fZMN8ATEDhdSsLklJe2GvihKuZVA6uuSkWAsK6u
MGo76xpPwYs3eUdLjtANS83a6/F/fhkX1GXs7zbQjh+Inzk8jhEdEogl9jPs/oDj
KjbkUpFlsCWwAZGoeKlmX7c4OGuD5c+FEH+2nYHvYl8y1E/K5SDt9Uocio8XuxbD
ZOzhw7LMSGkD1MZxpDzsCZY1emkSNd88NFj+9U8VssIDDVMYwKMsHKfjc0x5OlzQ"""
        
    def try_openssl_aes_decrypt(self, password):
        """Try OpenSSL-style AES-256-CBC decryption with PBKDF2"""
        try:
            # Clean the base64 blob
            clean_blob = self.cosmic_duality_blob.replace('\n', '').replace(' ', '')
            encrypted_data = base64.b64decode(clean_blob)
            
            # Check for "Salted__" prefix
            if encrypted_data[:8] != b'Salted__':
                print("❌ Not in OpenSSL Salted format")
                return None
                
            salt = encrypted_data[8:16]
            ciphertext = encrypted_data[16:]
            
            print(f"🧂 Salt: {salt.hex()}")
            print(f"📊 Ciphertext length: {len(ciphertext)} bytes")
            
            # Try different key derivation methods
            methods = [
                ("EVP_BytesToKey (OpenSSL)", self.evp_bytes_to_key),
                ("PBKDF2-SHA256-10000", lambda p, s: PBKDF2(p, s, 48, count=10000, hmac_hash_module=SHA256)),
                ("PBKDF2-SHA256-1000", lambda p, s: PBKDF2(p, s, 48, count=1000, hmac_hash_module=SHA256)),
                ("Direct SHA256", lambda p, s: hashlib.sha256(p + s).digest()[:48])
            ]
            
            for method_name, key_func in methods:
                try:
                    print(f"🔑 Trying {method_name}...")
                    
                    if method_name.startswith("Direct"):
                        # For direct SHA256, pad to 48 bytes
                        key_material = key_func(password.encode(), salt)
                        while len(key_material) < 48:
                            key_material += hashlib.sha256(key_material).digest()
                        key_material = key_material[:48]
                    else:
                        key_material = key_func(password.encode(), salt)
                    
                    key = key_material[:32]
                    iv = key_material[32:48]
                    
                    # Decrypt
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted = cipher.decrypt(ciphertext)
                    
                    # Remove padding
                    padding_length = decrypted[-1]
                    if padding_length <= 16:  # Valid padding
                        decrypted = decrypted[:-padding_length]
                        
                        print(f"✅ {method_name} decryption successful!")
                        print(f"📊 Decrypted data length: {len(decrypted)} bytes")
                        return decrypted
                    
                except Exception as e:
                    print(f"❌ {method_name} failed: {str(e)[:50]}...")
                    
            return None
            
        except Exception as e:
            print(f"❌ General decryption error: {e}")
            return None
    
    def evp_bytes_to_key(self, password, salt):
        """OpenSSL's EVP_BytesToKey algorithm using MD5"""
        d = d_i = b''
        while len(d) < 48:
            d_i = hashlib.md5(d_i + password + salt).digest()
            d += d_i
        return d[:48]
    
    def analyze_for_private_keys(self, data):
        """Comprehensive analysis of decrypted data for private keys"""
        candidates = []
        
        print("\n🔍 ANALYZING DECRYPTED DATA")
        print("="*50)
        
        # Try as text first
        try:
            text = data.decode('utf-8', errors='ignore')
            print(f"📝 Text preview (first 300 chars):")
            print(f"'{text[:300]}...'")
            
            # Look for hex patterns
            import re
            hex_patterns = re.findall(r'\b[a-fA-F0-9]{64}\b', text)
            if hex_patterns:
                print(f"🎯 Found {len(hex_patterns)} 64-char hex patterns in text")
                candidates.extend([h.lower() for h in hex_patterns])
        except:
            print("📝 Data is not readable as text")
        
        # Extract all possible 32-byte sequences
        hex_data = data.hex().lower()
        print(f"🔢 Full hex data length: {len(hex_data)} chars")
        
        # Extract 64-char sequences (32 bytes)
        for i in range(0, len(hex_data) - 63, 2):
            candidate = hex_data[i:i+64]
            candidates.append(candidate)
        
        print(f"🔍 Total candidate private keys to test: {len(candidates)}")
        
        return candidates
    
    def test_private_key(self, private_key_hex):
        """Test if private key generates the prize address"""
        try:
            if len(private_key_hex) != 64:
                return False
                
            # Validate in secp256k1 range
            key_int = int(private_key_hex, 16)
            secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            
            if not (1 <= key_int < secp256k1_order):
                return False
                
            # Generate Bitcoin address
            generated_address = bitcoin.privkey_to_address(private_key_hex)
            
            return generated_address == self.prize_address
            
        except:
            return False
    
    def execute_final_decryption(self):
        """Execute the final decryption attempt"""
        
        print("🚀 COSMIC DUALITY FINAL DECRYPTION")
        print("="*60)
        print(f"🎯 Target: {self.prize_address}")
        print(f"🔑 Password: {self.salphaseion_password}")
        print("")
        
        # Try decryption with the SalPhaseIon hash
        decrypted_data = self.try_openssl_aes_decrypt(self.salphaseion_password)
        
        if decrypted_data:
            print("\n🎉 DECRYPTION SUCCESSFUL!")
            
            # Analyze for private keys
            candidates = self.analyze_for_private_keys(decrypted_data)
            
            print(f"\n🔍 Testing {len(candidates)} candidates for prize address...")
            
            for i, candidate in enumerate(candidates):
                if i % 100 == 0:
                    print(f"  Testing candidate {i}...")
                    
                if self.test_private_key(candidate):
                    print(f"\n🎊🎊🎊 PRIZE PRIVATE KEY FOUND! 🎊🎊🎊")
                    print(f"🔑 Private Key: {candidate}")
                    print(f"🏠 Prize Address: {self.prize_address}")
                    print(f"📍 Found at position: {i}")
                    
                    # Save the result
                    import json
                    result = {
                        'PUZZLE_STATUS': 'COMPLETELY SOLVED',
                        'GSMG_IO_PRIZE_ADDRESS': self.prize_address,
                        'PRIVATE_KEY': candidate,
                        'DERIVATION_METHOD': 'Cosmic Duality AES decryption',
                        'SALPHASEION_PASSWORD': self.salphaseion_password,
                        'POSITION_IN_DATA': i,
                        'BLOCKCHAIN_EXPLORER': f'https://blockchain.com/explorer/addresses/btc/{self.prize_address}',
                        'SUCCESS': True
                    }
                    
                    with open('GSMGIO_PRIZE_COMPLETELY_SOLVED.json', 'w') as f:
                        json.dump(result, f, indent=2)
                    
                    print(f"💾 Complete solution saved: GSMGIO_PRIZE_COMPLETELY_SOLVED.json")
                    return True
            
            print("❌ No matching private key found in decrypted data")
            
            # Save decrypted data for analysis
            with open('cosmic_duality_decrypted.bin', 'wb') as f:
                f.write(decrypted_data)
            print("💾 Decrypted data saved: cosmic_duality_decrypted.bin")
            
            return False
        else:
            print("\n❌ Decryption failed with SalPhaseIon password")
            
            # Try alternative passwords
            print("\n🔄 Trying alternative password combinations...")
            alternatives = [
                self.salphaseion_password + "enter",
                "matrixsumlist" + self.salphaseion_password,
                hashlib.sha256(("matrixsumlist" + self.salphaseion_password).encode()).hexdigest(),
                "lastwordsbeforearchichoice" + self.salphaseion_password,
                "thispassword" + self.salphaseion_password
            ]
            
            for alt_password in alternatives:
                print(f"🔓 Trying: {alt_password[:30]}...")
                alt_data = self.try_openssl_aes_decrypt(alt_password)
                if alt_data:
                    print("✅ Alternative password worked!")
                    candidates = self.analyze_for_private_keys(alt_data)
                    for candidate in candidates[:50]:  # Test top 50
                        if self.test_private_key(candidate):
                            print(f"🏆 FOUND WITH ALTERNATIVE PASSWORD!")
                            return True
            
            return False

def main():
    decryptor = CosmicDualityDecryptor()
    success = decryptor.execute_final_decryption()
    
    if success:
        print("\n🏆🏆🏆 ULTIMATE SUCCESS! 🏆🏆🏆")
        print("🔓 GSMG.IO 5 BTC PUZZLE COMPLETELY SOLVED!")
    else:
        print("\n🔄 Continue analysis needed...")

if __name__ == "__main__":
    main()
