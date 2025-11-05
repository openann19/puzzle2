#!/usr/bin/env python3
"""
Solve the Cosmic Duality final phase using the hint "fourfirsthintisyourlastcommand"
"""

import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

def evp_bytes_to_key(password, salt):
    """OpenSSL's EVP_BytesToKey algorithm using MD5"""
    d = d_i = b''
    while len(d) < 48:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d += d_i
    return d[:48]

def try_openssl_decrypt(blob_b64, password):
    """Try to decrypt OpenSSL-style AES-256-CBC encrypted data"""
    try:
        # Clean and decode the base64 blob
        clean_blob = blob_b64.replace('\n', '').replace(' ', '')
        encrypted_data = base64.b64decode(clean_blob)
        
        # Check for "Salted__" prefix
        if encrypted_data[:8] != b'Salted__':
            return None
            
        salt = encrypted_data[8:16]
        ciphertext = encrypted_data[16:]
        
        # Try EVP_BytesToKey (OpenSSL default)
        key_material = evp_bytes_to_key(password.encode(), salt)
        key = key_material[:32]
        iv = key_material[32:48]
        
        # Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        
        # Remove PKCS7 padding
        padding_length = decrypted[-1]
        if 1 <= padding_length <= 16:
            decrypted = decrypted[:-padding_length]
            return decrypted
            
    except Exception as e:
        pass
    
    return None

def test_private_key(private_key_hex, target_address):
    """Test if a private key generates the target Bitcoin address"""
    try:
        import bitcoin
        if len(private_key_hex) != 64:
            return False
            
        # Validate in secp256k1 range
        key_int = int(private_key_hex, 16)
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        
        if not (1 <= key_int < secp256k1_order):
            return False
            
        # Generate Bitcoin addresses (both compressed and uncompressed)
        generated_compressed = bitcoin.privkey_to_address(private_key_hex)
        # For uncompressed, we need to use the pubkey
        pubkey = bitcoin.privtopub(private_key_hex)
        generated_uncompressed = bitcoin.pubtoaddr(pubkey, 0)  # 0 for uncompressed
        
        return generated_compressed == target_address or generated_uncompressed == target_address
            
    except Exception as e:
        print(f"Error testing key: {e}")
        return False

def main():
    target_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    
    # The Cosmic Duality blob from SalPhaseIon.md
    cosmic_blob = """U2FsdGVkX18tP2/gbclQ5tNZuD4shoV3axuUd8J8aycGCAMoYfhZK0JecHTDpTFe
dGJh4SJIP66qRtXvo7PTpvsIjwO8prLiC/sNHthxiGMuqIrKoO224rOisFJZgARi
c7PaJPne4nab8XCFuV3NbfxGX2BUjNkef5hg7nsoadZx08dNyU2b6eiciWiUvu7D
SATSFO7IFBiAMz7dDqIETKuGlTAP4EmMQUZrQNtfbJsURATW6V5VSbtZB5RFk0O+
IymhstzrQHsU0Bugjv2nndmOEhCxGi/lqK2rLNdOOLutYGnA6RDDbFJUattggELh
2SZx+SBpCdbSGjxOap27l9FOyl02r0HU6UxFdcsbfZ1utTqVEyNs91emQxtpgt+6
BPZisil74Jv4EmrpRDC3ufnkmWwR8NfqVPIKhUiGDu5QflYjczT6DrA9vLQZu3ko
k+/ZurtRYnqqsj49UhwEF9GfUfl7uQYm0UunatW43C3Z1tyFRGAzAHQUFS6jRCd+
vZGyoTlOsThjXDDCSAwoX2M+yM+oaEQoVvDwVkIqRhfDNuBmEfi+HpXuJLPBS1Pb
Ujrgo G/Uv7o8IeyST4HBv8+5KLx7IKQS8f1kPZ2YUME+8XJx0caFYs+JS2Jdm0oj
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
ZOzhw7LMSGkD1MZxpDzsCZY1emkSNd88NFj+9U8VssIDDVMYwKMsHKfjc0x5OlzQ
1f6ST0xCkwydDHHGRKKxFC4y6H6fV9sgf9OPK/65z94Rx72+mfvTyizShjxYSRpl
sH9otU4parl8roD0KsVTfXZoYrYXzK6cXBn1BO/OEqWlu++Dd9MiGaUGKd22fXER
qNWoRAKlNn2b6EehD2D8WaAoliPURjkB0Lb/FpP9unI93Twg6NxBXAj734nctukR
b3kE08RydJV70eJsvEftF5hbED4HacGx9pzisaSz6t9AKiuSoF6uoCtlTIYatyfZ
kQA4wg50hAJqTynOQ09ArRHEchtB/7uvWZSBGJ7+zlzRGKx99P3oDZD+Y5D8bmUs
3PV6FnAp+IRSlnsQ6hChkwBoQUcngcfGSkBRvmGjsGercCetRRwBOfh9fbX2ruw4
mzRYrGnz9eBtepkJXDRjD6yvhNfQMCSkm6l9zMWxKvFbv5g2ae2SLrEt/x3MP2/G"""

    # The hint is in SalPhaseIon.md - "four first hint is your last command"
    # We have two base64 strings from the hint section:
    # U2FsdGVkX186tYU0hVJBXXUnBUO7C0+X4KUWnWkCvoZSxbRD3wNsGWVHefvdrd9z
    # QvX0t8v3jPB4okpspxebRi6sE1BMl5HI8RkuKejUqTvdWOX6nQjSpepXwGuN/jJ
    # And "enter" and "shabefanstoo"
    
    # The puzzle says "four first hint is your last command"
    # Looking at the hints, we have 4 main hints/clues
    # Let me try to construct a password from the first 4 characters of key hints
    
    # From the analysis:
    # 1. "matrixsumlist" - first 4: "matr"
    # 2. "lastwordsbeforearchichoice" - first 4: "last"
    # 3. "thispassword" - first 4: "this"
    # 4. "enter" - first 4: "ente"
    
    # Try various combinations
    passwords_to_try = [
        "matrlasttdisente",  # first 4 of each
        "matrixsumliste",  # matrixsumlist + enter
        "lastwordsbeforearchichoiceenter",
        "thispasswordenter",
        "matrixsumlistenter",
        "HASHTHETEXT",
        "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32",  # The SHA256 hash
        "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
        "CosmicDuality",
        "CosmicDualityenter",
        # The hint says "shabefanstoo" - sha256(bef) + anstoo?
        "shabefanstoo",
        # Or maybe it's SHA256 of something + enter
        hashlib.sha256(b"matrixsumlist").hexdigest() + "enter",
        hashlib.sha256(b"lastwordsbeforearchichoice").hexdigest() + "enter",
        hashlib.sha256(b"fourfirsthintisyourlastcommand").hexdigest(),
        "fourfirsthintisyourlastcommand",
        "fourfirsthintisyourlastcommandenter",
    ]
    
    print(f"🎯 Target Address: {target_address}")
    print(f"🔍 Testing {len(passwords_to_try)} password combinations...")
    print()
    
    for i, password in enumerate(passwords_to_try, 1):
        print(f"[{i}/{len(passwords_to_try)}] Testing: {password[:50]}...")
        
        decrypted = try_openssl_decrypt(cosmic_blob, password)
        
        if decrypted:
            print(f"✅ DECRYPTION SUCCESSFUL with password: {password}")
            print(f"📊 Decrypted data length: {len(decrypted)} bytes")
            print(f"🔍 Hex preview: {decrypted[:64].hex()}")
            
            # Try to extract private keys
            hex_data = decrypted.hex()
            
            # Test all 32-byte (64 hex char) sequences
            for j in range(0, len(hex_data) - 63, 2):
                candidate = hex_data[j:j+64]
                
                if test_private_key(candidate, target_address):
                    print(f"\n🎊🎊🎊 PRIZE PRIVATE KEY FOUND! 🎊🎊🎊")
                    print(f"🔑 Private Key: {candidate}")
                    print(f"🏠 Target Address: {target_address}")
                    print(f"📍 Position: {j} in decrypted hex data")
                    print(f"🔓 Password: {password}")
                    
                    # Save result
                    import json
                    result = {
                        'PUZZLE_STATUS': 'COMPLETELY SOLVED',
                        'TARGET_ADDRESS': target_address,
                        'PRIVATE_KEY': candidate,
                        'PASSWORD': password,
                        'POSITION': j,
                        'SUCCESS': True
                    }
                    
                    with open('PUZZLE_SOLVED.json', 'w') as f:
                        json.dump(result, f, indent=2)
                    
                    print(f"\n💾 Solution saved to: PUZZLE_SOLVED.json")
                    return True
            
            # If no key found, save decrypted data for analysis
            with open('cosmic_duality_decrypted.bin', 'wb') as f:
                f.write(decrypted)
            print(f"💾 Decrypted data saved to: cosmic_duality_decrypted.bin")
            
            # Also save as hex for easier viewing
            with open('cosmic_duality_decrypted.hex', 'w') as f:
                f.write(hex_data)
            print(f"💾 Hex data saved to: cosmic_duality_decrypted.hex")
            
            print("\n❌ No matching private key found in decrypted data")
            print("   But decryption was successful - may need further analysis")
            return False
    
    print("\n❌ No password worked for decryption")
    return False

if __name__ == "__main__":
    main()
