#!/usr/bin/env python3
"""
Final attempt to solve the Cosmic Duality puzzle based on careful analysis of hints
"""

import hashlib
import base64
from Crypto.Cipher import AES

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
        clean_blob = blob_b64.replace('\n', '').replace(' ', '')
        encrypted_data = base64.b64decode(clean_blob)
        
        if encrypted_data[:8] != b'Salted__':
            return None
            
        salt = encrypted_data[8:16]
        ciphertext = encrypted_data[16:]
        
        key_material = evp_bytes_to_key(password.encode(), salt)
        key = key_material[:32]
        iv = key_material[32:48]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        
        padding_length = decrypted[-1]
        if 1 <= padding_length <= 16:
            decrypted = decrypted[:-padding_length]
            return decrypted
            
    except:
        pass
    
    return None

def test_private_key(private_key_hex, target_address):
    """Test if a private key generates the target Bitcoin address"""
    try:
        import bitcoin
        if len(private_key_hex) != 64:
            return False
            
        key_int = int(private_key_hex, 16)
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        
        if not (1 <= key_int < secp256k1_order):
            return False
            
        generated_compressed = bitcoin.privkey_to_address(private_key_hex)
        pubkey = bitcoin.privtopub(private_key_hex)
        generated_uncompressed = bitcoin.pubtoaddr(pubkey, 0)
        
        return generated_compressed == target_address or generated_uncompressed == target_address
            
    except Exception as e:
        return False

def main():
    target_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    
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

    # Based on hint analysis:
    # "four first hint is your last command"
    # First puzzle text: GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe
    # First FOUR characters: "GSMG"
    # OR first FOUR words: "GSMG" "IO" "5" "BTC"
    # The decoded hints from SalPhaseIon: matrixsumlist, lastwordsbeforearchichoice, thispassword, enter
    
    passwords_to_try = [
        # First 4 chars of first puzzle
        "GSMG",
        "gsmg",
        # First 4 chars of each hint combined
        "matrlastthisente",
        # Try words from first puzzle
        "GSMGIO5BTC",
        # Hash variations
        hashlib.sha256(b"GSMG").hexdigest(),
        hashlib.sha256(b"gsmg").hexdigest(),
        # Maybe it's the first 4 AND last?
        "GSMGenter",
        "gsmgenter",
        # Or capitalize properly 
        "Gsmg",
        "GsmgEnter",
        # Try MD5 instead
        hashlib.md5(b"GSMG").hexdigest(),
        hashlib.md5(b"gsmg").hexdigest(),
        # Maybe it's telling us to use the number 4 and word "first"
        "4first",
        "fourfirst",
        # Or literally the first word repeated 4 times
        "GSMGGSMGGSMGGSMG",
        "gsmggsmggsmggsmg",
        # Based on the hint "Roses are White but often Red. Yellow has a number and so does Blue"
        # This might be about specific colors/words
        "WhiteRedYellowBlue",
        # Or just colors
        "WRYB",
        "wryb",
    ]
    
    print(f"🎯 Target: {target_address}")
    print(f"🔍 Testing {len(passwords_to_try)} passwords...\n")
    
    for i, pwd in enumerate(passwords_to_try, 1):
        print(f"[{i}/{len(passwords_to_try)}] {pwd[:40]}...", end="", flush=True)
        
        decrypted = try_openssl_decrypt(cosmic_blob, pwd)
        
        if decrypted:
            print(f" ✅ DECRYPTED!")
            print(f"📊 Length: {len(decrypted)} bytes")
            print(f"🔍 First 64 bytes (hex): {decrypted[:64].hex()}")
            
            # Search for private keys
            hex_data = decrypted.hex()
            for j in range(0, len(hex_data) - 63, 2):
                candidate = hex_data[j:j+64]
                
                if test_private_key(candidate, target_address):
                    print(f"\n🎊🎊🎊 PUZZLE SOLVED! 🎊🎊🎊")
                    print(f"🔑 Private Key: {candidate}")
                    print(f"🔓 Password: {pwd}")
                    
                    import json
                    result = {
                        'TARGET_ADDRESS': target_address,
                        'PRIVATE_KEY': candidate,
                        'PASSWORD': pwd,
                        'POSITION': j,
                        'SUCCESS': True
                    }
                    
                    with open('PUZZLE_SOLVED.json', 'w') as f:
                        json.dump(result, f, indent=2)
                    
                    return True
            
            with open('cosmic_decrypted_temp.bin', 'wb') as f:
                f.write(decrypted)
            print(f"💾 Saved to: cosmic_decrypted_temp.bin")
            
        else:
            print(" ❌")
    
    print("\n❌ None of the passwords worked")
    return False

if __name__ == "__main__":
    main()
