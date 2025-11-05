#!/usr/bin/env python3
"""
Comprehensive solver - try all possible padding values and search strategies
"""

import hashlib
import base64
from Crypto.Cipher import AES
import bitcoin

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
ZOzhw7LMSGkD1MZxpDzsCZY1emkSNd88NFj+9U8VssIDDVMYwKMsHKfjc0x5OlzQ
1f6ST0xCkwydDHHGRKKxFC4y6H6fV9sgf9OPK/65z94Rx72+mfvTyizShjxYSRpl
sH9otU4parl8roD0KsVTfXZoYrYXzK6cXBn1BO/OEqWlu++Dd9MiGaUGKd22fXER
qNWoRAKlNn2b6EehD2D8WaAoliPURjkB0Lb/FpP9unI93Twg6NxBXAj734nctukR
b3kE08RydJV70eJsvEftF5hbED4HacGx9pzisaSz6t9AKiuSoF6uoCtlTIYatyfZ
kQA4wg50hAJqTynOQ09ArRHEchtB/7uvWZSBGJ7+zlzRGKx99P3oDZD+Y5D8bmUs
3PV6FnAp+IRSlnsQ6hChkwBoQUcngcfGSkBRvmGjsGercCetRRwBOfh9fbX2ruw4
mzRYrGnz9eBtepkJXDRjD6yvhNfQMCSkm6l9zMWxKvFbv5g2ae2SLrEt/x3MP2/G"""

def evp_bytes_to_key(password, salt):
    d = d_i = b''
    while len(d) < 48:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d += d_i
    return d[:48]

def test_key(key_hex):
    try:
        if len(key_hex) != 64:
            return False
        key_int = int(key_hex, 16)
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        if not (1 <= key_int < secp256k1_order):
            return False
        
        # Compressed address
        addr = bitcoin.privkey_to_address(key_hex)
        if addr == target_address:
            return ('compressed', addr)
        
        # Uncompressed address
        pubkey = bitcoin.privtopub(key_hex)
        addr_unc = bitcoin.pubtoaddr(pubkey, 0)
        if addr_unc == target_address:
            return ('uncompressed', addr_unc)
        
        return False
    except:
        return False

password = "matrixsumlist89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"

clean_blob = cosmic_blob.replace('\n', '').replace(' ', '')
encrypted_data = base64.b64decode(clean_blob)

salt = encrypted_data[8:16]
ciphertext = encrypted_data[16:]

key_material = evp_bytes_to_key(password.encode(), salt)
key = key_material[:32]
iv = key_material[32:48]

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted_raw = cipher.decrypt(ciphertext)

print(f"🎯 Target: {target_address}")
print(f"📊 Raw decrypted length: {len(decrypted_raw)} bytes")
print()

# Try different padding removal strategies
for padding_to_remove in range(0, 17):
    if padding_to_remove > len(decrypted_raw):
        continue
    
    if padding_to_remove == 0:
        decrypted = decrypted_raw
        print(f"[{padding_to_remove}] NO padding removal - {len(decrypted)} bytes")
    else:
        decrypted = decrypted_raw[:-padding_to_remove]
        print(f"[{padding_to_remove}] Remove {padding_to_remove} bytes padding - {len(decrypted)} bytes")
    
    hex_data = decrypted.hex()
    
    # Search for private keys
    for offset in range(0, len(hex_data) - 63, 2):
        candidate = hex_data[offset:offset+64]
        
        result = test_key(candidate)
        if result:
            print(f"\n🎊🎊🎊 PRIVATE KEY FOUND! 🎊🎊🎊")
            print(f"🔑 Private Key: {candidate}")
            print(f"🏠 Address ({result[0]}): {result[1]}")
            print(f"📍 Padding removed: {padding_to_remove} bytes")
            print(f"📍 Position: byte {offset//2}, hex offset {offset}")
            
            import json
            solution = {
                'TARGET_ADDRESS': target_address,
                'PRIVATE_KEY': candidate,
                'PASSWORD': password,
                'PADDING_REMOVED': padding_to_remove,
                'POSITION_BYTES': offset//2,
                'ADDRESS_TYPE': result[0],
                'SUCCESS': True
            }
            
            with open('PUZZLE_COMPLETELY_SOLVED.json', 'w') as f:
                json.dump(solution, f, indent=2)
            
            print(f"\n💾 Solution saved: PUZZLE_COMPLETELY_SOLVED.json")
            exit(0)

print("\n❌ No matching private key found with any padding strategy")
