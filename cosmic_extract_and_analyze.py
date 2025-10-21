#!/usr/bin/env python3
"""
Extract and analyze the successfully decrypted Cosmic Duality data
Focus on the successful "matrixsumlist + hash" decryption
"""

import sys
import hashlib
import base64
import binascii

sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    from Crypto.Cipher import AES
    import bitcoin
    CRYPTO_AVAILABLE = True
except ImportError as e:
    print(f"❌ Crypto import error: {e}")
    sys.exit(1)

def extract_decrypted_data():
    """Extract the successfully decrypted data using the working password"""
    
    # The working password combination
    salphaseion_hash = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
    working_password = "matrixsumlist" + salphaseion_hash
    
    # The Cosmic Duality blob
    cosmic_duality_blob = """U2FsdGVkX18tP2/gbclQ5tNZuD4shoV3axuUd8J8aycGCAMoYfhZK0JecHTDpTFe
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

    print("🚀 EXTRACTING DECRYPTED COSMIC DUALITY DATA")
    print("="*60)
    print(f"🔑 Working Password: matrixsumlist{salphaseion_hash[:20]}...")
    
    # Decrypt using EVP_BytesToKey (OpenSSL method)
    try:
        # Clean and decode base64
        clean_blob = cosmic_duality_blob.replace('\n', '').replace(' ', '')
        encrypted_data = base64.b64decode(clean_blob)
        
        salt = encrypted_data[8:16]
        ciphertext = encrypted_data[16:]
        
        # EVP_BytesToKey algorithm
        d = d_i = b''
        password_bytes = working_password.encode()
        while len(d) < 48:
            d_i = hashlib.md5(d_i + password_bytes + salt).digest()
            d += d_i
            
        key = d[:32]
        iv = d[32:48]
        
        # Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        
        # Remove padding
        padding_length = decrypted[-1]
        decrypted = decrypted[:-padding_length]
        
        print(f"✅ Successfully decrypted {len(decrypted)} bytes")
        
        # Save the raw data
        with open('cosmic_decrypted_raw.bin', 'wb') as f:
            f.write(decrypted)
        
        print(f"💾 Raw data saved: cosmic_decrypted_raw.bin")
        
        return decrypted
        
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        return None

def analyze_decrypted_data(data):
    """Comprehensive analysis of the decrypted data"""
    
    print(f"\n🔍 COMPREHENSIVE DATA ANALYSIS")
    print("="*50)
    print(f"📊 Data Length: {len(data)} bytes")
    
    # Save hex dump
    hex_data = data.hex()
    print(f"🔢 Hex Length: {len(hex_data)} chars")
    
    with open('cosmic_decrypted.hex', 'w') as f:
        # Format hex nicely
        for i in range(0, len(hex_data), 32):
            f.write(hex_data[i:i+32] + '\n')
    
    print("💾 Hex dump saved: cosmic_decrypted.hex")
    
    # Try different interpretations
    print(f"\n🔍 TESTING DIFFERENT INTERPRETATIONS")
    
    # 1. Look for ASCII strings
    try:
        ascii_parts = []
        current_string = ""
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) > 3:
                    ascii_parts.append(current_string)
                current_string = ""
        
        if ascii_parts:
            print(f"📝 Found {len(ascii_parts)} ASCII strings:")
            for i, s in enumerate(ascii_parts[:10]):
                print(f"  [{i}]: {s}")
    except:
        pass
    
    # 2. Look for Bitcoin private key patterns
    print(f"\n🔍 SEARCHING FOR BITCOIN PRIVATE KEYS")
    
    # Test different starting positions for 32-byte sequences
    prize_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    
    found_keys = []
    
    for start_pos in range(len(data) - 31):
        # Extract 32 bytes
        key_bytes = data[start_pos:start_pos + 32]
        key_hex = key_bytes.hex()
        
        # Validate key range
        try:
            key_int = int(key_hex, 16)
            secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            
            if 1 <= key_int < secp256k1_order:
                # Valid private key - test it
                try:
                    generated_address = bitcoin.privkey_to_address(key_hex)
                    found_keys.append({
                        'position': start_pos,
                        'private_key': key_hex,
                        'address': generated_address
                    })
                    
                    if generated_address == prize_address:
                        print(f"\n🎉🎉🎉 PRIZE PRIVATE KEY FOUND! 🎉🎉🎉")
                        print(f"🔑 Private Key: {key_hex}")
                        print(f"🏠 Prize Address: {prize_address}")
                        print(f"📍 Position in data: {start_pos}")
                        
                        # Save the result
                        import json
                        result = {
                            'PUZZLE_STATUS': 'COMPLETELY SOLVED',
                            'PRIZE_ADDRESS': prize_address,
                            'PRIVATE_KEY': key_hex,
                            'POSITION_IN_DECRYPTED_DATA': start_pos,
                            'DECRYPTION_PASSWORD': 'matrixsumlist + SalPhaseIon hash',
                            'SUCCESS': True
                        }
                        
                        with open('FINAL_PRIZE_SOLUTION.json', 'w') as f:
                            json.dump(result, f, indent=2)
                        
                        print(f"💾 SOLUTION SAVED: FINAL_PRIZE_SOLUTION.json")
                        return True
                        
                except:
                    pass
        except:
            pass
    
    print(f"🔍 Generated and tested {len(found_keys)} valid private keys")
    
    if found_keys:
        print(f"📋 Sample of generated addresses:")
        for i, key_info in enumerate(found_keys[:10]):
            print(f"  [{i}] Position {key_info['position']}: {key_info['address']}")
    
    # 3. Try different encodings
    print(f"\n🔍 TRYING ALTERNATIVE ENCODINGS")
    
    # Base64 decode attempts
    try:
        # Try base64 on different parts
        for chunk_size in [4, 8, 16, 32, 64]:
            for start in range(0, min(len(data), 200), chunk_size):
                chunk = data[start:start + chunk_size]
                try:
                    # Try as base64
                    if len(chunk) % 4 == 0:
                        decoded = base64.b64decode(chunk)
                        if len(decoded) == 32:  # Potential private key
                            key_hex = decoded.hex()
                            try:
                                key_int = int(key_hex, 16)
                                if 1 <= key_int < secp256k1_order:
                                    test_addr = bitcoin.privkey_to_address(key_hex)
                                    if test_addr == prize_address:
                                        print(f"🎉 FOUND with base64 decode at position {start}!")
                                        return True
                            except:
                                pass
                except:
                    pass
    except:
        pass
    
    # Save analysis results
    with open('cosmic_analysis.txt', 'w') as f:
        f.write(f"Cosmic Duality Analysis Results\n")
        f.write(f"Data Length: {len(data)} bytes\n")
        f.write(f"Valid Private Keys Found: {len(found_keys)}\n")
        f.write(f"Prize Address Searched: {prize_address}\n")
        f.write(f"Match Found: No\n\n")
        
        if found_keys:
            f.write("Valid Private Keys Generated:\n")
            for key_info in found_keys:
                f.write(f"Position {key_info['position']}: {key_info['private_key']} -> {key_info['address']}\n")
    
    print(f"💾 Analysis saved: cosmic_analysis.txt")
    
    return False

def main():
    print("🎯 Starting Cosmic Duality Data Extraction and Analysis")
    
    # Extract decrypted data
    decrypted_data = extract_decrypted_data()
    
    if decrypted_data:
        # Analyze for private keys
        success = analyze_decrypted_data(decrypted_data)
        
        if success:
            print(f"\n🏆🏆🏆 GSMG.IO PUZZLE COMPLETELY SOLVED! 🏆🏆🏆")
        else:
            print(f"\n🔄 Analysis complete - private key not found in current decrypted data")
            print(f"💡 Additional processing methods may be needed")
    else:
        print(f"\n❌ Could not extract decrypted data")

if __name__ == "__main__":
    main()
