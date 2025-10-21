#!/usr/bin/env python3
"""
Bitcoin Private Key Verification Script
Validates extracted private keys and generates proper Bitcoin addresses
"""

import hashlib
import base58
import ecdsa
from ecdsa import SigningKey, SECP256k1
import requests
import json
import time

def private_key_to_public_key(private_key_hex):
    """Convert private key to public key (compressed and uncompressed)"""
    private_key_int = int(private_key_hex, 16)
    
    # Create signing key
    sk = SigningKey.from_secret_exponent(private_key_int, curve=SECP256k1)
    vk = sk.verifying_key
    
    # Get uncompressed public key (65 bytes: 0x04 + 32 bytes x + 32 bytes y)
    public_key_uncompressed = b'\x04' + vk.to_string()
    
    # Get compressed public key (33 bytes: 0x02/0x03 + 32 bytes x)
    x, y = vk.to_string()[:32], vk.to_string()[32:]
    y_int = int.from_bytes(y, 'big')
    prefix = b'\x03' if y_int % 2 else b'\x02'
    public_key_compressed = prefix + x
    
    return public_key_compressed, public_key_uncompressed

def public_key_to_address(public_key, compressed=True):
    """Convert public key to Bitcoin address"""
    # SHA256
    sha256_hash = hashlib.sha256(public_key).digest()
    
    # RIPEMD160
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    ripemd160_hash = ripemd160.digest()
    
    # Add version byte (0x00 for mainnet)
    versioned_hash = b'\x00' + ripemd160_hash
    
    # Double SHA256 for checksum
    checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
    
    # Final address
    address_bytes = versioned_hash + checksum
    address = base58.b58encode(address_bytes).decode('ascii')
    
    return address

def private_key_to_wif(private_key_hex, compressed=True):
    """Convert private key to Wallet Import Format"""
    private_key_bytes = bytes.fromhex(private_key_hex)
    
    # Add version byte (0x80 for mainnet)
    extended_key = b'\x80' + private_key_bytes
    
    # Add compression flag if compressed
    if compressed:
        extended_key += b'\x01'
    
    # Double SHA256 for checksum
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    
    # Final WIF
    wif_bytes = extended_key + checksum
    wif = base58.b58encode(wif_bytes).decode('ascii')
    
    return wif

def validate_private_key(private_key_hex):
    """Validate private key is in valid range"""
    try:
        private_key_int = int(private_key_hex, 16)
        # SECP256k1 curve order
        curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        return 0 < private_key_int < curve_order
    except:
        return False

def check_address_balance(address, max_retries=3):
    """Check Bitcoin address balance using blockchain API"""
    for attempt in range(max_retries):
        try:
            # Using blockchain.info API
            url = f"https://blockchain.info/q/addressbalance/{address}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                balance_satoshis = int(response.text.strip())
                balance_btc = balance_satoshis / 100000000
                return balance_btc, True
            
        except Exception as e:
            print(f"API attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(2)  # Wait before retry
    
    return 0, False

def main():
    print("🔍 BITCOIN PRIVATE KEY VERIFICATION")
    print("=" * 50)
    
    # Load private key candidates from our decrypted solution
    key_candidates = []
    
    # Read all private key candidate files
    import glob
    import os
    
    candidate_files = glob.glob("private_key_candidate_offset_*.hex")
    
    if not candidate_files:
        print("⚠️ No candidate files found. Extracting from solution...")
        
        # Extract from solution file
        try:
            with open('solution_pbkdf2_SalPhaseIon_10000.txt', 'rb') as f:
                raw_data = f.read()
            
            # Extract 32-byte chunks as potential keys
            key_candidates = []
            for offset in range(0, min(len(raw_data)-32, 200), 8):
                chunk = raw_data[offset:offset+32]
                chunk_hex = chunk.hex()
                
                if validate_private_key(chunk_hex):
                    key_candidates.append((chunk_hex, offset))
                    
                if len(key_candidates) >= 10:  # Limit to first 10 valid candidates
                    break
                    
        except Exception as e:
            print(f"❌ Error reading solution file: {e}")
            return
    else:
        # Read from existing candidate files
        for file_path in sorted(candidate_files):
            try:
                with open(file_path, 'r') as f:
                    key_hex = f.read().strip()
                    if validate_private_key(key_hex):
                        offset = int(file_path.split('_')[-1].split('.')[0])
                        key_candidates.append((key_hex, offset))
            except Exception as e:
                print(f"❌ Error reading {file_path}: {e}")
    
    print(f"📊 Testing {len(key_candidates)} private key candidates...")
    
    valid_addresses = []
    
    for i, (private_key_hex, offset) in enumerate(key_candidates):
        print(f"\n--- CANDIDATE {i+1} (offset {offset}) ---")
        print(f"Private Key: {private_key_hex}")
        
        try:
            # Validate key
            if not validate_private_key(private_key_hex):
                print("❌ Invalid private key range")
                continue
            
            print("✅ Valid private key range")
            
            # Generate public keys
            pub_compressed, pub_uncompressed = private_key_to_public_key(private_key_hex)
            
            # Generate addresses
            addr_compressed = public_key_to_address(pub_compressed, compressed=True)
            addr_uncompressed = public_key_to_address(pub_uncompressed, compressed=False)
            
            # Generate WIF
            wif_compressed = private_key_to_wif(private_key_hex, compressed=True)
            wif_uncompressed = private_key_to_wif(private_key_hex, compressed=False)
            
            print(f"Compressed Address:   {addr_compressed}")
            print(f"Uncompressed Address: {addr_uncompressed}")
            print(f"WIF Compressed:       {wif_compressed}")
            print(f"WIF Uncompressed:     {wif_uncompressed}")
            
            # Check balances
            print("🔍 Checking address balances...")
            
            balance_comp, success_comp = check_address_balance(addr_compressed)
            if success_comp:
                print(f"Compressed balance:   {balance_comp} BTC")
                if balance_comp > 0:
                    print("🎯 FUNDS FOUND ON COMPRESSED ADDRESS!")
                    
            balance_uncomp, success_uncomp = check_address_balance(addr_uncompressed)  
            if success_uncomp:
                print(f"Uncompressed balance: {balance_uncomp} BTC")
                if balance_uncomp > 0:
                    print("🎯 FUNDS FOUND ON UNCOMPRESSED ADDRESS!")
            
            # Save valid key data
            key_data = {
                'private_key_hex': private_key_hex,
                'compressed_address': addr_compressed,
                'uncompressed_address': addr_uncompressed,
                'wif_compressed': wif_compressed,
                'wif_uncompressed': wif_uncompressed,
                'offset': offset,
                'balance_compressed': balance_comp if success_comp else None,
                'balance_uncompressed': balance_uncomp if success_uncomp else None
            }
            
            valid_addresses.append(key_data)
            
            # Save individual key file
            with open(f'verified_key_{i+1}.json', 'w') as f:
                json.dump(key_data, f, indent=2)
            
            time.sleep(1)  # Rate limit API calls
            
        except Exception as e:
            print(f"❌ Error processing key: {e}")
            continue
    
    # Summary
    print(f"\n🏆 VERIFICATION COMPLETE")
    print(f"Valid keys processed: {len(valid_addresses)}")
    
    # Save all results
    with open('all_verified_keys.json', 'w') as f:
        json.dump(valid_addresses, f, indent=2)
    
    print("💾 Results saved to all_verified_keys.json")
    
    # Check for any funds
    total_btc = 0
    for key_data in valid_addresses:
        if key_data.get('balance_compressed'):
            total_btc += key_data['balance_compressed']
        if key_data.get('balance_uncompressed'):
            total_btc += key_data['balance_uncompressed']
    
    if total_btc > 0:
        print(f"🎯 TOTAL FUNDS FOUND: {total_btc} BTC")
    else:
        print("🔍 No funds found on generated addresses")

if __name__ == "__main__":
    main()
