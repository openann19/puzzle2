#!/usr/bin/env python3
"""
Simple Bitcoin Key Extractor - Extract keys from breakthrough data
"""

import sys
import os
import re
import binascii

# Add btc_venv path
sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    import bitcoin
    BITCOIN_AVAILABLE = True
except ImportError:
    BITCOIN_AVAILABLE = False
    print("Warning: bitcoin library not available - validation disabled")

def load_breakthrough_data():
    """Load the breakthrough decrypted data"""
    try:
        with open('capsule3_breakthrough_1755336408.txt', 'rb') as f:
            data = f.read()
            print(f"✅ Loaded breakthrough data: {len(data)} bytes")
            return data
    except Exception as e:
        print(f"❌ Error loading data: {e}")
        return None

def extract_hex_keys(data):
    """Extract potential 32-byte hex private keys"""
    # Convert to text for pattern matching
    try:
        text_data = data.decode('utf-8', errors='ignore')
    except:
        text_data = str(data)
    
    # Look for 64-character hex strings (32 bytes = 256 bits)
    hex_patterns = re.findall(r'\b[0-9a-fA-F]{64}\b', text_data)
    
    valid_keys = []
    for pattern in hex_patterns:
        if validate_private_key(pattern):
            valid_keys.append(pattern)
    
    return valid_keys

def extract_binary_keys(data):
    """Try to interpret binary data as potential keys"""
    keys = []
    
    # Try each 32-byte chunk as a potential private key
    for i in range(0, len(data) - 32, 1):  # Slide through the data
        chunk = data[i:i+32]
        hex_key = chunk.hex()
        
        if validate_private_key(hex_key):
            keys.append(hex_key)
            if len(keys) >= 10:  # Limit to prevent too many results
                break
    
    return keys

def validate_private_key(key_hex):
    """Validate if hex string is a valid secp256k1 private key"""
    try:
        if len(key_hex) != 64:
            return False
        
        key_int = int(key_hex, 16)
        
        # Check if key is zero (invalid)
        if key_int == 0:
            return False
        
        # secp256k1 curve order (keys must be less than this)
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        
        return 1 <= key_int < secp256k1_order
        
    except Exception:
        return False

def generate_bitcoin_addresses(private_key_hex):
    """Generate Bitcoin addresses from private key"""
    if not BITCOIN_AVAILABLE:
        return {"error": "bitcoin library not available"}
    
    addresses = {}
    try:
        # Generate uncompressed address
        addresses['uncompressed'] = bitcoin.privkey_to_address(private_key_hex, compressed=False)
        
        # Generate compressed address  
        addresses['compressed'] = bitcoin.privkey_to_address(private_key_hex, compressed=True)
        
        # Generate WIF formats
        addresses['wif_uncompressed'] = bitcoin.encode_privkey(private_key_hex, 'wif')
        addresses['wif_compressed'] = bitcoin.encode_privkey(private_key_hex, 'wif_compressed')
        
    except Exception as e:
        addresses['error'] = str(e)
    
    return addresses

def analyze_data_structure(data):
    """Simple analysis of the data structure"""
    print(f"\n📊 Data Analysis:")
    print(f"   Length: {len(data)} bytes")
    print(f"   First 32 bytes (hex): {data[:32].hex()}")
    print(f"   Last 32 bytes (hex): {data[-32:].hex()}")
    
    # Check for patterns
    unique_bytes = len(set(data))
    print(f"   Unique bytes: {unique_bytes}/256")
    
    # Look for common signatures
    if data.startswith(b'Salted__'):
        print("   🔍 OpenSSL encrypted format detected")
    elif data.startswith(b'PK'):
        print("   🔍 ZIP archive format detected") 
    elif b'-----BEGIN' in data:
        print("   🔍 PEM format detected")
    else:
        print("   🔍 Unknown binary format")

def main():
    """Main analysis function"""
    print("🔍 Simple Bitcoin Key Extractor")
    print("="*50)
    
    # Load data
    data = load_breakthrough_data()
    if not data:
        return
    
    # Analyze structure
    analyze_data_structure(data)
    
    # Extract potential keys
    print(f"\n🔑 Extracting Potential Private Keys...")
    
    # Method 1: Look for hex patterns in text
    print(f"   Method 1: Text hex patterns")
    hex_keys = extract_hex_keys(data)
    print(f"   Found {len(hex_keys)} valid hex keys from text patterns")
    
    # Method 2: Try binary chunks
    print(f"   Method 2: Binary chunk analysis")  
    binary_keys = extract_binary_keys(data)
    print(f"   Found {len(binary_keys)} valid keys from binary chunks")
    
    # Combine and deduplicate
    all_keys = list(set(hex_keys + binary_keys))
    print(f"\n🎯 Total unique valid keys found: {len(all_keys)}")
    
    if all_keys:
        print(f"\n💰 Generating Bitcoin Addresses...")
        
        for i, key in enumerate(all_keys[:5]):  # Process first 5 keys
            print(f"\n   Key {i+1}: {key}")
            
            addresses = generate_bitcoin_addresses(key)
            
            if 'error' in addresses:
                print(f"      Error: {addresses['error']}")
            else:
                print(f"      Compressed addr:   {addresses.get('compressed', 'N/A')}")
                print(f"      Uncompressed addr: {addresses.get('uncompressed', 'N/A')}")
                print(f"      WIF compressed:    {addresses.get('wif_compressed', 'N/A')}")
        
        # Save results
        with open('extracted_bitcoin_keys.txt', 'w') as f:
            f.write("Bitcoin Keys Extracted from Breakthrough Data\n")
            f.write("=" * 50 + "\n\n")
            
            for i, key in enumerate(all_keys):
                f.write(f"Key {i+1}: {key}\n")
                addresses = generate_bitcoin_addresses(key)
                
                if 'error' not in addresses:
                    f.write(f"  Compressed:   {addresses.get('compressed', 'N/A')}\n")
                    f.write(f"  Uncompressed: {addresses.get('uncompressed', 'N/A')}\n")
                    f.write(f"  WIF Comp:     {addresses.get('wif_compressed', 'N/A')}\n")
                    f.write(f"  WIF Uncomp:   {addresses.get('wif_uncompressed', 'N/A')}\n")
                f.write("\n")
        
        print(f"\n💾 Results saved to 'extracted_bitcoin_keys.txt'")
        
        if BITCOIN_AVAILABLE:
            print(f"\n🎉 SUCCESS: {len(all_keys)} Bitcoin private keys extracted!")
            print("   Next step: Check balances for these addresses")
        else:
            print(f"\n⚠️ PARTIAL SUCCESS: {len(all_keys)} keys found but need bitcoin library for full validation")
    else:
        print(f"\n❌ No valid Bitcoin private keys found in the decrypted data")
        print("   The data may need further decryption or different analysis approach")

if __name__ == "__main__":
    main()
