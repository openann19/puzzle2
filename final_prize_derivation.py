#!/usr/bin/env python3
"""
FINAL PRIZE DERIVATION - The Self-Referential Key 
Based on the GitHub documentation showing the exact pattern!
"""

import hashlib
import sys

sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    import bitcoin
    BITCOIN_AVAILABLE = True
    print("✅ Bitcoin library available")
except ImportError:
    BITCOIN_AVAILABLE = False
    print("❌ Bitcoin library not available")
    sys.exit(1)

def derive_prize_private_key():
    """Derive the private key using the self-referential pattern found in GitHub docs"""
    
    # The exact string from the GitHub documentation
    puzzle_string = "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    target_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    
    print("🚀 FINAL PRIZE DERIVATION")
    print("="*60)
    print(f"🎯 Target Prize Address: {target_address}")
    print(f"🧩 Puzzle String: {puzzle_string}")
    print("")
    
    # Generate SHA256 hash as private key
    private_key_hash = hashlib.sha256(puzzle_string.encode()).hexdigest()
    print(f"🔑 Generated Private Key: {private_key_hash}")
    
    # Validate the private key is in valid range
    key_int = int(private_key_hash, 16)
    secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    if not (1 <= key_int < secp256k1_order):
        print("❌ Private key outside valid secp256k1 range")
        return None
    
    print("✅ Private key is in valid secp256k1 range")
    
    # Generate Bitcoin address from the private key
    try:
        generated_address = bitcoin.privkey_to_address(private_key_hash)
        print(f"🏠 Generated Address: {generated_address}")
        print(f"🎯 Target Address:   {target_address}")
        
        if generated_address == target_address:
            print("\n🎉🎉🎉 PERFECT MATCH! PRIVATE KEY FOUND! 🎉🎉🎉")
            print(f"🏆 THE GSMG.IO PRIZE IS UNLOCKED!")
            print(f"🔑 Private Key: {private_key_hash}")
            print(f"🏠 Prize Address: {target_address}")
            print(f"💰 Prize Amount: 5 BTC (originally, may be 2.5 BTC due to halving)")
            print(f"🔗 Check Balance: https://blockchain.com/explorer/addresses/btc/{target_address}")
            
            # Save the winning result
            result = {
                'PUZZLE_STATUS': 'COMPLETELY SOLVED',
                'PRIZE_ADDRESS': target_address,
                'PRIVATE_KEY': private_key_hash,
                'DERIVATION_METHOD': f'SHA256("{puzzle_string}")',
                'BLOCKCHAIN_EXPLORER': f'https://blockchain.com/explorer/addresses/btc/{target_address}',
                'DISCOVERY_METHOD': 'Self-referential pattern from GitHub documentation',
                'NEXT_STEP': 'Import private key to Bitcoin wallet to claim prize'
            }
            
            import json
            with open('GSMGIO_PRIZE_SOLVED.json', 'w') as f:
                json.dump(result, f, indent=2)
            
            print(f"\n💾 Complete solution saved to: GSMGIO_PRIZE_SOLVED.json")
            return private_key_hash
        else:
            print(f"\n❌ Address mismatch - this derivation method is incorrect")
            return None
            
    except Exception as e:
        print(f"❌ Error generating address: {e}")
        return None

def verify_documented_hash():
    """Verify the SHA256 hash matches the GitHub documentation"""
    
    puzzle_string = "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    calculated_hash = hashlib.sha256(puzzle_string.encode()).hexdigest()
    documented_hash = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
    
    print("\n🔍 VERIFICATION OF DOCUMENTED HASH")
    print(f"📖 Documented Hash: {documented_hash}")
    print(f"🧮 Calculated Hash: {calculated_hash}")
    
    if calculated_hash == documented_hash:
        print("✅ Hash verification SUCCESSFUL - documentation is accurate")
        return True
    else:
        print("❌ Hash verification FAILED - discrepancy detected")
        return False

def main():
    """Execute the final prize derivation"""
    
    print("🎯 Starting Final Prize Derivation Analysis")
    print("")
    
    # Verify the documented hash first
    if verify_documented_hash():
        print("\n" + "="*60)
        
        # Now try to derive the private key
        private_key = derive_prize_private_key()
        
        if private_key:
            print("\n🏆 PUZZLE COMPLETELY SOLVED!")
            print("🎊 CONGRATULATIONS ON SOLVING THE GSMG.IO 5 BTC PUZZLE!")
        else:
            print("\n🤔 Private key derivation unsuccessful")
            print("💡 Additional analysis may be needed")
    else:
        print("⚠️  Hash verification failed - need to investigate")

if __name__ == "__main__":
    main()
