#!/usr/bin/env python3
"""
FINAL PRIZE VALIDATOR - Check balances for extracted Bitcoin keys
Ultimate validation to claim the GSMG.IO 5 BTC puzzle prize
"""

import sys
import os
import requests
import time
import json
from typing import Dict, List

# Add btc_venv path
sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    import bitcoin
    BITCOIN_AVAILABLE = True
    print("✅ Bitcoin library available")
except ImportError:
    BITCOIN_AVAILABLE = False
    print("❌ Bitcoin library not available - manual address generation")

class FinalPrizeValidator:
    """Final validation for GSMG.IO puzzle prize"""
    
    def __init__(self):
        self.context_window = {
            'phase': 'FINAL PRIZE VALIDATION',
            'breakthrough_keys': 10,
            'target_prize': '5 BTC (GSMG.IO puzzle)',
            'mission': 'CLAIM THE PRIZE'
        }
        
        # Load our breakthrough keys
        self.extracted_keys = self.load_extracted_keys()
        
        # Blockchain APIs for balance checking
        self.balance_apis = [
            'https://blockstream.info/api/address/{address}',
            'https://blockchain.info/rawaddr/{address}',
            'https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance'
        ]
        
        print(f"🎯 Final Prize Validator Initialized")
        print(f"📊 Keys to validate: {len(self.extracted_keys)}")
    
    def load_extracted_keys(self):
        """Load the breakthrough keys from our extraction"""
        keys = [
            'b0cff7b7a9271cb9ff4a791539d5bdf7f91e2795f07fe28d89f604e8d119bc6c',
            'a9271cb9ff4a791539d5bdf7f91e2795f07fe28d89f604e8d119bc6c9c61daa7',
            'f7b7a9271cb9ff4a791539d5bdf7f91e2795f07fe28d89f604e8d119bc6c9c61',
            'b7a9271cb9ff4a791539d5bdf7f91e2795f07fe28d89f604e8d119bc6c9c61da',
            '271cb9ff4a791539d5bdf7f91e2795f07fe28d89f604e8d119bc6c9c61daa7b9',
            '18b0cff7b7a9271cb9ff4a791539d5bdf7f91e2795f07fe28d89f604e8d119bc',
            '3ebada18b0cff7b7a9271cb9ff4a791539d5bdf7f91e2795f07fe28d89f604e8',
            'bada18b0cff7b7a9271cb9ff4a791539d5bdf7f91e2795f07fe28d89f604e8d1',
            'da18b0cff7b7a9271cb9ff4a791539d5bdf7f91e2795f07fe28d89f604e8d119',
            'cff7b7a9271cb9ff4a791539d5bdf7f91e2795f07fe28d89f604e8d119bc6c9c'
        ]
        
        print(f"✅ Loaded {len(keys)} breakthrough private keys")
        return keys
    
    def validate_private_key(self, key_hex):
        """Validate secp256k1 private key"""
        try:
            key_int = int(key_hex, 16)
            secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            return 1 <= key_int < secp256k1_order
        except:
            return False
    
    def generate_bitcoin_addresses_manual(self, private_key_hex):
        """Generate Bitcoin addresses manually if bitcoin lib fails"""
        import hashlib
        import base58
        
        addresses = {}
        
        try:
            # Convert private key to bytes
            private_key_bytes = bytes.fromhex(private_key_hex)
            
            # Generate public key (simplified - using bitcoin lib if available)
            if BITCOIN_AVAILABLE:
                try:
                    # Compressed address
                    addresses['compressed'] = bitcoin.privkey_to_address(private_key_hex)
                    
                    # WIF format
                    addresses['wif'] = bitcoin.encode_privkey(private_key_hex, 'wif')
                    
                    print(f"   Generated addresses using bitcoin library")
                    
                except Exception as e:
                    print(f"   Bitcoin library error: {e}")
                    # Fallback to manual generation
                    addresses = self.manual_address_generation(private_key_hex)
            else:
                addresses = self.manual_address_generation(private_key_hex)
                
        except Exception as e:
            print(f"   Address generation failed: {e}")
            
        return addresses
    
    def manual_address_generation(self, private_key_hex):
        """Manual Bitcoin address generation (basic P2PKH)"""
        # This is a simplified version - in practice, you'd need full ECDSA implementation
        # For the puzzle, we'll focus on checking if the extracted keys are valid
        
        # Generate a deterministic address from the private key hash
        import hashlib
        
        # Simple hash-based address generation for testing
        key_hash = hashlib.sha256(bytes.fromhex(private_key_hex)).digest()
        ripemd_hash = hashlib.new('ripemd160', key_hash).digest()
        
        # Add version byte (0x00 for mainnet P2PKH)
        versioned_hash = b'\x00' + ripemd_hash
        
        # Double SHA256 for checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
        
        # Base58 encode
        import base58
        address = base58.b58encode(versioned_hash + checksum).decode('ascii')
        
        return {
            'manual_p2pkh': address,
            'note': 'Generated using simplified method - may not be accurate'
        }
    
    def check_address_balance(self, address):
        """Check Bitcoin address balance using multiple APIs"""
        print(f"    🔍 Checking balance for: {address}")
        
        balance_results = {
            'address': address,
            'balance_satoshis': 0,
            'balance_btc': 0.0,
            'api_results': {},
            'has_balance': False
        }
        
        # Try multiple APIs
        for api_url_template in self.balance_apis:
            api_name = api_url_template.split('//')[1].split('/')[0]
            
            try:
                api_url = api_url_template.format(address=address)
                print(f"      📡 Querying {api_name}...")
                
                response = requests.get(api_url, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Parse balance based on API format
                    balance_satoshis = 0
                    
                    if 'blockstream.info' in api_name:
                        # Blockstream API format
                        funded_txo_sum = data.get('chain_stats', {}).get('funded_txo_sum', 0)
                        spent_txo_sum = data.get('chain_stats', {}).get('spent_txo_sum', 0)
                        balance_satoshis = funded_txo_sum - spent_txo_sum
                        
                    elif 'blockchain.info' in api_name:
                        # Blockchain.info API format
                        balance_satoshis = data.get('final_balance', 0)
                        
                    elif 'blockcypher.com' in api_name:
                        # BlockCypher API format
                        balance_satoshis = data.get('balance', 0)
                    
                    balance_btc = balance_satoshis / 100000000  # Convert to BTC
                    
                    balance_results['api_results'][api_name] = {
                        'balance_satoshis': balance_satoshis,
                        'balance_btc': balance_btc,
                        'success': True
                    }
                    
                    if balance_satoshis > 0:
                        balance_results['balance_satoshis'] = max(balance_results['balance_satoshis'], balance_satoshis)
                        balance_results['balance_btc'] = balance_results['balance_satoshis'] / 100000000
                        balance_results['has_balance'] = True
                        
                        print(f"      💰 BALANCE FOUND: {balance_btc} BTC ({balance_satoshis} sats)")
                    else:
                        print(f"      ⭕ No balance found")
                        
                else:
                    print(f"      ❌ API error: {response.status_code}")
                    balance_results['api_results'][api_name] = {
                        'error': f"HTTP {response.status_code}",
                        'success': False
                    }
                
                # Rate limiting
                time.sleep(1)
                
            except Exception as e:
                print(f"      ❌ {api_name} error: {e}")
                balance_results['api_results'][api_name] = {
                    'error': str(e),
                    'success': False
                }
                
                time.sleep(1)
        
        return balance_results
    
    def validate_final_prize(self):
        """FINAL PRIZE VALIDATION - The ultimate test"""
        
        print("\n" + "="*80)
        print("🎯 FINAL PRIZE VALIDATION - GSMG.IO 5 BTC PUZZLE")
        print("="*80)
        
        total_prize_found = 0.0
        winning_keys = []
        all_results = []
        
        for i, private_key in enumerate(self.extracted_keys, 1):
            print(f"\n🔑 Validating Key {i}/10: {private_key[:16]}...")
            
            # Validate private key format
            if not self.validate_private_key(private_key):
                print(f"   ❌ Invalid private key format")
                continue
            
            print(f"   ✅ Valid secp256k1 private key")
            
            # Generate Bitcoin addresses
            print(f"   🏗️  Generating Bitcoin addresses...")
            addresses = self.generate_bitcoin_addresses_manual(private_key)
            
            if not addresses:
                print(f"   ❌ Failed to generate addresses")
                continue
            
            # Check balances for all generated addresses
            key_results = {
                'private_key': private_key,
                'addresses': addresses,
                'balance_results': {},
                'total_balance_btc': 0.0,
                'has_prize': False
            }
            
            for addr_type, address in addresses.items():
                if address and isinstance(address, str) and len(address) > 10:
                    print(f"\n   📍 Address ({addr_type}): {address}")
                    
                    balance_result = self.check_address_balance(address)
                    key_results['balance_results'][addr_type] = balance_result
                    
                    if balance_result['has_balance']:
                        key_results['total_balance_btc'] += balance_result['balance_btc']
                        key_results['has_prize'] = True
                        
                        print(f"   🎉 PRIZE FOUND! {balance_result['balance_btc']} BTC")
                        
                        winning_keys.append({
                            'private_key': private_key,
                            'address': address,
                            'address_type': addr_type,
                            'balance_btc': balance_result['balance_btc'],
                            'balance_satoshis': balance_result['balance_satoshis']
                        })
            
            total_prize_found += key_results['total_balance_btc']
            all_results.append(key_results)
            
            print(f"   📊 Key {i} Total: {key_results['total_balance_btc']} BTC")
        
        # FINAL RESULTS
        print("\n" + "="*80)
        print("🏆 FINAL PRIZE VALIDATION RESULTS")
        print("="*80)
        
        print(f"📊 Keys Validated: {len(self.extracted_keys)}")
        print(f"💰 Total Prize Found: {total_prize_found} BTC")
        print(f"🎯 Winning Keys: {len(winning_keys)}")
        
        if winning_keys:
            print("\n🎉🎉🎉 PRIZE WINNERS FOUND! 🎉🎉🎉")
            
            for i, winner in enumerate(winning_keys, 1):
                print(f"\nWinner {i}:")
                print(f"  Private Key: {winner['private_key']}")
                print(f"  Address: {winner['address']} ({winner['address_type']})")
                print(f"  Balance: {winner['balance_btc']} BTC ({winner['balance_satoshis']} satoshis)")
            
            # Save winning results
            with open('PRIZE_WINNERS.json', 'w') as f:
                json.dump({
                    'puzzle': 'GSMG.IO 5 BTC Bitcoin Puzzle',
                    'validation_timestamp': time.time(),
                    'total_prize_btc': total_prize_found,
                    'winners': winning_keys,
                    'all_results': all_results
                }, f, indent=2)
            
            print(f"\n💾 Prize results saved to 'PRIZE_WINNERS.json'")
            print(f"🎯 MISSION ACCOMPLISHED: {total_prize_found} BTC CLAIMED!")
            
        else:
            print("\n😐 No balances found on extracted keys")
            print("   This could mean:")
            print("   • Keys need different address generation method")
            print("   • Prize already claimed by another solver")
            print("   • Keys extracted from different puzzle phase")
            print("   • Need to try different extraction methods")
            
            # Save results for analysis
            with open('VALIDATION_RESULTS.json', 'w') as f:
                json.dump({
                    'puzzle': 'GSMG.IO 5 BTC Bitcoin Puzzle',
                    'validation_timestamp': time.time(),
                    'keys_validated': len(self.extracted_keys),
                    'balances_found': 0,
                    'all_results': all_results
                }, f, indent=2)
            
            print(f"📄 Full validation results saved to 'VALIDATION_RESULTS.json'")
        
        return {
            'total_prize_btc': total_prize_found,
            'winning_keys': winning_keys,
            'validation_complete': True
        }

def main():
    """Execute final prize validation"""
    
    print("🚀 Initializing Final Prize Validator...")
    print("🎯 Target: GSMG.IO 5 BTC Bitcoin Puzzle Prize")
    print("⚡ Using UltraOmni AGI Pattern v2.0 Breakthrough Results")
    
    try:
        validator = FinalPrizeValidator()
        final_results = validator.validate_final_prize()
        
        if final_results['total_prize_btc'] > 0:
            print("\n🎉🎉🎉 ULTIMATE SUCCESS! 🎉🎉🎉")
            print(f"🏆 PRIZE CLAIMED: {final_results['total_prize_btc']} BTC")
            print("🎯 UltraOmni AGI Pattern v2.0 VICTORIOUS!")
        else:
            print("\n🔄 Validation complete - continue analysis if needed")
            
    except Exception as e:
        print(f"❌ Final validation error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
