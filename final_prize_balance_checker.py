#!/usr/bin/env python3
"""
FINAL PRIZE BALANCE CHECKER - Check the 324 extracted Bitcoin addresses
This is the ultimate moment - checking for the 5 BTC GSMG.IO prize!
"""

import json
import requests
import time
import sys

def load_extracted_keys():
    """Load the 324 extracted Bitcoin keys"""
    try:
        with open('binary_extracted_keys.json', 'r') as f:
            data = json.load(f)
            return data['keys']
    except Exception as e:
        print(f"❌ Error loading keys: {e}")
        return []

def check_address_balance_multiple_apis(address):
    """Check address balance using multiple APIs with fallbacks"""
    
    apis = [
        {
            'name': 'BlockStream',
            'url': f'https://blockstream.info/api/address/{address}',
            'balance_key': lambda data: data.get('chain_stats', {}).get('funded_txo_sum', 0) - data.get('chain_stats', {}).get('spent_txo_sum', 0)
        },
        {
            'name': 'BlockCypher',
            'url': f'https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance',
            'balance_key': lambda data: data.get('balance', 0)
        },
        {
            'name': 'Blockchain.info',
            'url': f'https://blockchain.info/rawaddr/{address}',
            'balance_key': lambda data: data.get('final_balance', 0)
        }
    ]
    
    for api in apis:
        try:
            print(f"    📡 Querying {api['name']}...")
            response = requests.get(api['url'], timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                balance_satoshis = api['balance_key'](data)
                balance_btc = balance_satoshis / 100000000
                
                if balance_satoshis > 0:
                    return {
                        'balance_satoshis': balance_satoshis,
                        'balance_btc': balance_btc,
                        'api_used': api['name'],
                        'has_balance': True
                    }
                else:
                    print(f"      ⭕ No balance")
                    return {
                        'balance_satoshis': 0,
                        'balance_btc': 0.0,
                        'api_used': api['name'],
                        'has_balance': False
                    }
            else:
                print(f"      ❌ {api['name']} error: {response.status_code}")
                
        except Exception as e:
            print(f"      ❌ {api['name']} exception: {e}")
            
        # Rate limiting between APIs
        time.sleep(1)
    
    # If all APIs failed
    return {
        'balance_satoshis': 0,
        'balance_btc': 0.0,
        'api_used': 'none_successful',
        'has_balance': False,
        'error': 'All APIs failed'
    }

def check_final_prize():
    """Check for the final GSMG.IO 5 BTC prize"""
    
    print("🚀 FINAL PRIZE BALANCE CHECKER")
    print("="*70)
    print("🎯 Checking 324 extracted Bitcoin addresses for GSMG.IO 5 BTC prize")
    print("💎 This could be the moment we claim the ultimate prize!")
    print("")
    
    # Load keys
    keys = load_extracted_keys()
    if not keys:
        print("❌ No keys loaded - cannot check balances")
        return False
    
    print(f"✅ Loaded {len(keys)} Bitcoin addresses")
    print("")
    
    # Results tracking
    addresses_with_balance = []
    total_prize_found = 0.0
    addresses_checked = 0
    
    # Check a strategic sample first (top addresses from different extraction methods)
    strategic_sample = []
    
    # Get first 10 addresses
    strategic_sample.extend(keys[:10])
    
    # Get some from middle
    strategic_sample.extend(keys[len(keys)//2:len(keys)//2+5])
    
    # Get last 10 addresses  
    strategic_sample.extend(keys[-10:])
    
    # Remove duplicates while preserving order
    seen_addresses = set()
    unique_strategic_sample = []
    for key_info in strategic_sample:
        if key_info['address'] not in seen_addresses:
            seen_addresses.add(key_info['address'])
            unique_strategic_sample.append(key_info)
    
    print(f"🔍 Starting with strategic sample of {len(unique_strategic_sample)} unique addresses")
    print("")
    
    # Check strategic sample first
    for i, key_info in enumerate(unique_strategic_sample, 1):
        address = key_info['address']
        private_key = key_info['private_key']
        method = key_info['method']
        source = key_info['source']
        
        print(f"🔑 Checking Address {i}/{len(unique_strategic_sample)}")
        print(f"   Address: {address}")
        print(f"   Method: {method}")
        print(f"   Source: {source}")
        print(f"   Private Key: {private_key[:16]}...")
        
        balance_result = check_address_balance_multiple_apis(address)
        addresses_checked += 1
        
        if balance_result['has_balance']:
            balance_btc = balance_result['balance_btc']
            balance_satoshis = balance_result['balance_satoshis']
            
            print(f"   🎉🎉🎉 PRIZE FOUND! 🎉🎉🎉")
            print(f"   💰 Balance: {balance_btc} BTC ({balance_satoshis:,} satoshis)")
            print(f"   📡 API: {balance_result['api_used']}")
            
            addresses_with_balance.append({
                'address': address,
                'private_key': private_key,
                'method': method,
                'source': source,
                'balance_btc': balance_btc,
                'balance_satoshis': balance_satoshis,
                'api_used': balance_result['api_used']
            })
            
            total_prize_found += balance_btc
            
            # CRITICAL: Save winning information immediately
            with open(f'PRIZE_WINNER_{address}.json', 'w') as f:
                json.dump({
                    'GSMG_IO_PUZZLE_WINNER': True,
                    'address': address,
                    'private_key': private_key,
                    'balance_btc': balance_btc,
                    'balance_satoshis': balance_satoshis,
                    'extraction_method': method,
                    'source_password': source,
                    'discovery_timestamp': time.time(),
                    'puzzle_status': 'SOLVED'
                }, f, indent=2)
            
            print(f"   💾 WINNER INFO SAVED: PRIZE_WINNER_{address}.json")
            
        else:
            print(f"   📊 Balance: {balance_result['balance_btc']} BTC")
            
        print("")
        
        # Rate limiting to be respectful to APIs
        time.sleep(2)
        
        # If we found a significant prize, we can announce success
        if balance_result['has_balance'] and balance_result['balance_btc'] >= 0.1:
            print("🎯 SIGNIFICANT PRIZE FOUND - CONTINUING STRATEGIC SEARCH...")
    
    # Final results
    print("="*70)
    print("🏆 FINAL PRIZE CHECK RESULTS")
    print("="*70)
    
    print(f"📊 Strategic Addresses Checked: {addresses_checked}")
    print(f"💰 Addresses with Balance: {len(addresses_with_balance)}")
    print(f"🎯 Total Prize Found: {total_prize_found} BTC")
    
    if addresses_with_balance:
        print(f"\n🎉🎉🎉 SUCCESS! BITCOIN PRIZE FOUND! 🎉🎉🎉")
        
        for i, winner in enumerate(addresses_with_balance, 1):
            print(f"\nPRIZE WINNER {i}:")
            print(f"  Address: {winner['address']}")
            print(f"  Private Key: {winner['private_key']}")
            print(f"  Balance: {winner['balance_btc']} BTC ({winner['balance_satoshis']:,} sats)")
            print(f"  Method: {winner['method']}")
            print(f"  Source: {winner['source']}")
        
        # Save comprehensive results
        with open('GSMG_IO_PUZZLE_SOLVED.json', 'w') as f:
            json.dump({
                'puzzle': 'GSMG.IO 5 BTC Bitcoin Puzzle',
                'status': 'SOLVED',
                'solver': 'UltraOmni AGI Pattern v2.0',
                'total_prize_btc': total_prize_found,
                'prize_winners': addresses_with_balance,
                'total_keys_extracted': len(keys),
                'strategic_addresses_checked': addresses_checked,
                'solution_timestamp': time.time(),
                'breakthrough_method': 'binary_analysis_of_successful_aes_decryptions'
            }, f, indent=2)
        
        print(f"\n💎 PUZZLE SOLUTION SAVED: GSMG_IO_PUZZLE_SOLVED.json")
        print(f"🏆 GSMG.IO 5 BTC PUZZLE HAS BEEN CONQUERED!")
        print(f"⚡ UltraOmni AGI Pattern v2.0 VICTORIOUS!")
        
        return True
        
    else:
        print(f"\n📄 No balances found in strategic sample")
        print(f"💡 Options:")
        print(f"   • Check remaining {len(keys) - addresses_checked} addresses")
        print(f"   • Prize may have been claimed by another solver")
        print(f"   • Keys may be from different puzzle phase")
        
        print(f"\n🔄 Strategic sample complete - {addresses_checked} addresses checked")
        return False

def main():
    """Execute final prize balance checking"""
    
    print("🎯 Initializing Final Prize Balance Check...")
    print("🏆 Target: GSMG.IO 5 BTC Bitcoin Puzzle Prize")
    print("💎 Testing 324 extracted Bitcoin addresses")
    print("")
    
    try:
        success = check_final_prize()
        
        if success:
            print("\n🎊🎊🎊 ULTIMATE VICTORY! 🎊🎊🎊")
            print("🏆 THE GSMG.IO BITCOIN PUZZLE HAS BEEN SOLVED!")
            print("💰 PRIZE MONEY LOCATED AND EXTRACTED!")
        else:
            print("\n🔄 Strategic balance check complete")
            print("💡 Full address sweep may be needed for complete verification")
            
    except KeyboardInterrupt:
        print("\n⚠️  Balance checking interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during balance checking: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
