#!/usr/bin/env python3
"""
PRIZE ADDRESS MATCHER - Check if we have the private key for the prize address
Target: 1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe (THE ACTUAL GSMG.IO PRIZE ADDRESS!)
"""

import json
import sys

sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    import bitcoin
    BITCOIN_AVAILABLE = True
except ImportError:
    BITCOIN_AVAILABLE = False
    print("❌ Bitcoin library not available")

class PrizeAddressMatcher:
    def __init__(self):
        self.target_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
        self.extracted_keys = []
        
    def load_extracted_keys(self):
        """Load our 324 extracted keys"""
        try:
            with open('binary_extracted_keys.json', 'r') as f:
                data = json.load(f)
                self.extracted_keys = data['keys']
                print(f"✅ Loaded {len(self.extracted_keys)} extracted keys")
                return True
        except Exception as e:
            print(f"❌ Error loading keys: {e}")
            return False
    
    def check_direct_match(self):
        """Check if target address is directly in our extracted keys"""
        print(f"\n🔍 Checking for direct match with target address...")
        print(f"🎯 Target: {self.target_address}")
        
        matches = []
        for i, key_info in enumerate(self.extracted_keys):
            if key_info['address'] == self.target_address:
                matches.append({
                    'index': i,
                    'private_key': key_info['private_key'],
                    'method': key_info['method'],
                    'source': key_info['source']
                })
                
        if matches:
            print(f"\n🎉🎉🎉 DIRECT MATCH FOUND! 🎉🎉🎉")
            for match in matches:
                print(f"✅ Match #{match['index']+1}:")
                print(f"   Private Key: {match['private_key']}")
                print(f"   Method: {match['method']}")
                print(f"   Source: {match['source']}")
                
                # Save the winning key immediately
                with open('PRIZE_ADDRESS_PRIVATE_KEY.json', 'w') as f:
                    json.dump({
                        'GSMG_IO_PRIZE_ADDRESS': self.target_address,
                        'PRIVATE_KEY': match['private_key'],
                        'EXTRACTION_METHOD': match['method'],
                        'SOURCE_PASSWORD': match['source'],
                        'PUZZLE_STATUS': 'SOLVED - PRIVATE KEY FOUND!',
                        'BLOCKCHAIN_EXPLORER': f"https://www.blockchain.com/explorer/addresses/btc/{self.target_address}"
                    }, f, indent=2)
                
                print(f"💾 PRIZE KEY SAVED: PRIZE_ADDRESS_PRIVATE_KEY.json")
            
            return True
        else:
            print(f"❌ No direct match found in extracted keys")
            return False
    
    def derive_from_puzzle_elements(self):
        """Try to derive the private key from puzzle elements"""
        print(f"\n🧩 Attempting to derive private key from puzzle elements...")
        
        if not BITCOIN_AVAILABLE:
            print("❌ Cannot derive - bitcoin library not available")
            return False
        
        # Known puzzle elements that might generate this address
        puzzle_elements = [
            "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
            "gsmg.io/puzzle",
            "matrixsumlist",
            "SalPhaseIon", 
            "CosmicDuality",
            "causality",
            "theflowerblossomsthroughwhatseemstobeaconcretesurface",
            "yourfirsthintisyourlastcommand",
            "thematrixhasyou",
            "priseurl"
        ]
        
        import hashlib
        from Crypto.Protocol.KDF import PBKDF2
        from Crypto.Hash import SHA256
        
        for element in puzzle_elements:
            # Try direct SHA256
            try:
                key_hash = hashlib.sha256(element.encode()).hexdigest()
                if self.test_private_key(key_hash):
                    return key_hash
            except:
                pass
            
            # Try PBKDF2 variations
            for salt_text in ['', 'puzzle', 'bitcoin', 'gsmg']:
                for iterations in [1000, 10000, 100000]:
                    try:
                        salt = salt_text.encode() if salt_text else b''
                        derived_key = PBKDF2(element.encode(), salt, 32, count=iterations, hmac_hash_module=SHA256)
                        key_hex = derived_key.hex()
                        
                        if self.test_private_key(key_hex):
                            print(f"🎯 DERIVED KEY FOUND!")
                            print(f"   Element: {element}")
                            print(f"   Salt: '{salt_text}'")
                            print(f"   Iterations: {iterations}")
                            return key_hex
                    except:
                        pass
        
        return None
    
    def test_private_key(self, private_key_hex):
        """Test if a private key generates the target address"""
        try:
            if len(private_key_hex) != 64:
                return False
            
            # Validate key range
            key_int = int(private_key_hex, 16)
            secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            if not (1 <= key_int < secp256k1_order):
                return False
            
            # Generate address
            generated_address = bitcoin.privkey_to_address(private_key_hex)
            
            if generated_address == self.target_address:
                print(f"✅ PRIVATE KEY FOUND!")
                print(f"   Private Key: {private_key_hex}")
                print(f"   Generated Address: {generated_address}")
                print(f"   Target Address: {self.target_address}")
                
                # Save immediately
                with open('PRIZE_ADDRESS_PRIVATE_KEY.json', 'w') as f:
                    json.dump({
                        'GSMG_IO_PRIZE_ADDRESS': self.target_address,
                        'PRIVATE_KEY': private_key_hex,
                        'PUZZLE_STATUS': 'SOLVED - DERIVED PRIVATE KEY!',
                        'BLOCKCHAIN_EXPLORER': f"https://www.blockchain.com/explorer/addresses/btc/{self.target_address}"
                    }, f, indent=2)
                
                return True
            
            return False
        except Exception as e:
            return False
    
    def analyze_address_pattern(self):
        """Analyze the target address for patterns"""
        print(f"\n🔍 Analyzing target address pattern...")
        print(f"Address: {self.target_address}")
        print(f"Length: {len(self.target_address)}")
        print(f"Starts with: {self.target_address[:4]}")
        print(f"Ends with: {self.target_address[-4:]}")
        
        # Check if it contains puzzle elements
        puzzle_hints = ['GSMG', 'BTC', 'JC9', 'prBe']
        found_hints = [hint for hint in puzzle_hints if hint in self.target_address]
        
        if found_hints:
            print(f"🎯 Found puzzle hints in address: {found_hints}")
            
        # The address contains "GSMG" and other puzzle elements - this is clearly the designed prize address!
    
    def execute_matching(self):
        """Execute complete prize address matching"""
        
        print("🚀 PRIZE ADDRESS MATCHER - FINDING THE PRIVATE KEY")
        print("="*70)
        print(f"🎯 Target Prize Address: {self.target_address}")
        print(f"🔗 Blockchain Explorer: https://www.blockchain.com/explorer/addresses/btc/{self.target_address}")
        
        # Analyze the address
        self.analyze_address_pattern()
        
        # Load our extracted keys
        if not self.load_extracted_keys():
            return False
        
        # Check for direct match first
        if self.check_direct_match():
            print("\n🎉 SUCCESS! Private key found in extracted keys!")
            return True
        
        # Try to derive from puzzle elements
        print(f"\n🔄 No direct match - attempting derivation...")
        derived_key = self.derive_from_puzzle_elements()
        
        if derived_key:
            print(f"\n🎉 SUCCESS! Private key derived from puzzle elements!")
            return True
        else:
            print(f"\n🤔 Private key not found in current analysis")
            print(f"💡 This may require additional puzzle phases or methods")
            return False

def main():
    """Execute prize address matching"""
    
    print("🎯 Initializing Prize Address Matcher...")
    print("🏆 Target: THE ACTUAL GSMG.IO PRIZE ADDRESS!")
    print("")
    
    matcher = PrizeAddressMatcher()
    success = matcher.execute_matching()
    
    if success:
        print("\n🎊🎊🎊 ULTIMATE VICTORY! 🎊🎊🎊")
        print("🔑 PRIVATE KEY FOR PRIZE ADDRESS FOUND!")
        print("💰 READY TO CLAIM THE GSMG.IO BITCOIN PRIZE!")
        print("🏆 PUZZLE COMPLETELY SOLVED!")
    else:
        print("\n🔄 Analysis complete - additional methods may be needed")
        print("💡 The prize address is confirmed but private key derivation continues")

if __name__ == "__main__":
    main()
