#!/usr/bin/env python3
"""
Final Transformation Attempts - Try different methods to transform the 
decrypted Cosmic Duality data into the prize private key
"""

import sys
import hashlib
import binascii

sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    import bitcoin
    CRYPTO_AVAILABLE = True
except ImportError as e:
    print(f"❌ Bitcoin library not available: {e}")
    sys.exit(1)

class FinalTransformationAnalyzer:
    def __init__(self):
        self.prize_address = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
        self.puzzle_elements = {
            'matrixsumlist': 'matrixsumlist',
            'enter': 'enter',
            'salphaseion_hash': '89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32',
            'lastwords': 'lastwordsbeforearchichoice',
            'thispassword': 'thispassword'
        }
        
    def load_decrypted_data(self):
        """Load the decrypted Cosmic Duality data"""
        try:
            with open('cosmic_decrypted_raw.bin', 'rb') as f:
                return f.read()
        except FileNotFoundError:
            print("❌ Decrypted data file not found. Run cosmic_extract_and_analyze.py first.")
            return None
    
    def test_private_key(self, private_key_hex):
        """Test if a private key generates the prize address"""
        try:
            if len(private_key_hex) != 64:
                return False
                
            key_int = int(private_key_hex, 16)
            secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            
            if not (1 <= key_int < secp256k1_order):
                return False
                
            generated_address = bitcoin.privkey_to_address(private_key_hex)
            return generated_address == self.prize_address
            
        except:
            return False
    
    def try_hash_combinations(self, data):
        """Try different hash combinations of the decrypted data"""
        print("🔍 TRYING HASH COMBINATIONS")
        print("-" * 40)
        
        transformations = [
            ("SHA256 of full data", lambda d: hashlib.sha256(d).digest()),
            ("MD5 of full data", lambda d: hashlib.md5(d).digest()),
            ("SHA256 + matrixsumlist", lambda d: hashlib.sha256(d + b'matrixsumlist').digest()),
            ("SHA256 + enter", lambda d: hashlib.sha256(d + b'enter').digest()),
            ("SHA256 + SalPhaseIon hash", lambda d: hashlib.sha256(d + self.puzzle_elements['salphaseion_hash'].encode()).digest()),
            ("Double SHA256", lambda d: hashlib.sha256(hashlib.sha256(d).digest()).digest()),
            ("SHA256 of hex string", lambda d: hashlib.sha256(d.hex().encode()).digest()),
        ]
        
        for name, transform_func in transformations:
            try:
                result = transform_func(data)
                
                # Try first 32 bytes as private key
                if len(result) >= 32:
                    private_key_hex = result[:32].hex()
                    if self.test_private_key(private_key_hex):
                        print(f"🎉 FOUND WITH {name}!")
                        print(f"🔑 Private Key: {private_key_hex}")
                        return private_key_hex
                
                # Try full hash as private key if exactly 32 bytes
                if len(result) == 32:
                    private_key_hex = result.hex()
                    if self.test_private_key(private_key_hex):
                        print(f"🎉 FOUND WITH {name}!")
                        print(f"🔑 Private Key: {private_key_hex}")
                        return private_key_hex
                        
                print(f"  ❌ {name}: No match")
                
            except Exception as e:
                print(f"  ❌ {name}: Error - {e}")
        
        return None
    
    def try_half_and_half(self, data):
        """Try 'half and better half' combinations"""
        print("\n🔍 TRYING 'HALF AND BETTER HALF' COMBINATIONS")
        print("-" * 50)
        
        data_len = len(data)
        half_point = data_len // 2
        
        combinations = [
            ("First half", data[:half_point]),
            ("Second half", data[half_point:]),
            ("First half + Second half", data[:half_point] + data[half_point:]),
            ("Second half + First half", data[half_point:] + data[:half_point]),
            ("XOR halves", bytes(a ^ b for a, b in zip(data[:half_point], data[half_point:half_point*2]))),
            ("SHA256(First half + Second half)", hashlib.sha256(data[:half_point] + data[half_point:]).digest()),
            ("SHA256(Second half + First half)", hashlib.sha256(data[half_point:] + data[:half_point]).digest()),
        ]
        
        for name, combined_data in combinations:
            try:
                # Try as direct private key if 32 bytes
                if len(combined_data) == 32:
                    private_key_hex = combined_data.hex()
                    if self.test_private_key(private_key_hex):
                        print(f"🎉 FOUND WITH {name}!")
                        print(f"🔑 Private Key: {private_key_hex}")
                        return private_key_hex
                
                # Try SHA256 hash of combination
                hashed = hashlib.sha256(combined_data).digest()
                private_key_hex = hashed.hex()
                if self.test_private_key(private_key_hex):
                    print(f"🎉 FOUND WITH SHA256({name})!")
                    print(f"🔑 Private Key: {private_key_hex}")
                    return private_key_hex
                    
                print(f"  ❌ {name}: No match")
                
            except Exception as e:
                print(f"  ❌ {name}: Error - {e}")
        
        return None
    
    def try_puzzle_element_combinations(self, data):
        """Try combining with other puzzle elements"""
        print("\n🔍 TRYING PUZZLE ELEMENT COMBINATIONS")
        print("-" * 45)
        
        elements = [
            'matrixsumlist',
            'enter', 
            'lastwordsbeforearchichoice',
            'thispassword',
            'GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe',
            '89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32'
        ]
        
        for element in elements:
            combinations = [
                f"data + {element}",
                f"{element} + data",
                f"SHA256(data + {element})",
                f"SHA256({element} + data)",
            ]
            
            for combo_desc in combinations:
                try:
                    if "data + " in combo_desc and not combo_desc.startswith("SHA256"):
                        combined = data + element.encode()
                    elif " + data" in combo_desc and not combo_desc.startswith("SHA256"):
                        combined = element.encode() + data
                    elif combo_desc.startswith("SHA256(data + "):
                        combined = hashlib.sha256(data + element.encode()).digest()
                    elif combo_desc.startswith("SHA256(") and " + data)" in combo_desc:
                        combined = hashlib.sha256(element.encode() + data).digest()
                    else:
                        continue
                    
                    # Test as private key if 32 bytes
                    if len(combined) == 32:
                        private_key_hex = combined.hex()
                        if self.test_private_key(private_key_hex):
                            print(f"🎉 FOUND WITH {combo_desc}!")
                            print(f"🔑 Private Key: {private_key_hex}")
                            return private_key_hex
                    
                    # Also try SHA256 hash if not already hashed
                    if not combo_desc.startswith("SHA256"):
                        hashed = hashlib.sha256(combined).digest()
                        private_key_hex = hashed.hex()
                        if self.test_private_key(private_key_hex):
                            print(f"🎉 FOUND WITH SHA256({combo_desc})!")
                            print(f"🔑 Private Key: {private_key_hex}")
                            return private_key_hex
                    
                    print(f"  ❌ {combo_desc[:30]}...: No match")
                    
                except Exception as e:
                    print(f"  ❌ {combo_desc[:30]}...: Error")
        
        return None
    
    def try_position_based_extraction(self, data):
        """Try extracting private keys from specific positions"""
        print("\n🔍 TRYING POSITION-BASED EXTRACTION")
        print("-" * 40)
        
        # Try specific positions that might be meaningful
        positions = [0, 32, 64, 96, 128, 256, 512, len(data)//2, len(data)-32]
        
        for pos in positions:
            if pos + 32 <= len(data):
                private_key_hex = data[pos:pos+32].hex()
                if self.test_private_key(private_key_hex):
                    print(f"🎉 FOUND AT POSITION {pos}!")
                    print(f"🔑 Private Key: {private_key_hex}")
                    return private_key_hex
                print(f"  ❌ Position {pos}: No match")
        
        return None
    
    def execute_final_attempts(self):
        """Execute all final transformation attempts"""
        
        print("🚀 FINAL TRANSFORMATION ATTEMPTS")
        print("="*60)
        print(f"🎯 Target: {self.prize_address}")
        
        # Load decrypted data
        data = self.load_decrypted_data()
        if not data:
            return False
        
        print(f"📊 Working with {len(data)} bytes of decrypted data")
        
        # Try different transformation methods
        methods = [
            self.try_hash_combinations,
            self.try_half_and_half,
            self.try_puzzle_element_combinations,
            self.try_position_based_extraction
        ]
        
        for method in methods:
            result = method(data)
            if result:
                # Save the successful result
                import json
                solution = {
                    'PUZZLE_STATUS': 'COMPLETELY SOLVED',
                    'GSMG_IO_PRIZE_ADDRESS': self.prize_address,
                    'PRIVATE_KEY': result,
                    'SOLUTION_METHOD': method.__name__,
                    'DERIVATION_PATH': 'Cosmic Duality AES -> Final Transformation',
                    'SUCCESS': True
                }
                
                with open('GSMGIO_FINAL_SOLUTION.json', 'w') as f:
                    json.dump(solution, f, indent=2)
                
                print(f"\n💾 FINAL SOLUTION SAVED: GSMGIO_FINAL_SOLUTION.json")
                return True
        
        print(f"\n❌ No successful transformation found")
        return False

def main():
    analyzer = FinalTransformationAnalyzer()
    success = analyzer.execute_final_attempts()
    
    if success:
        print(f"\n🎊🎊🎊 ULTIMATE SUCCESS! 🎊🎊🎊")
        print(f"🏆 GSMG.IO 5 BTC PUZZLE COMPLETELY SOLVED!")
    else:
        print(f"\n🔄 All transformation attempts completed")
        print(f"💡 May need additional puzzle analysis or different approach")

if __name__ == "__main__":
    main()
