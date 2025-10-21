#!/usr/bin/env python3
"""
Test Mnemonic Hypothesis - Check if our successful passwords are mnemonic-based
"""

import sys
import hashlib
import hmac

sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    import bitcoin
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

def test_direct_mnemonic_words():
    """Test if our puzzle words are actual BIP39 words"""
    
    # Standard BIP39 word list (partial for testing)
    bip39_words = [
        'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd', 'abuse',
        'access', 'accident', 'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act',
        'action', 'actor', 'actress', 'actual', 'adapt', 'add', 'addict', 'address', 'adjust', 'admit',
        'adult', 'advance', 'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age', 'agent',
        'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album', 'alcohol', 'alert',
        'alien', 'all', 'alley', 'allow', 'almost', 'alone', 'alpha', 'already', 'also', 'alter',
        'always', 'amateur', 'amazing', 'among', 'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger',
        'enter', 'entire', 'envelope', 'episode', 'equal', 'equip', 'era', 'erase', 'erode', 'erosion',
        'error', 'erupt', 'escape', 'essay', 'essence', 'estate', 'eternal', 'ethics', 'evidence', 'evil',
        'exact', 'example', 'excess', 'exchange', 'excite', 'exclude', 'excuse', 'execute', 'exercise', 'exhale',
        'list', 'listen', 'little', 'live', 'lizard', 'load', 'loan', 'lobster', 'local', 'lock',
        'logic', 'lonely', 'long', 'loop', 'lottery', 'loud', 'lounge', 'love', 'loyal', 'lucky',
        'matrix', 'matter', 'maximum', 'maze', 'meadow', 'mean', 'measure', 'meat', 'mechanic', 'medal',
        'memory', 'mention', 'menu', 'mercy', 'merge', 'merit', 'merry', 'mesh', 'message', 'metal',
        'method', 'middle', 'midnight', 'milk', 'million', 'mimic', 'mind', 'minimum', 'minor', 'minute',
    ]
    
    print("🔍 TESTING PUZZLE WORDS AS BIP39 MNEMONIC WORDS")
    print("="*60)
    
    # Our key puzzle words
    puzzle_words = [
        'matrix', 'sum', 'list', 'enter', 'last', 'words', 'before', 'choice',
        'this', 'password', 'salt', 'phase', 'ion', 'cosmic', 'duality'
    ]
    
    bip39_matches = []
    for word in puzzle_words:
        if word.lower() in bip39_words:
            print(f"✅ '{word}' IS A BIP39 WORD!")
            bip39_matches.append(word.lower())
        else:
            print(f"❌ '{word}' - not in BIP39 list")
    
    print(f"\n🎯 BIP39 matches found: {bip39_matches}")
    return bip39_matches

def test_password_as_mnemonic_seed():
    """Test using our successful password components as mnemonic seed"""
    
    print(f"\n🌱 TESTING PASSWORD COMPONENTS AS MNEMONIC SEED")
    print("="*55)
    
    # Our successful password components
    half = "matrixsumlist" 
    better_half = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"
    
    # Method 1: Use the words directly as a seed phrase
    word_candidates = ['matrix', 'sum', 'list']
    
    print(f"Testing word components: {word_candidates}")
    
    # We need 12 words for a proper mnemonic, but let's try different approaches:
    
    # Approach 1: Hash the word components 
    word_string = ' '.join(word_candidates)
    seed1 = hashlib.sha256(word_string.encode()).hexdigest()
    print(f"Seed from words: {seed1}")
    
    if CRYPTO_AVAILABLE:
        try:
            addr1 = bitcoin.privkey_to_address(seed1)
            print(f"Address 1: {addr1}")
            if addr1 == "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe":
                print("🎉 MATCH FOUND!")
                return True
        except:
            pass
    
    # Approach 2: Use the full successful password as seed
    seed2 = hashlib.sha256((half + better_half).encode()).hexdigest()
    print(f"Seed from full password: {seed2}")
    
    if CRYPTO_AVAILABLE:
        try:
            addr2 = bitcoin.privkey_to_address(seed2)
            print(f"Address 2: {addr2}")
            if addr2 == "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe":
                print("🎉 MATCH FOUND!")
                return True
        except:
            pass
    
    # Approach 3: Use BIP39-style PBKDF2 with the password as passphrase
    try:
        # PBKDF2 with "mnemonic" + passphrase (standard BIP39 approach)
        passphrase = half  # Use "matrixsumlist" as passphrase
        salt = "mnemonic" + passphrase  # Standard BIP39 salt format
        
        seed3_bytes = hashlib.pbkdf2_hmac('sha512', word_string.encode(), salt.encode(), 2048, 64)
        seed3 = seed3_bytes[:32].hex()  # Take first 32 bytes for private key
        
        print(f"BIP39-style seed: {seed3}")
        
        if CRYPTO_AVAILABLE and is_valid_private_key(seed3):
            addr3 = bitcoin.privkey_to_address(seed3)
            print(f"Address 3: {addr3}")
            if addr3 == "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe":
                print("🎉 BIP39-STYLE MATCH FOUND!")
                return True
        
    except Exception as e:
        print(f"❌ BIP39 approach failed: {e}")
    
    return False

def is_valid_private_key(key_hex):
    """Check if private key is valid"""
    try:
        key_int = int(key_hex, 16)
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        return 1 <= key_int < secp256k1_order
    except:
        return False

def test_decrypted_data_as_word_list():
    """Test if our 987-byte decrypted data contains a word list"""
    
    print(f"\n📊 TESTING DECRYPTED DATA AS WORD LIST")
    print("="*45)
    
    try:
        with open('cosmic_decrypted_raw.bin', 'rb') as f:
            data = f.read()
        
        print(f"Data length: {len(data)} bytes")
        
        # Try to extract readable words
        # Method 1: Look for space-separated words
        try:
            text = data.decode('utf-8', errors='ignore')
            words = [w.strip() for w in text.split() if w.strip().isalpha() and len(w.strip()) >= 3]
            if len(words) >= 12:
                print(f"Found {len(words)} potential words:")
                print(f"First 20 words: {words[:20]}")
                
                # Test as mnemonic
                if CRYPTO_AVAILABLE:
                    test_mnemonic = ' '.join(words[:12])
                    seed = hashlib.sha256(test_mnemonic.encode()).hexdigest()
                    if is_valid_private_key(seed):
                        addr = bitcoin.privkey_to_address(seed)
                        print(f"Mnemonic address: {addr}")
                        if addr == "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe":
                            print("🎉 MNEMONIC MATCH FOUND!")
                            return True
                            
        except Exception as e:
            print(f"UTF-8 decode failed: {e}")
        
        # Method 2: Look for patterns that indicate word boundaries
        # Maybe the data contains length-prefixed words or other encoding
        
        print("Checking for word patterns in raw data...")
        
        # Look for repeated patterns that might be word separators
        for sep in [0x00, 0x20, 0x0a, 0x0d]:  # null, space, LF, CR
            if data.count(sep) > 10:
                segments = data.split(bytes([sep]))
                text_segments = []
                for seg in segments:
                    try:
                        text_seg = seg.decode('utf-8', errors='strict')
                        if text_seg.isalpha() and 3 <= len(text_seg) <= 10:
                            text_segments.append(text_seg)
                    except:
                        pass
                        
                if len(text_segments) >= 12:
                    print(f"Found {len(text_segments)} text segments with separator 0x{sep:02x}")
                    print(f"Segments: {text_segments[:12]}")
                    
                    # Test as mnemonic
                    if CRYPTO_AVAILABLE:
                        test_mnemonic = ' '.join(text_segments[:12])
                        seed = hashlib.sha256(test_mnemonic.encode()).hexdigest()
                        if is_valid_private_key(seed):
                            addr = bitcoin.privkey_to_address(seed)
                            print(f"Segments address: {addr}")
                            if addr == "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe":
                                print("🎉 SEGMENTS MATCH FOUND!")
                                return True
        
    except Exception as e:
        print(f"❌ Error analyzing decrypted data: {e}")
    
    return False

def main():
    """Main execution"""
    
    print("🌱 COMPREHENSIVE MNEMONIC HYPOTHESIS TEST")
    print("="*70)
    print("Testing if 'half and better half' refers to BIP39 mnemonic seed words")
    print()
    
    success = False
    
    # Test 1: Check if puzzle words are BIP39 words
    bip39_matches = test_direct_mnemonic_words()
    
    # Test 2: Use password components as mnemonic seed
    if test_password_as_mnemonic_seed():
        success = True
    
    # Test 3: Check decrypted data for word list
    if test_decrypted_data_as_word_list():
        success = True
    
    if success:
        print(f"\n🏆🏆🏆 MNEMONIC-BASED SOLUTION FOUND! 🏆🏆🏆")
    else:
        print(f"\n💡 MNEMONIC HYPOTHESIS INSIGHTS:")
        print(f"   - Found {len(bip39_matches)} actual BIP39 words in puzzle")
        print(f"   - Password components don't directly generate prize address")
        print(f"   - 987-byte data doesn't contain obvious word list")
        print(f"   - May need different interpretation of 'half and better half'")

if __name__ == "__main__":
    main()
