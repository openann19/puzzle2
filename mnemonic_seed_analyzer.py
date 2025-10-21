#!/usr/bin/env python3
"""
Mnemonic Seed Analyzer - Check for BIP39 mnemonic phrases
The user suggested "half and better half" might refer to mnemonic seed words!
"""

import sys
import hashlib
import re

sys.path.append('/home/ben/Desktop/puzzle/btc_venv/lib/python3.12/site-packages')

try:
    import bitcoin
    CRYPTO_AVAILABLE = True
    print("✅ Bitcoin library available")
except ImportError as e:
    print(f"❌ Bitcoin library not available: {e}")
    CRYPTO_AVAILABLE = False

# BIP39 word list (first 100 common words to test)
BIP39_COMMON_WORDS = [
    'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd', 'abuse',
    'access', 'accident', 'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act',
    'action', 'actor', 'actress', 'actual', 'adapt', 'add', 'addict', 'address', 'adjust', 'admit',
    'adult', 'advance', 'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age', 'agent',
    'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album', 'alcohol', 'alert',
    'alien', 'all', 'alley', 'allow', 'almost', 'alone', 'alpha', 'already', 'also', 'alter',
    'always', 'amateur', 'amazing', 'among', 'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger',
    'angle', 'angry', 'animal', 'ankle', 'announce', 'annual', 'another', 'answer', 'antenna', 'antique',
    'anxiety', 'any', 'apart', 'apology', 'appear', 'apple', 'approve', 'april', 'area', 'arena',
    'argue', 'arm', 'armed', 'armor', 'army', 'around', 'arrange', 'arrest', 'arrive', 'arrow',
    'art', 'article', 'artist', 'artwork', 'ask', 'aspect', 'assault', 'asset', 'assist', 'assume'
]

def load_puzzle_text_sources():
    """Load all puzzle text sources to search for mnemonic words"""
    text_sources = {}
    
    files_to_check = [
        'SalPhaseIon.md',
        'theseedisplantedpage2.md', 
        'githubpage.md'
    ]
    
    for filename in files_to_check:
        try:
            with open(filename, 'r') as f:
                text_sources[filename] = f.read()
        except FileNotFoundError:
            print(f"⚠️ File not found: {filename}")
    
    return text_sources

def extract_potential_mnemonic_words(text):
    """Extract words that could be BIP39 mnemonic words"""
    # Clean text and extract words
    words = re.findall(r'\b[a-z]+\b', text.lower())
    
    # Filter for words that match BIP39 pattern (3-8 characters typically)
    potential_words = []
    for word in words:
        if 3 <= len(word) <= 8 and word.isalpha():
            potential_words.append(word)
    
    return potential_words

def find_bip39_matches(words):
    """Find words that match the BIP39 word list"""
    matches = []
    for word in words:
        if word in BIP39_COMMON_WORDS:
            matches.append(word)
    return matches

def test_mnemonic_combinations():
    """Test different ways to find 'half and better half' mnemonic phrases"""
    
    print("🔍 ANALYZING PUZZLE TEXT FOR MNEMONIC SEED WORDS")
    print("="*60)
    
    text_sources = load_puzzle_text_sources()
    all_potential_words = []
    
    for filename, content in text_sources.items():
        print(f"\n📄 Analyzing {filename}:")
        
        # Extract potential mnemonic words
        potential_words = extract_potential_mnemonic_words(content)
        bip39_matches = find_bip39_matches(potential_words)
        
        print(f"   Potential words: {len(potential_words)}")
        print(f"   BIP39 matches: {len(bip39_matches)}")
        
        if bip39_matches:
            print(f"   Matches found: {bip39_matches[:10]}")  # Show first 10
            all_potential_words.extend(bip39_matches)
    
    # Remove duplicates while preserving order
    unique_words = []
    seen = set()
    for word in all_potential_words:
        if word not in seen:
            unique_words.append(word)
            seen.add(word)
    
    print(f"\n🎯 TOTAL UNIQUE BIP39 WORDS FOUND: {len(unique_words)}")
    if unique_words:
        print(f"Words: {unique_words}")
    
    return unique_words

def test_successful_passwords_as_mnemonic_source():
    """Test if our successful passwords contain mnemonic-related content"""
    
    print(f"\n🔑 TESTING SUCCESSFUL PASSWORDS FOR MNEMONIC CONTENT")
    print("="*55)
    
    successful_elements = [
        'matrixsumlist',
        'enter',
        'lastwordsbeforearchichoice', 
        'thispassword',
        'SalPhaseIon',
        'CosmicDuality'
    ]
    
    for element in successful_elements:
        print(f"\n📝 Analyzing: '{element}'")
        
        # Check if element contains potential mnemonic words
        words = extract_potential_mnemonic_words(element)
        bip39_matches = find_bip39_matches(words)
        
        if bip39_matches:
            print(f"   BIP39 matches: {bip39_matches}")
        
        # Try splitting the element (for "half and better half")
        if len(element) >= 6:
            mid = len(element) // 2
            first_half = element[:mid]
            second_half = element[mid:]
            
            print(f"   Half split: '{first_half}' | '{second_half}'")
            
            # Check if halves are BIP39 words
            if first_half in BIP39_COMMON_WORDS:
                print(f"   🎯 FIRST HALF IS BIP39 WORD: {first_half}")
            if second_half in BIP39_COMMON_WORDS:
                print(f"   🎯 SECOND HALF IS BIP39 WORD: {second_half}")

def test_decoded_segments_as_mnemonic():
    """Test our decoded segments from the puzzle for mnemonic words"""
    
    print(f"\n📊 TESTING DECODED SEGMENTS FOR MNEMONIC WORDS")
    print("="*50)
    
    # From our previous analysis, we know these decoded segments:
    decoded_segments = [
        'lastwordsbeforearchichoice',
        'thispassword',
        'matrixsumlist',
        'enter'
    ]
    
    for segment in decoded_segments:
        words = extract_potential_mnemonic_words(segment)
        bip39_matches = find_bip39_matches(words)
        
        print(f"Segment: {segment}")
        if bip39_matches:
            print(f"  🎯 BIP39 matches: {bip39_matches}")
        else:
            print(f"  ❌ No BIP39 matches")

def generate_mnemonic_based_private_keys(mnemonic_words):
    """Generate private keys from potential mnemonic phrases"""
    
    if not CRYPTO_AVAILABLE or len(mnemonic_words) < 12:
        print(f"❌ Need at least 12 words for mnemonic phrase (found {len(mnemonic_words)})")
        return []
    
    print(f"\n🔑 GENERATING PRIVATE KEYS FROM MNEMONIC PHRASES")
    print("="*55)
    
    # Try different combinations of 12 words
    if len(mnemonic_words) >= 12:
        # Test first 12 words
        mnemonic_phrase = ' '.join(mnemonic_words[:12])
        print(f"Testing mnemonic: {mnemonic_phrase}")
        
        try:
            # This would require a proper BIP39/BIP44 implementation
            # For now, let's hash the mnemonic to create a private key
            seed = hashlib.sha256(mnemonic_phrase.encode()).hexdigest()
            print(f"Generated seed: {seed}")
            
            # Test if this seed generates the prize address
            if is_valid_private_key(seed):
                address = bitcoin.privkey_to_address(seed)
                print(f"Address: {address}")
                
                if address == "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe":
                    print(f"🎉🎉🎉 PRIZE ADDRESS MATCH! 🎉🎉🎉")
                    return [{'mnemonic': mnemonic_phrase, 'private_key': seed, 'address': address}]
            
        except Exception as e:
            print(f"❌ Error testing mnemonic: {e}")
    
    return []

def is_valid_private_key(key_hex):
    """Check if private key is valid"""
    try:
        key_int = int(key_hex, 16)
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        return 1 <= key_int < secp256k1_order
    except:
        return False

def main():
    """Main execution"""
    
    print("🌱 MNEMONIC SEED PHRASE ANALYSIS")
    print("="*70)
    print("Testing if 'half and better half' refers to BIP39 mnemonic seed words")
    print()
    
    # Test 1: Find BIP39 words in puzzle text
    mnemonic_words = test_mnemonic_combinations()
    
    # Test 2: Check successful passwords for mnemonic content  
    test_successful_passwords_as_mnemonic_source()
    
    # Test 3: Check decoded segments
    test_decoded_segments_as_mnemonic()
    
    # Test 4: Try to generate keys from found words
    if len(mnemonic_words) >= 12:
        results = generate_mnemonic_based_private_keys(mnemonic_words)
        if results:
            print(f"\n🏆 SUCCESS: Found mnemonic-based solution!")
        else:
            print(f"\n🔄 No mnemonic-based solution found yet")
    else:
        print(f"\n📝 Need to find more BIP39 words (found {len(mnemonic_words)}, need 12)")
    
    print(f"\n💡 NEXT STEPS FOR MNEMONIC ANALYSIS:")
    print(f"   1. Check if our 987-byte decrypted data contains a word list")
    print(f"   2. Look for 12/18/24 word patterns in puzzle phases")
    print(f"   3. Try BIP39 seed generation from successful password components")
    print(f"   4. Check if 'matrix', 'sum', 'list' could be part of mnemonic")

if __name__ == "__main__":
    main()
