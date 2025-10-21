#!/usr/bin/env python3
"""
Phase 2 Riddle Solver for GSMG.IO 5 BTC Puzzle
Systematically solves the 7 riddles to generate SHA-256 password for Phase 2 AES decryption
"""

import hashlib
import subprocess
import itertools
import re
import os

def extract_phase2_blob():
    """Extract Phase 2 AES blob from HTML file"""
    html_file = 'page3choiceisanillusioncreatedbetweenthosewithpowerandthosewithoutaveryspecialdessertiwroteitmyself.html'
    
    with open(html_file, 'r') as f:
        content = f.read()
    
    # Find the first textarea (Phase 2)
    textarea_match = re.search(r'<textarea[^>]*>(.*?)</textarea>', content, re.DOTALL)
    if not textarea_match:
        raise ValueError("Could not extract Phase 2 blob from HTML")
    
    return textarea_match.group(1).strip()

def test_decryption(password_hash, blob_b64, method_args, method_name):
    """Test AES-256-CBC decryption with given password"""
    
    # Save blob to temp file
    with open('temp_phase2.b64', 'w') as f:
        f.write(blob_b64)
    
    try:
        cmd = ['openssl', 'enc', '-aes-256-cbc', '-d'] + method_args + [
            '-pass', f'pass:{password_hash}',
            '-base64', '-in', 'temp_phase2.b64'
        ]
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        
        if result.returncode == 0 and result.stdout:
            decrypted = result.stdout
            
            try:
                text = decrypted.decode('utf-8', errors='ignore').strip()
                
                # Check if this looks like valid decrypted content
                if len(text) > 30:
                    printable_ratio = sum(c.isprintable() for c in text) / len(text)
                    word_count = len(text.split())
                    
                    # Valid text should be mostly printable with reasonable words
                    if printable_ratio > 0.85 and word_count > 3:
                        return True, text
                        
            except UnicodeDecodeError:
                pass
                
    except Exception:
        pass
    finally:
        if os.path.exists('temp_phase2.b64'):
            os.remove('temp_phase2.b64')
    
    return False, None

def solve_riddles():
    """Systematically solve all 7 Phase 2 riddles"""
    
    print("🧩 PHASE 2 RIDDLE SOLVER")
    print("=" * 60)
    
    # Extract the encrypted blob
    phase2_blob = extract_phase2_blob()
    print(f"✅ Phase 2 blob extracted: {len(phase2_blob)} characters")
    
    # Define possible answers for each of the 7 riddles
    riddle_solutions = {
        1: ['1', 'keymaker', 'matrix', 'private'],                    # Matrix keymaker
        2: ['thevenin', 'norton', 'insecure'],                       # Norton competitor  
        3: ['leon', 'vatican', 'belize', 'poor', 'holy', 'see'],     # Poorest land
        4: ['nixon', 'dirty', 'richard', 'jim', 'bill', 'gates'],    # Rulers with characteristics
        5: ['00001', '11111', '10101', '01010', '11010', '10110'],   # 5-bit binary explicit
        6: ['b', 'bishop', 'move', 'check'],                         # Chess buddhist
        7: ['times', 'chancellor', 'bailout', 'banks', '1616']       # Genesis raw data
    }
    
    print("\n🔍 Testing high-probability combinations:")
    
    # High-probability combinations based on careful riddle analysis
    priority_combinations = [
        ['keymaker', 'thevenin', 'leon', 'nixon', '11111', 'b', 'times'],
        ['1', 'thevenin', 'vatican', 'dirty', '10101', 'bishop', 'chancellor'],
        ['matrix', 'thevenin', 'belize', 'richard', '01010', 'move', 'bailout'],
        ['keymaker', 'thevenin', 'poor', 'jim', '00001', 'b', 'chancellor'],
        ['1', 'thevenin', 'holy', 'nixon', '11010', 'bishop', 'times'],
        ['keymaker', 'thevenin', 'vatican', 'gates', '11111', 'check', 'bailout'],
        ['matrix', 'thevenin', 'see', 'bill', '10110', 'move', 'banks'],
    ]
    
    # Test priority combinations first
    for i, parts in enumerate(priority_combinations):
        success = test_combination(parts, phase2_blob, f"Priority-{i+1}")
        if success:
            return True
    
    print("\n🔄 Testing systematic combinations:")
    
    # Generate more systematic combinations (limit to avoid infinite testing)
    count = 0
    max_tests = 100
    
    for combo in itertools.product(
        riddle_solutions[1][:2],  # Limit each to top answers
        riddle_solutions[2][:2], 
        riddle_solutions[3][:3],
        riddle_solutions[4][:3], 
        riddle_solutions[5][:4],
        riddle_solutions[6][:2],
        riddle_solutions[7][:3]
    ):
        if count >= max_tests:
            break
            
        success = test_combination(list(combo), phase2_blob, f"Sys-{count+1}")
        if success:
            return True
            
        count += 1
    
    print(f"\n❌ Tested {count + len(priority_combinations)} combinations without success")
    print("🔍 May need to reconsider riddle interpretations...")
    return False

def test_combination(parts, blob_b64, test_id):
    """Test a specific 7-part combination"""
    
    combined = ''.join(parts)
    password_hash = hashlib.sha256(combined.encode()).hexdigest()
    
    print(f"\n--- {test_id} ---")
    print(f"Parts: {parts}")
    print(f"Combined: {combined}")
    print(f"SHA-256: {password_hash[:32]}...")
    
    # Test different AES decryption methods
    methods = [
        ('SHA256', ['-md', 'sha256']),
        ('PBKDF2-10K', ['-pbkdf2', '-iter', '10000']),
        ('MD5', ['-md', 'md5']),
        ('PBKDF2-1K', ['-pbkdf2', '-iter', '1000'])
    ]
    
    for method_name, method_args in methods:
        success, decrypted_text = test_decryption(password_hash, blob_b64, method_args, method_name)
        
        if success:
            print(f"✅ SUCCESS! Method: {method_name}")
            print(f"Decrypted length: {len(decrypted_text)} characters")
            print(f"Preview: {decrypted_text[:200]}...")
            
            # Save the solution
            save_solution(parts, combined, password_hash, method_name, decrypted_text)
            return True
    
    return False

def save_solution(parts, combined, password_hash, method, decrypted_text):
    """Save successful Phase 2 solution"""
    
    solution_file = 'PHASE2_SOLUTION.txt'
    
    with open(solution_file, 'w') as f:
        f.write("🎯 PHASE 2 SOLUTION FOUND!\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Riddle parts: {parts}\n")
        f.write(f"Combined string: {combined}\n")
        f.write(f"SHA-256 password: {password_hash}\n")
        f.write(f"Decryption method: {method}\n\n")
        f.write("DECRYPTED CONTENT:\n")
        f.write("=" * 30 + "\n")
        f.write(decrypted_text)
        f.write("\n\n")
        f.write("🔄 Use this decrypted content to solve Phase 3!\n")
    
    print(f"💾 Solution saved to {solution_file}")

if __name__ == "__main__":
    success = solve_riddles()
    
    if success:
        print("\n🎯 Phase 2 SOLVED! Check PHASE2_SOLUTION.txt")
        print("🔄 Ready to proceed to Phase 3...")
    else:
        print("\n❓ Phase 2 not solved - need different riddle interpretations")
