#!/usr/bin/env python3
# salphaseion_master.py - Unified AES decryption master sweep
import hashlib, base64, subprocess, json, os, time, re, itertools
from multiprocessing import Pool, cpu_count
from pathlib import Path

BLOBS = {
    "salphaseion": "artifacts/blob_8529f6b1df5dd9850e5f3914119059b3855a07963a51eb6efb3346a728a06728.b64",
    "cosmic_duality": "artifacts/blob_92f9dddfdf5cb8722727c95e0120782af3c4fb4c3c78490923e83758760604c5.b64"
}

BASE_SEEDS = [
    "matrixsumlist",
    "thispassword", 
    "lastwordsbeforearchichoice",
    "enter"
]

EXTRA_FILES = [
    "pwlist.txt",
    "candidates_from_unused.txt", 
    "candidates_from_unused_v2.txt",
    "candidates_polybius_tap_vic.txt"
]

# Salt modes: (name, salt_bytes_or_None)
SALTS = [
    ("header", None),  # embedded in blob
    ("none", None),    # -nosalt
    ("literal", b"matrixsumlist"),
    ("sha256_first8", hashlib.sha256(b"matrixsumlist").digest()[:8])
]

# Derivation modes: (name, openssl_args)
DERIVATIONS = [
    ("evp_md5", ["-md", "md5"]),
    ("evp_sha256", ["-md", "sha256"]),
    ("pbkdf2_sha256_1k", ["-pbkdf2", "-iter", "1000", "-md", "sha256"]),
    ("pbkdf2_sha256_10k", ["-pbkdf2", "-iter", "10000", "-md", "sha256"]),
    ("pbkdf2_md5_1k", ["-pbkdf2", "-iter", "1000", "-md", "md5"]),
    ("pbkdf2_md5_10k", ["-pbkdf2", "-iter", "10000", "-md", "md5"])
]

LOGFILE = "salphaseion_master_attempts.jsonl"
SOLUTION_FILE = "salphaseion_solution.txt"

def load_candidates(max_candidates=20000):
    """Load and dedupe all candidates from files"""
    cands = set(BASE_SEEDS)
    
    for fname in EXTRA_FILES:
        if os.path.exists(fname):
            try:
                with open(fname, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        w = line.strip()
                        # Filter: 3-64 chars, printable ASCII only
                        if 3 <= len(w) <= 64 and all(32 <= ord(c) <= 126 for c in w):
                            cands.add(w)
            except Exception as e:
                print(f"Warning: Could not read {fname}: {e}")
    
    result = sorted(cands)[:max_candidates]
    print(f"Loaded {len(result)} base candidates from {len(EXTRA_FILES)} files")
    return result

def variants(word):
    """Generate all variants of a word"""
    out = set()
    
    # Basic variants
    out.add(word)
    out.add(word.lower())
    out.add(word.upper()) 
    out.add(word.title())
    
    # Newline variants
    out.add(word + "\n")
    out.add(word + "\r\n")
    
    # SHA256 hex
    out.add(hashlib.sha256(word.encode()).hexdigest())
    
    # Numeric transformations for short words
    if len(word) <= 10:
        # Try as base64
        try:
            decoded = base64.b64decode(word + "==", validate=False)
            if decoded:
                out.add(decoded.decode('utf-8', 'ignore'))
        except:
            pass
        
        # Try hex decode
        if all(c in '0123456789abcdefABCDEF' for c in word):
            try:
                if len(word) % 2 == 0:
                    decoded = bytes.fromhex(word)
                    if decoded:
                        out.add(decoded.decode('utf-8', 'ignore'))
            except:
                pass
    
    # Filter results and return
    return [v for v in out if v and 1 <= len(v) <= 256 and all(ord(c) <= 127 for c in v)]

def is_plausible_text(data):
    """Check if decrypted data looks like valid plaintext"""
    if not data:
        return False, 0.0
        
    # Check for binary magic numbers first
    magic_patterns = [
        b'PK\x03\x04',  # ZIP
        b'%PDF',        # PDF
        b'\x89PNG',     # PNG
        b'\x1f\x8b',    # GZIP
        b'Rar!',        # RAR
        b'7z\xbc\xaf',  # 7ZIP
        b'\x00\x00\x00\x14ftypmp4', # MP4
    ]
    
    for magic in magic_patterns:
        if data.startswith(magic):
            return True, 1.0
    
    # Try to decode as text
    try:
        text = data.decode('utf-8', 'ignore')
    except:
        try:
            text = data.decode('latin1', 'ignore')
        except:
            return False, 0.0
    
    if not text.strip():
        return False, 0.0
    
    # Calculate printable ratio
    printable_count = sum(1 for c in text if c.isprintable())
    printable_ratio = printable_count / len(text)
    
    # Must be mostly printable
    if printable_ratio < 0.8:
        return False, printable_ratio
    
    # Look for structured data patterns
    structured_patterns = [
        r'^[0-9a-fA-F]{64}$',  # 64-char hex (private key)
        r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$',  # Bitcoin address
        r'^\{.*\}$',  # JSON
        r'^-----BEGIN',  # PEM format
        r'^[a-z]+ [a-z]+ [a-z]+',  # BIP39 seed phrase pattern
        r'private.{0,10}key',  # contains "private key"
        r'bitcoin|btc|satoshi|blockchain',  # crypto related
    ]
    
    text_lower = text.lower()
    for pattern in structured_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE | re.MULTILINE):
            return True, printable_ratio
    
    # Look for english words
    common_words = ['the', 'and', 'to', 'of', 'a', 'in', 'is', 'it', 'you', 'that', 'he', 'was', 'for', 'on', 'are', 'as', 'with', 'his', 'they', 'i', 'at', 'be', 'this', 'have', 'from', 'or', 'one', 'had', 'by', 'word', 'but', 'not', 'what', 'all', 'were', 'we', 'when', 'your', 'can', 'said', 'there', 'each', 'which', 'she', 'do', 'how', 'their', 'if', 'will', 'up', 'other', 'about', 'out', 'many', 'then', 'them', 'these', 'so', 'some', 'her', 'would', 'make', 'like', 'into', 'him', 'has', 'two', 'more', 'go', 'no', 'way', 'could', 'my', 'than', 'first', 'been', 'call', 'who', 'its', 'now', 'find', 'long', 'down', 'day', 'did', 'get', 'come', 'made', 'may', 'part']
    
    word_matches = sum(1 for word in common_words if word in text_lower)
    if word_matches >= 3:  # At least 3 common English words
        return True, printable_ratio
    
    # If high printable ratio and reasonable length, consider plausible
    if printable_ratio >= 0.9 and len(text.strip()) >= 20:
        return True, printable_ratio
        
    return False, printable_ratio

def run_openssl_decrypt(args):
    """Worker function for multiprocessing"""
    blob_name, blob_path, pw, deriv_name, deriv_args, salt_name, salt_bytes = args
    
    try:
        # Read blob data
        with open(blob_path, 'rb') as f:
            blob_data = base64.b64decode(f.read())
        
        # Build OpenSSL command
        cmd = ["openssl", "enc", "-aes-256-cbc", "-d"] + deriv_args
        
        # Handle salt
        if salt_name == "header":
            pass  # Default behavior
        elif salt_name == "none":
            cmd.append("-nosalt")
        elif salt_name in ("literal", "sha256_first8"):
            cmd += ["-S", salt_bytes.hex()]
        
        # Add password
        cmd += ["-pass", f"pass:{pw}"]
        
        # Execute
        proc = subprocess.run(
            cmd, 
            input=blob_data,
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            timeout=30,
            check=False
        )
        
        success = proc.returncode == 0 and b"bad decrypt" not in proc.stderr.lower()
        
        if success and proc.stdout:
            is_plausible, score = is_plausible_text(proc.stdout)
            return {
                "blob": blob_name,
                "password": pw,
                "derivation": deriv_name, 
                "salt": salt_name,
                "success": True,
                "plausible": is_plausible,
                "score": score,
                "data": proc.stdout if is_plausible else None,
                "length": len(proc.stdout),
                "preview": proc.stdout[:200].decode('utf-8', 'ignore').replace('\n', '\\n')
            }
        else:
            return {
                "blob": blob_name,
                "password": pw, 
                "derivation": deriv_name,
                "salt": salt_name,
                "success": False,
                "plausible": False,
                "score": 0.0,
                "data": None,
                "length": 0,
                "preview": ""
            }
            
    except Exception as e:
        return {
            "blob": blob_name,
            "password": pw,
            "derivation": deriv_name,
            "salt": salt_name,
            "success": False,
            "plausible": False, 
            "score": 0.0,
            "data": None,
            "length": 0,
            "preview": f"ERROR: {str(e)}"
        }

def generate_tasks(candidates):
    """Generate all decryption tasks"""
    tasks = []
    
    for blob_name, blob_path in BLOBS.items():
        for cand in candidates:
            for variant in variants(cand):
                for salt_name, salt_bytes in SALTS:
                    for deriv_name, deriv_args in DERIVATIONS:
                        tasks.append((
                            blob_name, blob_path, variant, 
                            deriv_name, deriv_args, salt_name, salt_bytes
                        ))
    
    return tasks

def run_master_sweep(max_candidates=20000):
    """Run the master AES decryption sweep"""
    print("🔥 SALPHASEION MASTER SWEEP INITIATED 🔥")
    print("="*60)
    
    # Load candidates
    candidates = load_candidates(max_candidates)
    
    # Generate all tasks
    tasks = generate_tasks(candidates)
    total_tasks = len(tasks)
    
    print(f"📊 SWEEP PARAMETERS:")
    print(f"   Candidates: {len(candidates)}")
    print(f"   Blobs: {len(BLOBS)}")
    print(f"   Salt modes: {len(SALTS)}")
    print(f"   Derivations: {len(DERIVATIONS)}")
    print(f"   Total tasks: {total_tasks:,}")
    print("="*60)
    
    # Setup multiprocessing
    num_processes = min(cpu_count(), 8)  # Don't overwhelm system
    print(f"🚀 Using {num_processes} processes")
    
    start_time = time.time()
    completed = 0
    hits = 0
    
    try:
        with open(LOGFILE, 'a') as logfile:
            with Pool(num_processes) as pool:
                # Process in chunks for better progress reporting
                chunk_size = max(1, total_tasks // 100)  # 1% chunks
                
                for i in range(0, total_tasks, chunk_size):
                    chunk = tasks[i:i + chunk_size]
                    results = pool.map(run_openssl_decrypt, chunk)
                    
                    for result in results:
                        completed += 1
                        
                        # Log result
                        logfile.write(json.dumps(result) + '\n')
                        logfile.flush()
                        
                        # Check for success
                        if result['plausible']:
                            hits += 1
                            print(f"\n🎯 HIT #{hits}!")
                            print(f"   Blob: {result['blob']}")
                            print(f"   Password: {result['password']}")
                            print(f"   Derivation: {result['derivation']}")
                            print(f"   Salt: {result['salt']}")
                            print(f"   Score: {result['score']:.3f}")
                            print(f"   Length: {result['length']} bytes")
                            print(f"   Preview: {result['preview']}")
                            
                            if result['data']:
                                # Save solution
                                with open(SOLUTION_FILE, 'wb') as f:
                                    f.write(result['data'])
                                print(f"💾 Solution saved to {SOLUTION_FILE}")
                                return True
                        
                        # Progress reporting
                        if completed % 1000 == 0 or completed == total_tasks:
                            elapsed = time.time() - start_time
                            rate = completed / elapsed if elapsed > 0 else 0
                            eta = (total_tasks - completed) / rate if rate > 0 else 0
                            
                            print(f"\r⚡ Progress: {completed:,}/{total_tasks:,} "
                                  f"({100*completed/total_tasks:.1f}%) "
                                  f"| Rate: {rate:.0f}/s "
                                  f"| ETA: {eta/60:.0f}m "
                                  f"| Hits: {hits}", end='', flush=True)
    
    except KeyboardInterrupt:
        print("\n❌ Sweep interrupted by user")
        return False
    
    print(f"\n📋 SWEEP COMPLETED")
    print(f"   Total attempts: {completed:,}")
    print(f"   Total hits: {hits}")
    print(f"   Duration: {(time.time() - start_time)/60:.1f} minutes")
    
    return hits > 0

def expand_mining_fallback():
    """Fallback: expand token mining with more aggressive parameters"""
    print("\n🔄 FALLBACK: Expanding token mining...")
    
    # Re-run miners with more aggressive settings
    fallback_scripts = [
        "python3 mine_unused_tokens_v2.py",
        "python3 polybius_tap_vic.py"
    ]
    
    for script in fallback_scripts:
        try:
            subprocess.run(script.split(), timeout=60, check=False)
        except Exception as e:
            print(f"Warning: {script} failed: {e}")
    
    # Generate additional candidates from SalPhaseIon.md directly
    try:
        with open("SalPhaseIon.md", "r") as f:
            content = f.read()
        
        # Extract more aggressive patterns
        additional = set()
        
        # All 3+ character alphabetic sequences
        for match in re.finditer(r'[a-zA-Z]{3,}', content):
            additional.add(match.group().lower())
        
        # All hex-like sequences
        for match in re.finditer(r'[0-9a-fA-F]{6,}', content):
            additional.add(match.group())
        
        # Save additional candidates
        with open("candidates_fallback.txt", "w") as f:
            for cand in sorted(additional):
                f.write(cand + '\n')
        
        print(f"Generated {len(additional)} fallback candidates")
        
    except Exception as e:
        print(f"Fallback mining failed: {e}")

def main():
    """Main execution loop"""
    attempt = 1
    max_attempts = 3
    
    while attempt <= max_attempts:
        print(f"\n🎯 ATTEMPT {attempt}/{max_attempts}")
        
        success = run_master_sweep(max_candidates=20000)
        
        if success:
            print("🏆 SOLUTION FOUND! Check salphaseion_solution.txt")
            return
        
        if attempt < max_attempts:
            print("❌ No solution found. Expanding search...")
            expand_mining_fallback()
        
        attempt += 1
    
    print("❌ All attempts exhausted. No solution found.")
    print("💡 Consider:")
    print("   - Different cipher algorithms") 
    print("   - Multi-stage decryption")
    print("   - Alternative blob sources")
    print("   - Different key derivation methods")

if __name__ == "__main__":
    main()
