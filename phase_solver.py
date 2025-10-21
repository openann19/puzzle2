#!/usr/bin/env python3
import os
import re
import base64
import hashlib
import subprocess
import argparse
from pathlib import Path

BASE = Path(__file__).resolve().parent
FILES = [
    BASE / "puzzlehunt_gsmgio-5btc-puzzle_ GSMG.IO 5 BTC puzzle hints.html",
    BASE / "page3choiceisanillusioncreatedbetweenthosewithpowerandthosewithoutaveryspecialdessertiwroteitmyself.html",
    BASE / "page489727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32.html",
]
OUTDIR = BASE / "artifacts" / "phase_solver"
OUTDIR.mkdir(parents=True, exist_ok=True)
BLOBDIR = OUTDIR / "blobs"
BLOBDIR.mkdir(parents=True, exist_ok=True)

# Known phase 3 digest explicitly stated in hints file
PHASE3_DIGEST = "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5"
# Known phase 3.2 digest explicitly stated in hints file
PHASE32_DIGEST = "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"

# Small, high-confidence candidate words from riddles (lowercase)
C1 = [
    "jean",                   # first name of Jean Baudrillard (Simulacra and Simulation)
    "baudrillard",            # surname, just in case
    "jeanbaudrillard",        # concatenated
    "choice",                 # merovingian is wrong -> choice is ours
    "freewill",
]
C2 = [
    "giveitone",              # Cheshire Cat: how long is forever? one second -> giveit + one
    "giveitonesec",
    "giveitonesecond",
    "giveit1",
]
C3 = [
    "uncertaintyprinciple",
    "heisenberguncertaintyprinciple",
    "heisenberg",
]

# Build candidate passwords (plain strings); then sha256(lowercase) will be used as openssl -pass pass:<hex>
PLAIN_PW_CANDIDATES = set()
for a in C1:
    PLAIN_PW_CANDIDATES.add(a)
for b in C2:
    PLAIN_PW_CANDIDATES.add(b)
for c in C3:
    PLAIN_PW_CANDIDATES.add(c)
for a in C1:
    for b in C2:
        for c in C3:
            PLAIN_PW_CANDIDATES.add(a + b + c)

# Also include the known Phase 3 and 3.2 digests as passwords for specific blobs
PASS_HEX_CANDIDATES = set([PHASE3_DIGEST, PHASE32_DIGEST])

# Base64 alphabet
B64CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

# Runtime controls (can be overridden via CLI flags)
OPENSSL_TIMEOUT = 3.0  # seconds
FAST_MODE = False


def extract_b64_blobs_from_text(text: str):
    """Extract OpenSSL 'Salted__' base64 blobs. Handles cases with arbitrary whitespace in-between characters."""
    blobs = []
    # Remove all whitespace to make the search simpler for obfuscated sequences like 'U 2 F s d ...'
    compact = re.sub(r"\s+", "", text)
    start = 0
    while True:
        idx = compact.find("U2FsdGVk", start)
        if idx == -1:
            break
        # Collect base64 chars from idx forward
        j = idx
        while j < len(compact) and compact[j] in B64CHARS:
            j += 1
        candidate = compact[idx:j]
        # Basic sanity
        if len(candidate) > 16 and candidate not in blobs:
            blobs.append(candidate)
        start = j
    return blobs


def read_file(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return ""


def _run_openssl(args, b64_data: str):
    # Ensure base64 input ends with a newline for OpenSSL stdin consumption
    if not b64_data.endswith("\n"):
        b64_data = b64_data + "\n"
    return subprocess.run(
        args,
        input=b64_data.encode("ascii"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=OPENSSL_TIMEOUT,
    )


def openssl_decrypt_b64_variants(b64_data: str, pass_str: str, log_label: str | None = None) -> bytes | None:
    """Try multiple OpenSSL enc ciphers and KDF modes with the provided password string.
    Returns first successful plaintext or None."""
    ciphers_all = ["-aes-256-cbc", "-aes-192-cbc", "-aes-128-cbc"]
    ciphers_fast = ["-aes-256-cbc"]
    variants_all = [
        [],
        ["-md", "md5"],
        ["-md", "sha1"],
        ["-md", "sha256"],
        ["-pbkdf2"],
        ["-pbkdf2", "-iter", "1000"],
        ["-pbkdf2", "-iter", "10000"],
    ]
    variants_fast = [
        [],
        ["-md", "md5"],
        ["-md", "sha256"],
        ["-pbkdf2"],
    ]
    ciphers = ciphers_fast if FAST_MODE else ciphers_all
    variants = variants_fast if FAST_MODE else variants_all
    for cipher in ciphers:
        base = ["openssl", "enc", cipher, "-d", "-a", "-pass", f"pass:{pass_str}"]
        for extra in variants:
            proc = _run_openssl(base + extra, b64_data)
            if proc.returncode == 0 and proc.stdout:
                return proc.stdout
            # For known digests, log one-line errors to help debugging
            if log_label and proc.stderr:
                err = proc.stderr.decode(errors="ignore").strip().splitlines()[-1:]
                if err:
                    print(f"[{log_label}] {cipher} mode {' '.join(extra) or 'default'} -> {err[0]}")
    return None


def is_plausible_text(data: bytes) -> bool:
    if not data:
        return False
    # Consider plausible if >= 85% printable or common ASCII + newlines
    printable = sum(1 for b in data if (32 <= b <= 126) or b in (9, 10, 13))
    ratio = printable / len(data)
    # Relax a bit; some outputs may contain symbols or sparse binary
    return ratio >= 0.6


def main(args):
    all_blobs = []
    # Optionally scan the HTML sources unless restricted to recovered blobs only
    if not getattr(args, 'only_rec', False):
        for fp in FILES:
            text = read_file(fp)
            if not text:
                continue
            blobs = extract_b64_blobs_from_text(text)
            for i, b in enumerate(blobs):
                all_blobs.append((fp.name, i, b))
    # Also load any recovered base64 blobs saved by analyzer into BLOBDIR
    if getattr(args, 'glob', None):
        extra_patterns = args.glob
    else:
        extra_patterns = ['*.b64', '*_b64.txt', '*_raw2b64.txt']
    extra_files = []
    for pat in extra_patterns:
        extra_files.extend(BLOBDIR.glob(pat))
    if extra_files:
        for ef in extra_files:
            try:
                b64s = ef.read_text(encoding='utf-8', errors='ignore')
                # pick only base64 alphabet to be safe
                compact = re.sub(r"\s+", "", b64s)
                if 'U2FsdGVk' in compact and len(compact) > 16:
                    all_blobs.append((ef.name, 0, compact))
            except Exception:
                pass

    # Deduplicate by content
    seen = {}
    uniq = []
    for src, idx, b64s in all_blobs:
        if b64s not in seen:
            seen[b64s] = (src, idx)
            uniq.append((src, idx, b64s))

    print(f"Found {len(uniq)} unique Salted__ base64 blobs.")
    # Save all blobs to disk for manual testing
    for src, idx, b64s in uniq:
        safe_src = src.replace(" ", "_")
        blob_path = BLOBDIR / f"{safe_src}_{idx}.b64"
        blob_path.write_text(b64s)
    print(f"Saved blobs to {BLOBDIR}")

    hits = []
    derived_passes = set()

    # Try the known Phase 3 and Phase 3.2 digests first (lower and UPPER hex)
    for known_label, known_pass in (("PHASE3DIGEST", PHASE3_DIGEST), ("PHASE32DIGEST", PHASE32_DIGEST)):
        for src, idx, b64s in uniq:
            for pstr in (known_pass, known_pass.upper()):
                pt = openssl_decrypt_b64_variants(b64s, pstr, log_label=known_label)
                if pt:
                    # Save regardless of plausibility for known digests
                    outf = OUTDIR / f"hit_{src}_{idx}_pass_{known_label}.txt"
                    outf.write_bytes(pt)
                    print(f"HIT(with {known_label}) {src} #{idx} -> {outf} (len={len(pt)})")
                    # Preview
                    preview = OUTDIR / f"hit_{src}_{idx}_pass_{known_label}.preview.txt"
                    preview.write_text(pt.decode(errors='ignore')[:600])
                    hits.append((src, idx, known_label, len(pt)))
                    if getattr(args, 'limit_hits', 0) and len(hits) >= args.limit_hits:
                        print("Hit limit reached during known-digest pass. Stopping early.")
                        print_summary(hits)
                        return
                    # Derive next-phase pass candidates from plaintext bytes and simple transforms
                    cand_hexes = set()
                    cand_hexes.add(hashlib.sha256(pt).hexdigest())
                    cand_hexes.add(hashlib.sha256(pt[::-1]).hexdigest())
                    try:
                        cand_hexes.add(hashlib.sha256(pt.hex().encode('ascii')).hexdigest())
                    except Exception:
                        pass
                    try:
                        b64 = base64.b64encode(pt)
                        cand_hexes.add(hashlib.sha256(b64).hexdigest())
                    except Exception:
                        pass
                    # double SHA on raw bytes and on hex string
                    cand_hexes.add(hashlib.sha256(hashlib.sha256(pt).digest()).hexdigest())
                    cand_hexes.add(hashlib.sha256(hashlib.sha256(pt).hexdigest().encode('ascii')).hexdigest())
                    derived_passes.update(cand_hexes)
                    print(f"Derived {len(cand_hexes)} next-pass candidates from {known_label}")

    # If only known digests requested, stop here
    if getattr(args, 'known_only', False):
        print_summary(hits)
        return

    # Include any digests derived from hits
    if derived_passes:
        PASS_HEX_CANDIDATES.update(derived_passes)
        print(f"Added {len(derived_passes)} derived pass candidates from hits.")

    # Build hex password candidates from plaintext candidates
    for pw in sorted(PLAIN_PW_CANDIDATES):
        pass_hex = hashlib.sha256(pw.encode()).hexdigest()
        PASS_HEX_CANDIDATES.add(pass_hex)

    # Try the union of all pass hex candidates on all blobs
    tried = 0
    for src, idx, b64s in uniq:
        for pass_hex in PASS_HEX_CANDIDATES:
            for pstr in (pass_hex, pass_hex.upper()):
                tried += 1
                # try both lower/upper hex and multiple KDF modes
                pt = openssl_decrypt_b64_variants(b64s, pstr)
                if pt:
                    # Save regardless of plausibility; a valid padding means a likely correct pass
                    if pass_hex == PHASE3_DIGEST:
                        label = "phase3"
                    elif pass_hex == PHASE32_DIGEST:
                        label = "phase3_2"
                    else:
                        label = pass_hex[:12]
                    outf = OUTDIR / f"hit_{src}_{idx}_pass_{label}.txt"
                    outf.write_bytes(pt)
                    print(f"HIT {src} #{idx} pass:{label} -> {outf} (len={len(pt)})")
                    # Also save a preview
                    preview = OUTDIR / f"hit_{src}_{idx}_pass_{label}.preview.txt"
                    preview.write_text(pt.decode(errors='ignore')[:600])
                    hits.append((src, idx, label, len(pt)))
                    if getattr(args, 'limit_hits', 0) and len(hits) >= args.limit_hits:
                        print("Hit limit reached. Stopping early.")
                        print_summary(hits)
                        return
                    # Derive next-phase pass candidates from plaintext bytes and simple transforms
                    cand_hexes = set()
                    cand_hexes.add(hashlib.sha256(pt).hexdigest())
                    cand_hexes.add(hashlib.sha256(pt[::-1]).hexdigest())
                    try:
                        cand_hexes.add(hashlib.sha256(pt.hex().encode('ascii')).hexdigest())
                    except Exception:
                        pass
                    try:
                        b64 = base64.b64encode(pt)
                        cand_hexes.add(hashlib.sha256(b64).hexdigest())
                    except Exception:
                        pass
                    cand_hexes.add(hashlib.sha256(hashlib.sha256(pt).digest()).hexdigest())
                    cand_hexes.add(hashlib.sha256(hashlib.sha256(pt).hexdigest().encode('ascii')).hexdigest())
                    for dhex2 in cand_hexes:
                        if dhex2 not in PASS_HEX_CANDIDATES:
                            print(f"Derived next-pass candidate from pass {label}: {dhex2}")
                    derived_passes.update(cand_hexes)

    print_summary(hits)

def print_summary(hits):
    # Summary
    print("\nSummary:")
    for src, idx, label, n in hits:
        print(f" - {src} block #{idx} with pass {label} -> {n} bytes")
    if not hits:
        print("No plausible plaintext hits. Consider adjusting candidate list.")
    else:
        print(f"Saved {len(hits)} plaintext candidates into {OUTDIR}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument('--only-rec', action='store_true', help='only load recovered blobs from artifacts/phase_solver/blobs (skip HTML scan)')
    ap.add_argument('--glob', action='append', help='glob pattern(s) within blobs/ to include (e.g., rec_*_raw2b64.txt). Can repeat.')
    ap.add_argument('--known-only', action='store_true', help='only try known PHASE3/PHASE32 digests and stop')
    ap.add_argument('--fast', action='store_true', help='restrict to aes-256-cbc and a subset of KDF modes for speed')
    ap.add_argument('--limit-hits', type=int, default=0, help='stop after N hits (0 = no limit)')
    ap.add_argument('--timeout', type=float, default=OPENSSL_TIMEOUT, help='per-openssl run timeout seconds')
    args = ap.parse_args()
    # set globals
    if args.fast:
        FAST_MODE = True
    OPENSSL_TIMEOUT = float(args.timeout)
    try:
        main(args)
    except subprocess.TimeoutExpired:
        print("OpenSSL call timed out. Consider increasing --timeout.")
