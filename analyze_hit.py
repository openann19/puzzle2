#!/usr/bin/env python3
import sys, argparse, hashlib, string, base64, zlib, gzip, bz2, lzma
from pathlib import Path

# Decompressors can be unsafe/expensive on random inputs. Disabled by default.
ALLOW_DECOMPRESS = False

def printable_ratio(b: bytes) -> float:
    pr = sum(1 for x in b if (32 <= x <= 126) or x in (9,10,13))
    return pr / max(1, len(b))

def strings_extract(b: bytes, minlen=3):
    s = []
    cur = []
    for x in b:
        if 32 <= x <= 126:
            cur.append(chr(x))
        else:
            if len(cur) >= minlen:
                s.append(''.join(cur))
            cur = []
    if len(cur) >= minlen:
        s.append(''.join(cur))
    return s

def invert_bytes(b: bytes) -> bytes:
    return bytes([x ^ 0xFF for x in b])

def swap_nibbles(b: bytes) -> bytes:
    return bytes([((x & 0x0F) << 4) | ((x & 0xF0) >> 4) for x in b])

def rotl(b: bytes, k=1) -> bytes:
    out = bytearray()
    for x in b:
        out.append(((x << k) & 0xFF) | (x >> (8 - k)))
    return bytes(out)

def rotr(b: bytes, k=1) -> bytes:
    out = bytearray()
    for x in b:
        out.append((x >> k) | ((x << (8 - k)) & 0xFF))
    return bytes(out)

def try_keyed_xor(name: str, key: bytes, data: bytes):
    if not key:
        return None
    out = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    ratio = printable_ratio(out)
    head = out[:32]
    found = b'Salted__' in out or b'U2FsdGVk' in out
    if ratio >= 0.6 or found:
        print(f"XOR with {name}: printable {ratio:.2f}; head: {head.hex()} foundSalt={found}")
        ss = strings_extract(out, 4)[:10]
        print(f"  Strings: {ss}")
    return out if found else None

def try_b64_from_bytes(b: bytes):
    # filter only base64 alphabet from bytes as latin1
    txt = b.decode('latin1', errors='ignore')
    filt = ''.join(ch for ch in txt if ch.isalnum() or ch in '+/=')
    if len(filt) < 16:
        return None
    try:
        dec = base64.b64decode(filt, validate=False)
        return dec
    except Exception:
        return None

def try_decompressors(b: bytes):
    outs = []
    # gzip
    try:
        outs.append(('gzip', gzip.decompress(b)))
    except Exception:
        pass
    # zlib
    try:
        outs.append(('zlib', zlib.decompress(b)))
    except Exception:
        pass
    # raw DEFLATE try with -zlib wrapper missing
    for wbits in (-15, 15):
        try:
            outs.append((f'deflate({wbits})', zlib.decompress(b, wbits)))
            break
        except Exception:
            pass
    # bz2
    try:
        outs.append(('bz2', bz2.decompress(b)))
    except Exception:
        pass
    # lzma
    try:
        # Use a conservative memory limit to avoid pathological allocations on random data
        outs.append(('lzma', lzma.decompress(b, format=lzma.FORMAT_AUTO, memlimit=8 * 1024 * 1024)))
    except Exception:
        pass
    return outs

def single_byte_xor_candidates(b: bytes, topn=5):
    scored = []
    for k in range(256):
        x = bytes([bb ^ k for bb in b])
        ratio = printable_ratio(x)
        scored.append((ratio, k, x))
    scored.sort(reverse=True)
    return [(k, r, x[:120]) for r, k, x in scored[:topn]]

def analyze(path: Path):
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    print(f"File: {path}")
    print(f"Size: {len(data)} bytes  SHA256: {sha}")
    print(f"Printable ratio: {printable_ratio(data):.2f}")
    print(f"Head hex: {data[:32].hex()}")
    if len(data) <= 256:
        # Full hex dump
        print("Full hex:")
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hexs = ' '.join(f"{b:02x}" for b in chunk)
            ascii = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            print(f"{i:04x}: {hexs:<48}  {ascii}")
    # Signatures
    sigs = []
    if data.startswith(b'Salted__'):
        sigs.append('OpenSSL-Salted (raw)')
    if data.startswith(b'\x1f\x8b'):
        sigs.append('gzip')
    if data.startswith(b'BZh'):
        sigs.append('bzip2')
    if data.startswith(b'\xFD7zXZ\x00'):
        sigs.append('xz')
    if data.startswith(b'PK\x03\x04'):
        sigs.append('zip')
    if data.startswith(b'%PDF'):
        sigs.append('pdf')
    if sigs:
        print('Signatures:', ', '.join(sigs))
    # Embedded patterns
    try:
        txt = data.decode('utf-8')
    except Exception:
        txt = data.decode('latin1', errors='ignore')
    if 'U2FsdGVk' in txt:
        print('Found embedded base64 Salted__ marker U2FsdGVk...')
    # strings
    ss = strings_extract(data, 4)
    print(f"Strings(4+): {ss[:10]}")
    # Try base64 from bytes
    b64d = try_b64_from_bytes(data)
    if b64d:
        print(f"Base64-filter decoded len={len(b64d)} bytes; head hex: {b64d[:16].hex()}")
        if b64d.startswith(b'Salted__'):
            print('Decoded b64 appears to be OpenSSL raw Salted__ blob')
    # Decompress attempts (optional)
    if ALLOW_DECOMPRESS:
        outs = try_decompressors(data)
        for name, out in outs:
            print(f"Decompress via {name}: {len(out)} bytes; printable ratio {printable_ratio(out):.2f}")
            s10 = strings_extract(out, 4)[:10]
            print(f"  Strings: {s10}")
    # Simple transforms
    transforms = {
        'reverse': data[::-1],
        'invert': invert_bytes(data),
        'swap_nibbles': swap_nibbles(data),
        'rotl1': rotl(data, 1),
        'rotr1': rotr(data, 1),
    }
    # Blockwise XOR with seeds
    if len(data) >= 16:
        seeds = {
            'seed_first16': data[:16],
            'seed_mid16': data[16:32] if len(data) >= 32 else data[:16],
            'seed_last16': data[-16:],
        }
        for sname, seed in seeds.items():
            out = bytes(data[i] ^ seed[i % 16] for i in range(len(data)))
            transforms[f'xor_{sname}'] = out
    for tname, tb in transforms.items():
        pr = printable_ratio(tb)
        sig = (b'Salted__' in tb) or (b'U2FsdGVk' in tb)
        if pr >= 0.6 or sig:
            print(f"Transform {tname}: printable {pr:.2f} sig={sig}; head {tb[:16].hex()}")
            if sig:
                print(f"  Found Salt marker after {tname}")
    # Repeating-key XOR with candidate keys
    keys = []
    # ascii hex of SHA256(data)
    keys.append(('sha_hex', sha.encode('ascii')))
    # raw bytes of SHA256(data)
    keys.append(('sha_raw', bytes.fromhex(sha)))
    # known phase digests
    PHASE3 = '1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5'
    PHASE32 = '250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c'
    keys.append(('phase3_hex', PHASE3.encode('ascii')))
    keys.append(('phase3_raw', bytes.fromhex(PHASE3)))
    keys.append(('phase32_hex', PHASE32.encode('ascii')))
    keys.append(('phase32_raw', bytes.fromhex(PHASE32)))
    keys.append(('SalPhaseIon', b'SalPhaseIon'))
    for name, kb in keys:
        try_keyed_xor(name, kb, data)
    # XOR guesses
    cands = single_byte_xor_candidates(data)
    for k, r, prev in cands:
        print(f"XOR key 0x{k:02x} -> printable {r:.2f}; preview: {prev.decode('latin1', errors='ignore')}")
    # Bruteforce 2-byte repeating XOR for Salted markers
    best = (0.0, None, None)
    found_marker = None
    for a in range(256):
        for b in range(256):
            key = bytes([a, b])
            out = bytes(data[i] ^ key[i % 2] for i in range(len(data)))
            if (b'Salted__' in out) or (b'U2FsdGVk' in out):
                found_marker = (a, b, out)
                break
            pr = printable_ratio(out)
            if pr > best[0]:
                best = (pr, (a, b), out[:80])
        if found_marker:
            break
    if found_marker:
        a, b, out = found_marker
        print(f"Found Salt marker via 2-byte XOR key [{a:02x} {b:02x}]")
        print(f"Head: {out[:32].hex()}")
        print(f"Strings: {strings_extract(out,4)[:10]}")
    else:
        pr, key, prev = best
        if key:
            print(f"Best 2-byte XOR printable {pr:.2f} with key [{key[0]:02x} {key[1]:02x}] preview: {prev.decode('latin1', errors='ignore')}")
    # Sliding XOR to align to 'Salted__' or 'U2FsdGVk'
    targets = [b'Salted__', b'U2FsdGVk']
    for tgt in targets:
        for pos in range(0, max(0, len(data) - len(tgt) + 1)):
            seg = data[pos:pos+len(tgt)]
            key = bytes(a ^ b for a, b in zip(seg, tgt))
            if not key:
                continue
            # repeat key across data length
            out = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
            if tgt in out:
                print(f"Sliding XOR aligned to {tgt.decode('latin1')} at pos {pos} using key {key.hex()}")
                print(f"  Head: {out[:32].hex()}  tail: {out[-16:].hex()}")
                ss = strings_extract(out, 4)[:12]
                print(f"  Strings: {ss}")
                # If raw Salted__ appears anywhere in bytes, trim to that offset and base64-encode and save
                # This captures cases where the aligned Salted__ is not at index 0
                if b'Salted__' in out:
                    try:
                        idx = out.find(b'Salted__')
                        if idx > 0:
                            out_dir = Path('artifacts/phase_solver/blobs')
                            out_dir.mkdir(parents=True, exist_ok=True)
                            src_name = path.name.replace(' ', '_')
                            stem_slug = hashlib.sha256(src_name.encode('utf-8')).hexdigest()[:16]
                            key_short = key.hex()[:16]
                            out_path = out_dir / f"rec_{stem_slug}_p{pos}_ofs{idx}_k{key_short}_raw2b64.txt"
                            b64 = base64.b64encode(out[idx:]).decode('ascii')
                            with out_path.open('w') as fh:
                                fh.write(b64)
                            print(f"  Saved recovered raw->b64 (offset {idx}) to {out_path}")
                    except Exception:
                        pass
                # If it looks base64-ish, try decode
                txt = out.decode('latin1', errors='ignore')
                filt = ''.join(ch for ch in txt if ch.isalnum() or ch in '+/=' or ch in '\n')
                if 'U2FsdGVk' in filt:
                    try:
                        dec = base64.b64decode(filt, validate=False)
                        if dec.startswith(b'Salted__'):
                            print('  Decoded sliding-XOR b64 -> OpenSSL Salted__ blob! len', len(dec))
                            # Save recovered base64 for pipeline reuse
                            out_dir = Path('artifacts/phase_solver/blobs')
                            out_dir.mkdir(parents=True, exist_ok=True)
                            # Use a short hashed slug for the source name to avoid overly long filenames
                            src_name = path.name.replace(' ', '_')
                            stem_slug = hashlib.sha256(src_name.encode('utf-8')).hexdigest()[:16]
                            key_short = key.hex()[:16]
                            out_path = out_dir / f"rec_{stem_slug}_p{pos}_k{key_short}_b64.txt"
                            with out_path.open('w') as fh:
                                fh.write(filt)
                            print(f"  Saved recovered base64 to {out_path}")
                    except Exception:
                        pass
                # If raw Salted__ appears in bytes, base64-encode and save
                if out.startswith(b'Salted__'):
                    out_dir = Path('artifacts/phase_solver/blobs')
                    out_dir.mkdir(parents=True, exist_ok=True)
                    # Use short hashed slug to keep filename manageable
                    src_name = path.name.replace(' ', '_')
                    stem_slug = hashlib.sha256(src_name.encode('utf-8')).hexdigest()[:16]
                    key_short = key.hex()[:16]
                    out_path = out_dir / f"rec_{stem_slug}_p{pos}_k{key_short}_raw2b64.txt"
                    b64 = base64.b64encode(out).decode('ascii')
                    with out_path.open('w') as fh:
                        fh.write(b64)
                    print(f"  Saved recovered raw->b64 to {out_path}")

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--decompress', action='store_true', help='enable gzip/zlib/bz2/lzma attempts (disabled by default)')
    ap.add_argument('paths', nargs='*', help='paths to hit files', default=[])
    args = ap.parse_args()
    # set global flag
    if args.decompress:
        globals()['ALLOW_DECOMPRESS'] = True
    files = [Path(p) for p in args.paths] if args.paths else list(Path('artifacts/phase_solver').glob('hit_*_pass_*.txt'))
    if not files:
        print('No hit files found.')
        sys.exit(0)
    for fp in files:
        try:
            analyze(fp)
            print('-'*60)
        except Exception as e:
            print(f"Error analyzing {fp}: {e}")
