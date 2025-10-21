#!/usr/bin/env python3
"""Quick Analysis helper for SalPhaseIon.md remaining segments.
Run: python3 analysis_salphaseion.py
Outputs a JSON summary of attempts to decode each segment.
"""
from pathlib import Path
import json, binascii, sys, re

FILE = Path("SalPhaseIon.md")
if not FILE.exists():
    sys.exit("SalPhaseIon.md not found")
lines = FILE.read_text().splitlines()
if len(lines) < 2:
    sys.exit("Unexpected file format")
# First payload line after title
payload_tokens = lines[1].strip().split()
segments = []
cur = []
for tok in payload_tokens:
    if tok == 'z':
        segments.append(cur)
        cur = []
    else:
        cur.append(tok)
segments.append(cur)

# mapping for a-i,o digits
digit_map = {c: str(i+1) for i, c in enumerate("abcdefghi")}
digit_map['o'] = '0'

def decode_digit_segment(seg, mapping=None):
    """Attempt digit mapping -> decimal -> hex -> ascii"""
    if not seg:
        return None
    mp = mapping if mapping else digit_map
    if not all(all(ch in mp for ch in tok) for tok in seg):
        return None
    digits = ''.join(mp[ch] for tok in seg for ch in tok)
    try:
        n_int = int(digits)
    except ValueError:
        return None
    hex_str = f"{n_int:x}"
    if len(hex_str) % 2:
        hex_str = '0' + hex_str
    try:
        ascii_bytes = bytes.fromhex(hex_str)
        ascii_text = ascii_bytes.decode('utf-8', errors='ignore')
    except (ValueError, binascii.Error):
        ascii_text = None
    return ascii_text

def alt_digit_mappings():
    maps = []
    # a=1..9, o=0 (default)
    maps.append(digit_map)
    # a=0..8, o=9
    maps.append({**{c:str(i) for i,c in enumerate('abcdefghi')}, 'o':'9'})
    # reversed a=9..1, o=0
    maps.append({**{c:str(9-i) for i,c in enumerate('abcdefghi')}, 'o':'0'})
    return maps

# deps: pip install pyaes
import base64, hashlib, pyaes

def _openssl_key_iv(pass_bytes: bytes, salt: bytes, klen=32, ivlen=16):
    """Derive (key, iv) the way OpenSSL’s EVP_BytesToKey does (MD5, 1 round)."""
    d = b''
    while len(d) < klen + ivlen:
        d += hashlib.md5(d + pass_bytes + salt).digest()
    return d[:klen], d[klen:klen+ivlen]

def aes_cbc_decrypt_b64(blob_b64: str, password: str, use_pbkdf2: bool=False, rounds: int=10000) -> bytes:
    raw = base64.b64decode(blob_b64)
    assert raw.startswith(b'Salted__'), "OpenSSL salt header missing"
    salt, ct = raw[8:16], raw[16:]
    if use_pbkdf2:
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, rounds, dklen=48)
        key, iv = dk[:32], dk[32:48]
    else:
        key, iv = _openssl_key_iv(password.encode(), salt)
    aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
    decryptor = pyaes.Decrypter(aes, pad=pyaes.PADDING_PKCS7)
    return decryptor.feed(ct) + decryptor.finish()
    
def vic_transpose_decode(digits_str, widths):
    """Try reading a digit string as rect. matrices with given widths,
    reading by columns then rows, convert each result (decimal->hex->ascii)."""
    outs = []
    for w in widths:
        if len(digits_str) % w:
            continue
        h = len(digits_str) // w
        # build matrix row-wise
        rows = [digits_str[i*w:(i+1)*w] for i in range(h)]
        # column-first read
        col_first = ''.join(rows[r][c] for c in range(w) for r in range(h))
        for variant, s in ((f"C{w}", col_first), (f"R{w}", ''.join(rows))):
            try:
                n = int(s)
                hx = f"{n:x}"
                if len(hx) % 2:
                    hx = '0' + hx
                txt = bytes.fromhex(hx).decode('utf-8', errors='ignore')
                if any(ch.isalpha() for ch in txt):
                    outs.append((variant, txt))
            except Exception:
                pass
    return outs

def decode_binary_tokens(tokens):
    """Locate all contiguous runs of single-letter a/b tokens and decode each run separately.
    Returns list of decoded ASCII strings (non-empty)."""
    out = []
    run = []
    for tok in tokens + [None]:  # sentinel
        if tok in ("a", "b") and len(tok) == 1:
            run.append(tok)
        else:
            if len(run) >= 8:  # need at least one byte
                bits = "".join("0" if t == "a" else "1" for t in run)
                chars = [bits[i : i + 8] for i in range(0, len(bits), 8)]
                try:
                    decoded = "".join(chr(int(b, 2)) for b in chars if len(b) == 8)
                    if decoded.strip():
                        out.append(decoded)
                except ValueError:
                    pass
            run = []
    return out

results = {}
decoded_words = set()
for idx, seg in enumerate(segments):
    res = {}
    digit_txt = None
    for mp in alt_digit_mappings():
        t = decode_digit_segment(seg, mp)
        if t:
            digit_txt = t
            decoded_words.update(re.findall(r'[A-Za-z]{5,}', t))
            break
    if digit_txt:
        res['digit_decode'] = digit_txt
    bin_runs = decode_binary_tokens(seg)
    if bin_runs:
        for br in bin_runs:
            decoded_words.update(re.findall(r'[A-Za-z]{5,}', br))
    if bin_runs:
        res['binary_runs'] = bin_runs
    # attempt base-9 conversion if segment only contains digits 0-8
    if not res and seg and all(tok in "abcdefghi" for tok in seg):
        base9_digits = ''.join(str(ord(t) - ord('a')) for t in seg)  # a=0 ... i=8
        try:
            base10 = int(base9_digits, 9)
            hexstr = f"{base10:x}"
            if len(hexstr) % 2:
                hexstr = '0' + hexstr
            txt = bytes.fromhex(hexstr).decode('utf-8', errors='ignore')
            if txt.strip():
                res['base9_ascii'] = txt
        except Exception:
            pass
    # For segment 0 additional VIC transposition attempts
    if idx == 0:
        vic_out = vic_transpose_decode(''.join(digit_map[ch] for tok in seg for ch in tok), [3,5,9,15,17,27,45,51,85])
        if vic_out:
            res['vic_attempts'] = vic_out
    if res:
        results[str(idx)] = res

print(json.dumps(results, indent=2))

# --- Try AES blob(s) decryption
text_nosp = Path('SalPhaseIon.md').read_text()
import re, hashlib
blob_candidates = re.findall(r'U2FsdGVk[0-9A-Za-z+/=]+', re.sub(r'\s+', '', text_nosp))
if blob_candidates:
    cand_pw = [
        'matrixsumlist',
        'enter',
        'lastwordsbeforearchichoice',
        'thispassword',
        'yourlastcommand',
        'fourfirsthintisyourlastcommand',
    ]
    # include words decoded earlier
    cand_pw.extend(list(decoded_words))
    # include any alpha substrings from file >4 chars
    alpha_words = re.findall(r'[A-Za-z]{5,}', text_nosp)
    cand_pw.extend(alpha_words)
    cand_pw = list(set(cand_pw))
    # include case variants and combos
    extra = []
    for p in cand_pw:
        extra.extend([p.upper(), p.title()])
    for a in cand_pw:
        for b in cand_pw:
            if a!=b:
                extra.append(a+b)
                extra.append(a+'_'+b)
    cand_pw.extend(extra)
    # add sha256 of each
    cand_pw.extend([hashlib.sha256(p.encode()).hexdigest() for p in cand_pw])
    tried = {}
    for blob in blob_candidates:
        for pw in cand_pw:
            variants = [(False, None), (True, 1000), (True, 10000)]
            for use_pbkdf2, rnd in variants:
                try:
                    dec = aes_cbc_decrypt_b64(blob, pw, use_pbkdf2, rnd if rnd else 10000)
                    txt = dec.decode('utf-8', 'ignore')
                    if sum(c.isprintable() for c in txt)/max(1,len(txt)) > 0.7 and re.search(r'[A-Za-z]{5,}', txt):
                        key = f"{blob[:10]}_{pw[:10]}_{'pbkdf2' if use_pbkdf2 else 'md5'}_{rnd}"
                        tried[key] = txt[:200]
                except Exception:
                    pass
    if tried:
        print('\nAES_DECRYPT_SUCC:', json.dumps(tried, indent=2))
    else:
        print('\nNo AES blob decrypted with current candidates.')
