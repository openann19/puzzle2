"""Solver Pipeline for GSMG.IO 5 BTC puzzle (SalPhaseIon → Cosmic Duality)

Goals
-----
1. Extract segments from the markdown payload lines.
2. Provide multiple decoding heuristics (digit-maps, binary runs, base-9, VIC, grid sums).
3. Central password candidate aggregator.
4. Pure-Python AES-256-CBC decryptor (pyaes) supporting EVP-MD5 and PBKDF2-SHA256 key derivation.
5. Brute-force sweeper against every OpenSSL-style `U2FsdGVk…` blob.

Usage
-----
```
python -m solver_pipeline <markdown_file>
```
Prints JSON of discovered plaintexts.  Extend `Pipeline.run()` with new heuristics.
"""
from __future__ import annotations

import base64, binascii, hashlib, json, re, sys
from pathlib import Path
import argparse
import itertools
from typing import Dict, List, Sequence, Tuple

try:
    import pyaes  # type: ignore
except ImportError as exc:  # pragma: no cover
    sys.exit("pyaes missing – activate venv & `pip install pyaes`.")

############################################################
#    Helpers
############################################################
_DIGIT_MAP_DEFAULT = {c: str(i + 1) for i, c in enumerate("abcdefghi")}
_DIGIT_MAP_DEFAULT["o"] = "0"

_DIGIT_MAPS: List[Dict[str, str]] = [
    _DIGIT_MAP_DEFAULT,
    {**{c: str(i) for i, c in enumerate("abcdefghi")}, "o": "9"},  # a=0…8,o=9
    {**{c: str(9 - i) for i, c in enumerate("abcdefghi")}, "o": "0"},  # reversed
]

_WIDTHS = [3, 5, 9, 15, 17, 27, 45, 51, 85, 255]

PRINTABLE_RATIO_MIN = 0.7
_MIN_ALPHA = re.compile(r"[A-Za-z]{5,}")

############################################################
#    AES helpers (OpenSSL compat)
############################################################

def _evp_bytes_to_key_md5(password: bytes, salt: bytes, klen: int = 32, ivlen: int = 16):
    d = b""
    while len(d) < klen + ivlen:
        d += hashlib.md5(d + password + salt).digest()
    return d[:klen], d[klen : klen + ivlen]


def aes_cbc_decrypt(
    blob_b64: str,
    password: str,
    pbkdf2_rounds: int | None = None,
) -> bytes | None:
    try:
        raw = base64.b64decode(blob_b64)
    except Exception:
        return None
    if not raw.startswith(b"Salted__"):
        return None
    salt, ct = raw[8:16], raw[16:]
    if pbkdf2_rounds:
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, pbkdf2_rounds, dklen=48)
        key, iv = dk[:32], dk[32:48]
    else:
        key, iv = _evp_bytes_to_key_md5(password.encode(), salt)
    aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
    dec = pyaes.Decrypter(aes, pad=pyaes.PADDING_PKCS7)
    try:
        return dec.feed(ct) + dec.finish()
    except ValueError:
        return None

############################################################
#    Decoders
############################################################

def binary_runs(tokens: Sequence[str]) -> List[str]:
    out, run = [], []
    for tok in list(tokens) + [None]:
        if tok in ("a", "b"):
            run.append(tok)
        else:
            if len(run) >= 8:
                bits = "".join("0" if t == "a" else "1" for t in run)
                chars = [bits[i : i + 8] for i in range(0, len(bits), 8)]
                try:
                    out.append("".join(chr(int(c, 2)) for c in chars if len(c) == 8))
                except ValueError:
                    pass
            run = []
    return [s for s in out if s.strip()]


def digit_decode(tokens: Sequence[str]) -> List[str]:
    outs: List[str] = []
    for mp in _DIGIT_MAPS:
        digits = "".join(mp.get(ch, "") for tok in tokens for ch in tok)
        if not digits:
            continue
        try:
            n = int(digits)
        except ValueError:
            continue
        hx = f"{n:x}"
        if len(hx) % 2:
            hx = "0" + hx
        try:
            txt = bytes.fromhex(hx).decode("utf-8", "ignore")
            if _MIN_ALPHA.search(txt):
                outs.append(txt)
        except (ValueError, binascii.Error):
            pass
    return outs


############################################################
#    Pipeline
############################################################
class Pipeline:
    def __init__(self, md_file: Path):
        self.md_file = md_file
        self.candidates: set[str] = set()
        self.blobs: List[str] = []

    # --------------------------------------------------
    def extract_segments(self) -> List[List[str]]:
        lines = self.md_file.read_text().splitlines()
        tokens = lines[1].split() if len(lines) > 1 else []
        segs, cur = [], []
        for t in tokens:
            if t == "z":
                segs.append(cur)
                cur = []
            else:
                cur.append(t)
        segs.append(cur)
        return segs

    # --------------------------------------------------
    def harvest_candidates(self, segments: List[List[str]]):
        for seg in segments:
            for txt in binary_runs(seg) + digit_decode(seg):
                self.candidates.update(_MIN_ALPHA.findall(txt))

        # plus every alpha word in whole doc
        self.candidates.update(_MIN_ALPHA.findall(self.md_file.read_text()))

    # --------------------------------------------------
    def find_blobs(self):
        text_no_ws = re.sub(r"\s+", "", self.md_file.read_text())
        self.blobs = re.findall(r"U2FsdGVk[0-9A-Za-z+/=]+", text_no_ws)

    # --------------------------------------------------
    def brute(self, max_pw:int|None=None, allow_combos:bool=True, progress_every:int=5000) -> Dict[str, str]:
        results: Dict[str, str] = {}
        pw_list = list(self.candidates)
        pw_list += [p.upper() for p in pw_list] + [p.title() for p in pw_list]
        if allow_combos:
            # simple concatenations (limit to first 200 words to curb explosion)
            base = pw_list[:200]
            for a, b in itertools.product(base, repeat=2):
                if a!=b:
                    pw_list.append(a+b)
                    pw_list.append(a+"_"+b)
        pw_list = list(dict.fromkeys(pw_list))  # dedupe preserving order
        if max_pw:
            pw_list = pw_list[:max_pw]
        # plus SHA-256 hex of each
        pw_list += [hashlib.sha256(p.encode()).hexdigest() for p in pw_list]

        attempts = 0
        for blob in self.blobs:
            for pw in pw_list:
                for rounds in [None, 1000, 10000]:
                    pt = aes_cbc_decrypt(blob, pw, rounds)
                    attempts += 1
                    if attempts % progress_every == 0:
                        print(f".. tried {attempts} passphrases", file=sys.stderr)
                    if pt and pt.strip():
                        text = pt.decode("utf-8", "ignore")
                        if (sum(c.isprintable() for c in text) / len(text)) >= PRINTABLE_RATIO_MIN and _MIN_ALPHA.search(text):
                            tag = f"{blob[:10]}:{pw[:10]}:{'pbkdf2' if rounds else 'md5'}:{rounds or 0}"
                            results[tag] = text
                            print("* HIT", tag)
                            return results  # stop on first hit
        return results

    # --------------------------------------------------
    def run(self, max_pw:int|None=None, allow_combos:bool=True):
        segs = self.extract_segments()
        self.harvest_candidates(segs)
        self.find_blobs()
        hits = self.brute(max_pw=max_pw, allow_combos=allow_combos)
        print(json.dumps({"hits": hits, "pw_candidates": len(self.candidates)}, indent=2))


############################################################
#    CLI
############################################################
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Brute decrypt GSMG.IO puzzle blobs")
    parser.add_argument("markdown", help="Markdown file containing blobs")
    parser.add_argument("--top", type=int, default=1000, help="max passwords to try before hashes (default 1000)")
    parser.add_argument("--no-combos", action="store_true", help="disable concatenation combos to save time")
    args = parser.parse_args()

    Pipeline(Path(args.markdown)).run(max_pw=args.top, allow_combos=not args.no_combos)
    if len(sys.argv) < 2:
        sys.exit("Usage: python -m solver_pipeline <SalPhaseIon.md>")
    Pipeline(Path(sys.argv[1])).run()
