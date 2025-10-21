#!/usr/bin/env python3
# extract_spaced_blob.py
from __future__ import annotations
import argparse, re, base64, hashlib, sys
from pathlib import Path

BASE64_CHARS = r"A-Za-z0-9+/="
RUN_RE = re.compile(rf"(?:[{BASE64_CHARS}\s]{{80,}})")

def compact_b64(s: str) -> str:
    return re.sub(r"\s+", "", s)

def try_decode(b64text: str):
    try:
        raw = base64.b64decode(b64text, validate=True)
        return raw
    except Exception:
        try:
            return base64.b64decode(b64text)
        except Exception:
            return None

def find_candidates(text: str, minlen:int=80):
    matches = RUN_RE.findall(text)
    uniq = sorted(set(m.strip() for m in matches), key=len, reverse=True)
    return [m for m in uniq if len(m)>=minlen]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("infile")
    p.add_argument("--out", required=True)
    p.add_argument("--minlen", type=int, default=80)
    args = p.parse_args()
    txt = Path(args.infile).read_text()
    candidates = find_candidates(txt, minlen=args.minlen)
    if not candidates:
        print("No candidates", file=sys.stderr); sys.exit(2)
    chosen = None
    chosen_raw = None
    for run in candidates:
        b64 = compact_b64(run)
        raw = try_decode(b64)
        if raw and raw.startswith(b"Salted__"):
            chosen = b64; chosen_raw = raw; break
    if not chosen:
        # fallback: try any decodable one
        for run in candidates:
            b64 = compact_b64(run)
            raw = try_decode(b64)
            if raw:
                chosen = b64; chosen_raw = raw; break
    if not chosen:
        print("No decodable candidate", file=sys.stderr); sys.exit(3)
    out_b64 = Path(args.out)
    out_raw = out_b64.with_suffix(out_b64.suffix + ".raw")
    out_b64.write_text(chosen + "\n")
    out_raw.write_bytes(chosen_raw)
    print("WROTE:", out_b64, out_raw)
    print("blob sha256:", hashlib.sha256(chosen.encode()).hexdigest())
    if chosen_raw.startswith(b"Salted__"):
        print("salt hex:", chosen_raw[8:16].hex())
    sys.exit(0)

if __name__ == "__main__":
    main()
