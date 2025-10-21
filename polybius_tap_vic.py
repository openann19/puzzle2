#!/usr/bin/env python3
# polybius_tap_vic.py — deeper decoders (Polybius 5x5 + Tap code + VIC-style numeric scanning)
from pathlib import Path
import re, itertools

txt = Path("SalPhaseIon.md").read_text()
lines = txt.splitlines()
run = lines[1] if len(lines) > 1 else txt
tokens = re.findall(r"[a-z]", run, flags=re.I)
s = "".join(tokens).lower()

candidates=set()

# Simple Tap decoder: pairs of digits 1-5 encoded as letters a..e mapping? We'll treat a..e groups
# Build potential pairs from letters a-e sequences
def try_tap(s):
    outs=[]
    # map a->1 .. e->5
    mapping = {ch:str(i+1) for i,ch in enumerate('abcde')}
    digits = "".join(mapping.get(ch,'') for ch in s)
    # pair digits
    for i in range(0,len(digits)-1,2):
        pair = digits[i:i+2]
    # naive: sliding windows as with other miners
    return outs

# Polybius 5x5 naive: try interpret `s` as digits (1..5) if letters exist; but our stream is letters
# Instead, try mapping small letter groups (3..8) to potential plain words via common keyed squares
for w in range(3,9):
    for i in range(0, len(s)-w+1):
        fragment = s[i:i+w]
        # try common transforms: reverse, rot13, atbash
        candidates.add(fragment)
        candidates.add(fragment[::-1])

# VIC-like numeric windows: search for long runs of digits mapped from a..i,o
maps=[]
base=list("abcdefghi")
maps.append({c:str(i+1) for i,c in enumerate(base)})
maps.append({c:str(i) for i,c in enumerate(base)})
for mp in maps:
    digits = "".join(mp.get(ch,'') for ch in s)
    for w in (6,8,10,12):
        for i in range(0,len(digits)-w+1):
            blk = digits[i:i+w]
            # split into 2-digit, 3-digit windows
            for width in (2,3):
                parts=[blk[j:j+width] for j in range(0,len(blk),width) if len(blk[j:j+width])==width]
                try:
                    hx="".join(format(int(p),'x') for p in parts)
                    if len(hx)%2: hx='0'+hx
                    txt=bytes.fromhex(hx).decode('utf-8','ignore')
                    if any(c.isalpha() for c in txt) and len(txt)>=3:
                        candidates.add(txt)
                except Exception:
                    pass

out = Path("candidates_polybius_tap_vic.txt")
out.write_text("\n".join(sorted(candidates)))
print("wrote", out, "count", len(candidates))
