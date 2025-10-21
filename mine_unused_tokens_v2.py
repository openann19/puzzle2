#!/usr/bin/env python3
# mine_unused_tokens_v2.py — extended miner (3+ char windows)
from pathlib import Path
import re, json

txt = Path("SalPhaseIon.md").read_text()
# heuristic: take the long symbol line (line 2) or largest letter-only run
lines = txt.splitlines()
run = lines[1] if len(lines) > 1 else txt
letters = re.findall(r"[a-z]", run, flags=re.I)
s = "".join(letters).lower()

cands = set()

# binary a/b -> ascii
def binary_runs(s):
    outs=[]
    run=[]
    for ch in s + "x":
        if ch in ("a","b"):
            run.append(ch)
        else:
            if len(run) >= 8:
                bits = "".join("0" if c=="a" else "1" for c in run)
                bytes_ = [bits[i:i+8] for i in range(0,len(bits),8)]
                try:
                    outs.append("".join(chr(int(b,2)) for b in bytes_ if len(b)==8))
                except Exception:
                    pass
            run=[]
    return outs

for t in binary_runs(s):
    if any(c.isalpha() for c in t) and len(t) >= 3:
        cands.add(t)

# digit maps a..i + o (several maps)
maps=[]
base=list("abcdefghi")
maps.append({c:str(i+1) for i,c in enumerate(base)})
maps.append({c:str(i) for i,c in enumerate(base)})
maps.append({c:str(9-i) for i,c in enumerate(base)})
for m in maps: m['o']='0'

def num_windows(s, mp):
    outs=[]
    digits = "".join(mp.get(ch,'') for ch in s)
    for w in (2,3,4):
        for i in range(0, len(digits)-w+1):
            block = digits[i:i+w]
            try:
                n=int(block)
                hx=format(n,'x')
                if len(hx)%2: hx='0'+hx
                txt=bytes.fromhex(hx).decode('utf-8','ignore')
                if any(c.isalpha() for c in txt) and len(txt)>=3:
                    outs.append(txt)
            except Exception:
                pass
    return outs

for mp in maps:
    for o in num_windows(s, mp):
        cands.add(o)

# add small alpha windows from run (3..9)
for w in re.findall(r'[a-z]{3,9}', run, flags=re.I):
    cands.add(w.lower())

out = Path("candidates_from_unused_v2.txt")
out.write_text("\n".join(sorted(cands)))
print("wrote", out, "count", len(cands))
