#!/usr/bin/env python3
"""mine_unused_tokens.py

Extract candidate pass-phrases from the long symbol runs that were not yet
used for SalPhaseIon.

It scans *SalPhaseIon.md* for stretches consisting only of the letters
``a b c d e f g h i o`` (case-insensitive) — these are the remnants from the
Beaufort/Matrixphase step.  Several cheap decoders are then applied:

1. a/b → binary (a=0, b=1 and swapped) → ASCII
2. a-i(+o) → digit strings under two mappings
   • Map-1: a=1 … i=9, o=0
   • Map-2: a=0 … i=8, o=9
   The resulting digit string is interpreted as either
   • two-digit decimal ASCII codes, or
   • pairs of hex digits (still decimal 0–9 only but sometimes works)
3. Polybius 5×5: letters a-e → 1-5 (two-digit groups), decoded with classical
   square, IJ conflated.

All reasonably printable ≥3-letter alphabetic outputs are collected, de-duped
(lower-cased) and written to *candidates_from_unused.txt* (one per line).

Run:
    python mine_unused_tokens.py
"""
from __future__ import annotations

import re
import string
from pathlib import Path

MD_PATH = Path("SalPhaseIon.md")
OUT_PATH = Path("candidates_from_unused.txt")

POLY_SQUARE = (
    "abcde"
    "fghik"  # J conflated with I
    "lmnop"
    "qrstu"
    "vwxyz"
)

def polybius_decode(digits: str) -> str | None:
    if len(digits) % 2:
        return None
    out = []
    for i in range(0, len(digits), 2):
        r = int(digits[i])
        c = int(digits[i + 1])
        if not (1 <= r <= 5 and 1 <= c <= 5):
            return None
        out.append(POLY_SQUARE[(r - 1) * 5 + (c - 1)])
    return "".join(out)

def bin_to_ascii(bits: str) -> str | None:
    if len(bits) % 8:
        return None
    chars = []
    for i in range(0, len(bits), 8):
        b = int(bits[i : i + 8], 2)
        if 32 <= b <= 126:
            chars.append(chr(b))
        else:
            return None
    return "".join(chars)

def digits_to_ascii_fixed(dec_string: str, width: int) -> str | None:
    if len(dec_string) % width:
        return None
    out = []
    for i in range(0, len(dec_string), width):
        segment = dec_string[i : i + width]
        val = int(segment)
        if 32 <= val <= 126:
            out.append(chr(val))
        else:
            return None
    return "".join(out)

def digits_base9_to_ascii(triples: str) -> str | None:
    if not set(triples) <= set("012345678"):  # base9 digits only
        return None
    if len(triples) % 3:
        return None
    out = []
    for i in range(0, len(triples), 3):
        val = int(triples[i : i + 3], 9)
        if 32 <= val <= 126:
            out.append(chr(val))
        else:
            return None
    return "".join(out)

def digits_to_ascii_hex(hex_string: str) -> str | None:
    # two hex digits per byte – only works if chars are 0-9
    if len(hex_string) % 2:
        return None
    out = []
    for i in range(0, len(hex_string), 2):
        h = int(hex_string[i : i + 2], 16)
        if 32 <= h <= 126:
            out.append(chr(h))
        else:
            return None
    return "".join(out)

def main() -> None:
    text = MD_PATH.read_text()
    # grab longest stretch of allowed letters
    runs = re.findall(r"(?:[abCDEFGHIOfghio]+(?:\s+[abCDEFGHIOfghio]+)+)", text, re.I)
    # include also compact runs with no spaces
    runs += re.findall(r"[abCDEFGHIOfghio]{20,}", text, re.I)
    if not runs:
        print("[!] No symbol runs found")
        return

    print(f"[*] Found {len(runs)} candidate runs")
    candidates: set[str] = set()

    for run in runs:
        letters = re.sub(r"\s+", "", run).lower()

        # 1. binary decodings (a/b -> 0/1 or swapped)
        for zero, one in (("a", "b"), ("b", "a")):
            bits = letters.translate(str.maketrans({zero: "0", one: "1"}))
            if set(bits) <= {"0", "1"}:
                txt = bin_to_ascii(bits)
                if txt and txt.isprintable():
                    for w in re.findall(r"[A-Za-z]{3,}", txt):
                        candidates.add(w.lower())

        # 2. digit-map decodings
        maps = [
            {ch: str(i + 1) for i, ch in enumerate("abcdefghi")} | {"o": "0"},
            {ch: str(i) for i, ch in enumerate("abcdefghi")} | {"o": "9"},
        ]
        for mp in maps:
            num = "".join(mp.get(ch, "") for ch in letters)
            if num and num.isdigit():
                for fn in (
                    lambda s: digits_to_ascii_fixed(s, 2),
                    lambda s: digits_to_ascii_fixed(s, 3),
                    digits_to_ascii_hex,
                ):
                    txt = fn(num)
                    if txt:
                        for w in re.findall(r"[A-Za-z]{3,}", txt):
                            candidates.add(w.lower())
            # base-9 triples
            txt9 = digits_base9_to_ascii(num)
            if txt9:
                for w in re.findall(r"[A-Za-z]{3,}", txt9):
                    candidates.add(w.lower())
            # Polybius uses digits 1-5 only – quick filter
            if set(num) <= {"1", "2", "3", "4", "5"}:
                txt = polybius_decode(num)
                if txt:
                    for w in re.findall(r"[A-Za-z]{3,}", txt):
                        candidates.add(w.lower())

    if not candidates:
        print("[!] No printable candidates extracted")
    else:
        sorted_cands = sorted(candidates)
        OUT_PATH.write_text("\n".join(sorted_cands))
        print(f"[+] Wrote {len(sorted_cands)} candidate words to {OUT_PATH}")

if __name__ == "__main__":
    main()
