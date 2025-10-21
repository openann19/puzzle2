#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GPU-accelerated puzzle solver (enhanced version of solve_puzzle.py).
Uses gpu_decrypt module for parallel decryption when CUDA available.
Falls back to CPU if GPU unavailable.
"""

import argparse
import json
import re
import subprocess
import sys
import base64
import math
from pathlib import Path
from typing import Iterable, List, Dict, Any, Tuple, Optional
from datetime import datetime, timezone
from collections import Counter

import yaml
from tqdm import tqdm
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import scrypt as kdf_scrypt, PBKDF2
from Cryptodome.Hash import SHA256, SHA1
from ecdsa import SigningKey, SECP256k1

from gpu_decrypt import get_device_info, try_decrypt_blob_gpu

# ---------- small utils ----------
def read_text_safe(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""

def sha256(b: bytes) -> bytes:
    h = SHA256.new()
    h.update(b)
    return h.digest()

B58_ALPH = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, 'big')
    enc = ''
    while n > 0:
        n, r = divmod(n, 58)
        enc = B58_ALPH[r] + enc
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return '1' * pad + enc

def base58check(version_byte: int, payload: bytes) -> str:
    data = bytes([version_byte]) + payload
    checksum = sha256(sha256(data))[:4]
    return b58encode(data + checksum)

def ripemd160(b: bytes) -> bytes:
    from Cryptodome.Hash import RIPEMD160
    h = RIPEMD160.new()
    h.update(b)
    return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

def to_pubkey(priv32: bytes, compressed: bool = True) -> bytes:
    sk = SigningKey.from_string(priv32, curve=SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    prefix = 2 + (y & 1) if compressed else 4
    if compressed:
        return bytes([prefix]) + x.to_bytes(32, 'big')
    else:
        return bytes([prefix]) + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

def p2pkh_from_priv(priv_hex: str, compressed: bool = True) -> str:
    priv = bytes.fromhex(priv_hex)
    pub = to_pubkey(priv, compressed=compressed)
    return base58check(0x00, hash160(pub))

def p2wpkh_from_priv(priv_hex: str) -> str:
    hrp = "bc"
    def bech32_polymod(values):
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = (chk >> 25) & 0xff
            chk = ((chk & 0x1ffffff) << 5) ^ v
            for i in range(5):
                if (b >> i) & 1:
                    chk ^= GEN[i]
        return chk
    def bech32_hrp_expand(s):
        return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]
    def bech32_create_checksum(hrp, data):
        pm = bech32_polymod(bech32_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    def to_base32(data: bytes) -> List[int]:
        acc = 0
        bits = 0
        out = []
        for b in data:
            acc = (acc << 8) | b
            bits += 8
            while bits >= 5:
                out.append((acc >> (bits - 5)) & 31)
                bits -= 5
        if bits:
            out.append((acc << (5 - bits)) & 31)
        return out
    priv = bytes.fromhex(priv_hex)
    pub = to_pubkey(priv, compressed=True)
    h160 = hash160(pub)
    data = [0] + to_base32(h160)
    checksum = bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(CHARS[d] for d in data + checksum)

BTC_ADDR_RE = re.compile(r'\b(?:bc1|[13])[0-9A-Za-z]{25,90}\b')
WIF_RE = re.compile(r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b')
HEX64_RE = re.compile(r'\b[0-9a-fA-F]{64}\b')

def find_addresses(text: str) -> List[str]:
    return list(set(BTC_ADDR_RE.findall(text)))

def iter_files(root: Path) -> Iterable[Path]:
    for p in sorted(root.rglob('*')):
        if p.is_file():
            yield p

def bytes_entropy(b: bytes, sample: int = 65536) -> float:
    s = b if len(b) <= sample else b[:sample]
    c = Counter(s)
    total = len(s)
    return -sum((n / total) * math.log2(n / total) for n in c.values())

def load_passwords(root: Path, globs: List[str]) -> List[str]:
    out = set()
    for g in globs:
        for p in root.rglob(g):
            for line in read_text_safe(p).splitlines():
                w = line.strip()
                if w:
                    out.add(w)
    return sorted(out)

def load_candidate_privkeys(root: Path, patterns: List[str]) -> List[str]:
    out = set()
    for g in patterns:
        for p in root.rglob(g):
            if p.suffix.lower() == ".json":
                try:
                    js = json.loads(read_text_safe(p))
                    if isinstance(js, dict):
                        for k, v in js.items():
                            if isinstance(v, str) and re.fullmatch(HEX64_RE, v):
                                out.add(v.lower())
                    elif isinstance(js, list):
                        for v in js:
                            if isinstance(v, str) and re.fullmatch(HEX64_RE, v):
                                out.add(v.lower())
                except Exception:
                    pass
            elif p.suffix.lower() in (".hex", ".txt"):
                for h in HEX64_RE.findall(read_text_safe(p)):
                    out.add(h.lower())
    return sorted(out)

def discover_prize_addresses(root: Path, prefer_files: List[str]) -> List[str]:
    results = set()
    for pat in prefer_files:
        for p in root.rglob(pat):
            results.update(find_addresses(read_text_safe(p)))
    if not results:
        for p in iter_files(root):
            if p.suffix.lower() in (".txt", ".md", ".json", ".log", ".py", ".sh", ".html"):
                results.update(find_addresses(read_text_safe(p)))
    return sorted(results)

def english_score(b: bytes) -> float:
    try:
        t = b.decode('utf-8', errors='ignore')
    except Exception:
        return 0.0
    hits = 0
    for w in (" the ", " and ", " to ", " of ", " in ", " that ", " with ", " for ",
              "btc", "address", "private", "key"):
        hits += t.lower().count(w)
    return hits / max(1, len(t) / 1000)

def looks_like_btc_structs(b: bytes) -> float:
    t = b.decode('utf-8', errors='ignore')
    addr = len(BTC_ADDR_RE.findall(t))
    wif = len(WIF_RE.findall(t))
    hexs = len(HEX64_RE.findall(t))
    return min(1.0, (addr * 0.5 + wif * 0.3 + hexs * 0.2) / 10.0)

def score_hypothesis(parts: Dict[str, float], weights: Dict[str, float]) -> float:
    return sum(weights.get(k, 0.0) * v for k, v in parts.items())

def run_helpers(root: Path, helpers: List[str], logdir: Path):
    for h in helpers:
        for p in root.rglob(h):
            try:
                subprocess.run([sys.executable, str(p)], cwd=str(p.parent), timeout=3600,
                               check=False,
                               stdout=open(logdir / f"{p.name}.out", "w"),
                               stderr=open(logdir / f"{p.name}.err", "w"))
            except Exception:
                pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--mode", choices=["full", "index", "validate", "decrypt"], default="full")
    ap.add_argument("--gpu-batch-size", type=int, default=256,
                    help="Batch size for GPU decryption (default 256)")
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text())
    root = Path(cfg["puzzle_dir"]).resolve()
    out = Path(".solver_out")
    out.mkdir(exist_ok=True)
    logs = out / "logs"
    logs.mkdir(exist_ok=True)

    # Device info
    device_info = get_device_info()
    print(f"[*] Device: {device_info['device']}")
    if device_info.get('available'):
        print(f"    Compute Capability: {device_info.get('compute_capability')}")
        print(f"    Max Threads/Block: {device_info.get('max_threads_per_block')}")
        print(f"    Total Memory: {device_info.get('total_memory_gb'):.2f} GB")
    else:
        print(f"    Reason: {device_info.get('reason')}")

    # 1) Discover prize addresses
    prize_addrs = discover_prize_addresses(root, cfg["prize_address_files"])
    (out / "prize_addresses.json").write_text(json.dumps(prize_addrs, indent=2))
    print(f"[+] Prize address candidates: {len(prize_addrs)}")

    # 2) Collect passwords and privkeys
    pw_list = load_passwords(root, cfg["password_files"])
    keys_list = load_candidate_privkeys(root, cfg["key_files"])
    (out / "passwords.count").write_text(str(len(pw_list)))
    (out / "keys.count").write_text(str(len(keys_list)))
    print(f"[+] Password candidates: {len(pw_list)} | Private-key candidates: {len(keys_list)}")

    # 3) Validate keys and derive addresses
    validations = []
    for hexkey in tqdm(keys_list, desc="Validating keys"):
        try:
            p2pkh_c = p2pkh_from_priv(hexkey, compressed=True)
            p2pkh_u = p2pkh_from_priv(hexkey, compressed=False)
            p2wpkh = p2wpkh_from_priv(hexkey)
            match = len(set(prize_addrs) & {p2pkh_c, p2pkh_u, p2wpkh}) > 0
            validations.append({
                "privhex": hexkey,
                "p2pkh_compressed": p2pkh_c,
                "p2pkh_uncompressed": p2pkh_u,
                "p2wpkh": p2wpkh,
                "matches_prize": match
            })
        except Exception:
            continue
    (out / "key_validations.json").write_text(json.dumps(validations, indent=2))

    # 4) Run helper scripts if present (non-fatal)
    run_helpers(root, cfg.get("helpers", []), logs)

    # 5) GPU-accelerated decrypt candidate blobs using passwords
    blob_paths = []
    for g in cfg["blob_files"]:
        blob_paths += list(root.rglob(g))
    blob_paths = [p for p in blob_paths if p.is_file()]
    results = []
    for p in tqdm(blob_paths, desc="GPU decrypting blobs"):
        raw = p.read_bytes()
        if p.suffix.lower() == ".b64" or (b"==" in raw[:100] and b"\n" in raw[:200]):
            try:
                raw_dec = base64.b64decode(read_text_safe(p), validate=False)
            except Exception:
                raw_dec = raw
        else:
            raw_dec = raw
        ent = bytes_entropy(raw_dec)

        # Use GPU batch decryption
        sample_pw = pw_list[:min(5000, len(pw_list))]
        gpu_results = try_decrypt_blob_gpu(raw_dec, sample_pw, cfg, 
                                           batch_size=args.gpu_batch_size)
        best_local = []
        for method, pw, pt in gpu_results:
            score = 0.4 * english_score(pt) + 0.6 * looks_like_btc_structs(pt)
            if score > 0.2:
                best_local.append((score, method, pw, pt[:2048]))
        best_local.sort(reverse=True, key=lambda x: x[0])
        if best_local:
            top = best_local[0]
            results.append({
                "file": str(p),
                "entropy": ent,
                "method": top[1],
                "password": top[2],
                "score": round(top[0], 4),
                "preview_utf8": top[3].decode('utf-8', 'ignore')
            })
    (out / "decrypt_findings.json").write_text(json.dumps(results, indent=2))

    # 6) Rank final hypotheses
    weights = cfg["score_weights"]
    ranked = []
    prize_set = set(prize_addrs)
    for v in validations:
        parts = {
            "key_validates_prize": 1.0 if (prize_set & {v["p2pkh_compressed"],
                                                         v["p2pkh_uncompressed"],
                                                         v["p2wpkh"]}) else 0.0,
            "key_derives_any_address": 1.0,
            "file_name_signal": 0.0,
            "decrypted_has_ascii_english": 0.0,
            "decrypted_has_btc_structs": 0.0
        }
        score = score_hypothesis(parts, weights)
        ranked.append({"type": "key", "privhex": v["privhex"], "score": round(score, 4), **v})
    for r in results:
        parts = {
            "key_validates_prize": 0.0,
            "key_derives_any_address": 0.0,
            "decrypted_has_ascii_english": min(1.0, r["score"]),
            "decrypted_has_btc_structs": min(1.0, r["score"]),
            "file_name_signal": 0.1 if any(x in r["file"].lower()
                                           for x in ("final", "prize", "cosmic", "salphaseion"))
            else 0.0
        }
        score = score_hypothesis(parts, weights)
        ranked.append({"type": "decrypt", "score": round(score, 4), **r})

    ranked.sort(key=lambda x: x["score"], reverse=True)
    (out / "FINAL_RANKED.json").write_text(json.dumps(ranked, indent=2))

    # 7) Human-readable report
    now = datetime.now(timezone.utc).isoformat()
    lines = [f"# Puzzle Solve Report ({now})",
             f"- Device: {device_info['device']}",
             f"- Prize candidates: {len(prize_addrs)}",
             f"- Keys validated: {len(validations)}",
             f"- Decrypt leads: {len(results)}",
             "", "## Top 10 Hypotheses"]
    for i, h in enumerate(ranked[:10], 1):
        if h["type"] == "key":
            lines.append(f"{i}. KEY score={h['score']} privhex={h['privhex'][:12]}… "
                         f"p2pkhC={h['p2pkh_compressed']} p2wpkh={h['p2wpkh']} "
                         f"{'MATCHES_PRIZE' if h['matches_prize'] else ''}")
        else:
            lines.append(f"{i}. DEC score={h['score']} file={h['file']} method={h['method']} "
                         f"pw={h['password']}")
    (out / "FINAL_RANKED.md").write_text("\n".join(lines))
    print(f"[✓] Wrote .solver_out/FINAL_RANKED.md")

if __name__ == "__main__":
    main()
