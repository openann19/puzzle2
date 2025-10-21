#!/usr/bin/env python3
# salphaseion_sweeper.py
from pathlib import Path
import argparse, hashlib, base64, subprocess, time, json, sys

DEFAULT_SEEDS = ["matrixsumlist","enter","lastwordsbeforearchichoice","thispassword"]
OUTDIR = Path("artifacts"); OUTDIR.mkdir(exist_ok=True)

def sha256hex(s): return hashlib.sha256(s.encode()).hexdigest()

def read_blob(bfile):
    b64 = Path(bfile).read_text().strip()
    return b64

def run_openssl(b64file, pw, mode, iters, saltmode, derived_hex=None):
    cmd = ["openssl","enc","-aes-256-cbc","-d","-a","-in",str(b64file)]
    if saltmode == "nosalt": cmd += ["-nosalt"]
    if saltmode == "derived" and derived_hex: cmd += ["-S", derived_hex]
    if mode == "md5": cmd += ["-md","md5"]
    if mode == "sha256" and iters==0: cmd += ["-md","sha256"]
    if mode == "pbkdf2": cmd += ["-pbkdf2","-md","sha256","-iter",str(iters)]
    cmd += ["-pass", f"pass:{pw}"]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return proc.returncode==0, proc.stdout, proc.stderr.decode(errors="ignore")[:2000]
    except FileNotFoundError:
        print("openssl not found", file=sys.stderr); sys.exit(3)

def classify(pt):
    if not pt: return "ERROR"
    # magic bytes
    if pt.startswith(b"PK\x03\x04") or pt.startswith(b"%PDF") or pt.startswith(b"\x89PNG"):
        return "BINARY_CONTAINER"
    printable = sum(1 for c in pt.decode("latin1") if c.isprintable())
    ratio = printable/max(1,len(pt))
    if ratio < 0.7: return "GIBBERISH"
    if any(ch.isalpha() for ch in pt.decode("utf-8","ignore")): return "PLAUSIBLE_TEXT"
    return "GIBBERISH"

def evp_bytes_to_key(password: bytes, salt: bytes, md: str) -> tuple[bytes, bytes]:
    """OpenSSL EVP_BytesToKey for md5 or sha256 (*one* iteration)."""
    digester = hashlib.md5 if md == "md5" else hashlib.sha256
    d = b""
    while len(d) < 48:  # 32 key + 16 IV
        d += digester(d + password + salt).digest()
    return d[:32], d[32:48]

def aes_decrypt(blob_b64: str, pw: str, mode: str, salt_opt: str) -> bytes | None:
    """Decrypt helper.
    mode: md5 | sha256 | pbkdf2-<iters>
    salt_opt: header | matrixsumlist | matrixhash | none
    """
    # Pad to correct length
    padded = blob_b64 + "=" * (-len(blob_b64) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except Exception:
        return None
    if not raw.startswith(b"Salted__"):
        return None
    hdr_salt = raw[8:16]
    ct = raw[16:]

    if salt_opt == "header":
        salt = hdr_salt
    elif salt_opt == "matrixsumlist":
        salt = bytes.fromhex(hashlib.sha256(b"matrixsumlist").hexdigest()[:16])
    elif salt_opt == "matrixhash":
        salt = bytes.fromhex(hashlib.sha256(b"matrixsumlist").hexdigest()[:16])
    else:
        salt = b""

    if mode.startswith("pbkdf2"):
        iters = int(mode.split("-")[1])
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iters, dklen=48)
        key, iv = dk[:32], dk[32:48]
    else:
        md = "md5" if mode == "md5" else "sha256"
        key, iv = evp_bytes_to_key(pw.encode(), salt, md)
    aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
    dec = pyaes.Decrypter(aes)  # default: PKCS7 unpad
    try:
        return dec.feed(ct) + dec.finish()
    except Exception:
        return None

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--blob", required=True)
    p.add_argument("--seeds-file")
    p.add_argument("--max-candidates", type=int, default=200)
    p.add_argument("--stop-on-first", action="store_true")
    p.add_argument("--top-derive-limit", type=int, default=50)
    args = p.parse_args()

    seeds = DEFAULT_SEEDS.copy()
    if args.seeds_file:
        seeds = [l.strip() for l in Path(args.seeds_file).read_text().splitlines() if l.strip()]
    # generate variants
    candidates=[]
    for s in seeds[:args.max_candidates]:
        candidates += [s, s.upper(), s.title(), s+"\n", s+"\r\n"]
    # add sha256 hexs
    candidates += [hashlib.sha256(x.encode()).hexdigest() for x in candidates]
    # dedupe preserving order
    seen=set(); final=[]
    for c in candidates:
        if c not in seen:
            seen.add(c); final.append(c)

    blob = args.blob
    derived = hashlib.sha256("matrixsumlist".encode()).hexdigest()[:16]
    modes = [("md5",0),("sha256",0),("pbkdf2",1000),("pbkdf2",10000)]
    salt_modes = ["embedded","nosalt"]
    logf = Path("salphaseion_attempts.jsonl")
    attempts=0
    for idx,cand in enumerate(final):
        for salt in salt_modes:
            for mode,iters in modes:
                ok, out, err = run_openssl(blob, cand, mode, iters, salt)
                attempts+=1
                cls="ERROR"
                sample=""
                if ok:
                    cls = classify(out)
                    sample = out.decode("utf-8","ignore")[:200].replace("\n","\\n")
                entry = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                         "candidate": cand, "derivation": mode, "iters": iters,
                         "salt_mode": salt, "result": cls, "sample": sample}
                logf.write_text(logf.read_text()+json.dumps(entry)+"\n" if logf.exists() else json.dumps(entry)+"\n")
                if cls in ("PLAUSIBLE_TEXT","BINARY_CONTAINER"):
                    h = hashlib.sha256(out).hexdigest()
                    p = OUTDIR / f"pt_{h}.bin"
                    p.write_bytes(out)
                    print("HIT:", entry)
                    if args.stop_on_first: return
        # derived salt
        if idx < args.top_derive_limit:
            for mode,iters in modes:
                ok,out,err = run_openssl(blob, cand, mode, iters, "derived", derived)
                attempts+=1
                cls="ERROR"; sample=""
                if ok:
                    cls=classify(out); sample=out.decode("utf-8","ignore")[:200].replace("\n","\\n")
                entry = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                         "candidate": cand, "derivation": mode, "iters": iters,
                         "salt_mode": "derived", "derived_salt_hex": derived, "result": cls, "sample": sample}
                logf.write_text(logf.read_text()+json.dumps(entry)+"\n" if logf.exists() else json.dumps(entry)+"\n")
                if cls in ("PLAUSIBLE_TEXT","BINARY_CONTAINER"):
                    h=hashlib.sha256(out).hexdigest()
                    p=OUTDIR/f"pt_{h}.bin"; p.write_bytes(out)
                    print("HIT (derived):", entry)
                    if args.stop_on_first: return
    print("done attempts", attempts)

if __name__=="__main__":
    main()
