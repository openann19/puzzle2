#!/usr/bin/env python3
# btc_key_prove.py
# Usage:
# 1) echo "<hexpriv>" | python btc_key_prove.py           # read hex priv from stdin
# 2) python btc_key_prove.py --wif <WIF>                 # or use WIF
# Output: derived addresses and a signed test message (base64)

from __future__ import annotations
import sys, argparse, hashlib, base64
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der, sigdecode_der

# --- base58 and helpers ---
ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58encode(b: bytes) -> str:
    # simple base58 encode
    n = int.from_bytes(b, 'big')
    res = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        res.insert(0, ALPHABET[r])
    # leading zeros
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return (ALPHABET[0:1] * pad + res).decode()

def b58decode(s: str) -> bytes:
    n = 0
    for ch in s.encode():
        n = n * 58 + ALPHABET.index(bytes([ch]))
    # produce bytes, with leading zero count
    full = n.to_bytes((n.bit_length() + 7) // 8, 'big') or b'\x00'
    pad = 0
    for ch in s:
        if ch == '1':
            pad += 1
        else:
            break
    return b'\x00'*pad + full

def wif_to_priv(wif: str) -> bytes:
    data = b58decode(wif)
    # last 4 bytes = checksum; strip
    payload, checksum = data[:-4], data[-4:]
    # payload format: 0x80 + priv (+ 0x01 if compressed)
    if payload[0] != 0x80:
        raise ValueError("Not a mainnet WIF")
    if len(payload) == 34 and payload[-1] == 0x01:
        return payload[1:-1]  # compressed private key
    return payload[1:]  # 32-byte priv

def ripemd160(x: bytes) -> bytes:
    h = hashlib.new('ripemd160')
    h.update(x)
    return h.digest()

def sha256(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def pubkey_from_priv(priv_bytes: bytes, compressed: bool = True) -> bytes:
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()
    px = vk.to_string()  # 64 bytes (x||y)
    x = px[:32]; y = px[32:]
    if compressed:
        prefix = b'\x02' if (y[-1] % 2 == 0) else b'\x03'
        return prefix + x
    else:
        return b'\x04' + x + y

def p2pkh_address(pubkey_bytes: bytes) -> str:
    h = ripemd160(sha256(pubkey_bytes))
    payload = b'\x00' + h  # version 0x00 mainnet
    checksum = sha256(sha256(payload))[:4]
    return b58encode(payload + checksum)

def sign_message(priv_bytes: bytes, message: str) -> str:
    # Bitcoin Signed Message format
    prefix = b"\x18Bitcoin Signed Message:\n"
    def varstr(s: bytes) -> bytes:
        L = len(s)
        if L < 253:
            return bytes([L]) + s
        raise ValueError("message too long")
    msg = prefix + varstr(message.encode('utf-8'))
    digest = sha256(sha256(msg))
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    sig = sk.sign_digest(digest, sigencode=sigencode_der)
    # return base64 DER signature (note: Bitcoin-core uses a different compact format
    # for their signmessage which includes recovery id. For a canonical prove we do DER)
    return base64.b64encode(sig).decode()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--wif', help="WIF private key (mainnet)")
    parser.add_argument('--hex', help="private key hex (32 bytes)")
    parser.add_argument('--message', default="I control this address (puzzle proof)", help="message to sign")
    args = parser.parse_args()
    priv = None
    compressed = True
    if args.wif:
        try:
            priv = wif_to_priv(args.wif)
            # assume compressed if WIF length indicated
        except Exception as e:
            print("WIF decode error:", e, file=sys.stderr); sys.exit(2)
    elif args.hex:
        s = args.hex.strip()
        if len(s) != 64:
            print("Expect 64-hex chars for 32-byte private key", file=sys.stderr); sys.exit(2)
        priv = bytes.fromhex(s)
    else:
        # read from stdin (hex)
        raw = sys.stdin.read().strip()
        if raw:
            if all(c in "0123456789abcdefABCDEF" for c in raw) and len(raw) in (64, 66, 68):
                priv = bytes.fromhex(raw[:64])
            else:
                print("Provide hex private key on stdin or use --wif/--hex", file=sys.stderr); sys.exit(2)
    if not priv:
        print("No private key provided", file=sys.stderr); sys.exit(2)

    # derive pubkeys & addresses
    pub_comp = pubkey_from_priv(priv, compressed=True)
    pub_uncomp = pubkey_from_priv(priv, compressed=False)
    addr_comp = p2pkh_address(pub_comp)
    addr_uncomp = p2pkh_address(pub_uncomp)
    print("Compressed pubkey (hex):", pub_comp.hex())
    print("Uncompressed pubkey (hex):", pub_uncomp.hex())
    print("P2PKH address (compressed-pub):", addr_comp)
    print("P2PKH address (uncompressed-pub):", addr_uncomp)

    # sign message
    sig = sign_message(priv, args.message)
    print("Signature (base64 DER):", sig)
    print("Message signed:", args.message)

if __name__ == '__main__':
    main()
