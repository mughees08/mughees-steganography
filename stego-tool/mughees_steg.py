#!/usr/bin/env python3
"""
Mughees Steganography v3.0
Developer: Muhammad Mughees Abbasi
Hide any file inside PNG images with AES-256 encryption.
"""
import argparse, hashlib, json, os, struct, sys, zlib
from pathlib import Path
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"MSGV3\x00\x01"
SALT_LEN = 16
ITER_DEFAULT = 200_000
HEADER_FMT = ">8s16sIBBQHHHI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

class C:
    R="\033[0m"; B="\033[1m"; G="\033[32m"; Y="\033[33m"; Cy="\033[36m"; Rd="\033[31m"

def ok(s): print(f"{C.G}  [✓] {s}{C.R}")
def err(s): print(f"{C.Rd}[✗] {s}{C.R}", file=sys.stderr); sys.exit(1)
def warn(s): print(f"{C.Y}[!] {s}{C.R}", file=sys.stderr)
def info(s): print(f"{C.Cy}[*] {s}{C.R}")
def head(s): print(f"\n{C.B}{C.Cy}{s}{C.R}")

def banner():
    print(f"{C.Cy}{C.B}")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║              M U G H E E S   S T E G A N O G R A P H Y       ║")
    print("║              Advanced Steganography Toolkit · v3.0           ║")
    print("║              Developer: Muhammad Mughees Abbasi              ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(C.R)

def derive_key(password, salt, iterations):
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, iterations)
    return kdf.derive(password.encode())

def encrypt(key, data):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)

def decrypt(key, blob):
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)

def build_payload(files):
    parts = [struct.pack(">H", len(files))]
    for path in files:
        p = Path(path); data = p.read_bytes(); nb = p.name.encode()
        parts.extend([struct.pack(">H", len(nb)) + nb,
                      struct.pack(">Q", len(data)) + hashlib.sha256(data).digest(), data])
    return b"".join(parts)

def parse_payload(plain):
    n, = struct.unpack(">H", plain[:2]); off = 2; entries = []
    for _ in range(n):
        nlen, = struct.unpack(">H", plain[off:off+2]); off += 2
        name = plain[off:off+nlen].decode(); off += nlen
        size, = struct.unpack(">Q", plain[off:off+8]); off += 8
        digest = plain[off:off+32]; off += 32
        data = plain[off:off+size]; off += size
        if hashlib.sha256(data).digest() != digest:
            raise ValueError(f"integrity failed: {name}")
        entries.append(dict(name=name, size=size, sha256=digest.hex(), data=data))
    return entries

def usable(path):
    with Image.open(path) as im: w, h = im.size
    return (w * h * 3) // 8 - HEADER_SIZE

def embed_chunk(arr, chunk, salt, iters, count, total_size, idx, total):
    hdr = struct.pack(HEADER_FMT, MAGIC, salt, iters, 3, 0, total_size, count, idx, total, len(chunk))
    bits = np.unpackbits(np.frombuffer(hdr + chunk, dtype=np.uint8), bitorder="big")
    flat = arr.reshape(-1)
    flat[:bits.size] = (flat[:bits.size] & 0xFE) | bits
    return arr

def read_chunk(path):
    with Image.open(path) as im: arr = np.array(im.convert("RGB"), dtype=np.uint8)
    flat = arr.reshape(-1)
    f = struct.unpack(HEADER_FMT, np.packbits(flat[:HEADER_SIZE*8] & 1, bitorder="big").tobytes())
    if f[0] != MAGIC: raise ValueError("no payload")
    clen = f[-1]; end = HEADER_SIZE*8 + clen*8
    chunk = np.packbits(flat[HEADER_SIZE*8:end] & 1, bitorder="big").tobytes()
    return dict(salt=f[1], iterations=f[2], total_size=f[5], file_count=f[6], idx=f[7], total=f[8], chunk=chunk)

def cmd_hide(args):
    plain = build_payload(args.files)
    compressed = zlib.compress(plain, 9)
    salt = os.urandom(SALT_LEN)
    encrypted = encrypt(derive_key(args.password, salt, args.iterations), compressed)
    total_bytes = len(encrypted)
    covers = list(args.images); caps = [usable(c) for c in covers]
    if sum(caps) < total_bytes: err(f"capacity insufficient. Need {total_bytes} B, have {sum(caps)} B.")
    chunks = []; off = 0
    for cap in caps:
        if off >= total_bytes: break
        chunks.append(encrypted[off:off+cap]); off += len(chunks[-1])
    outputs = args.outputs or [f"vault_part{i+1}.png" for i in range(len(chunks))]
    for i, (cover, out, chunk) in enumerate(zip(covers, outputs, chunks)):
        with Image.open(cover) as im: arr = np.array(im.convert("RGB"), dtype=np.uint8)
        arr = embed_chunk(arr, chunk, salt, args.iterations, len(args.files), total_bytes, i, len(chunks))
        Image.fromarray(arr).save(out, "PNG")
        ok(f"part {i+1}/{len(chunks)} → {out}")
    ok(f"done — {total_bytes} bytes embedded")

def cmd_extract(args):
    infos = [read_chunk(p) for p in args.images]; infos.sort(key=lambda x: x["idx"])
    token = b"".join(i["chunk"] for i in infos)
    try: entries = parse_payload(zlib.decompress(decrypt(derive_key(args.password, infos[0]["salt"], infos[0]["iterations"]), token)))
    except Exception: err("wrong password or corrupted")
    out_dir = Path(args.output or "extracted"); out_dir.mkdir(exist_ok=True)
    for e in entries:
        (out_dir / e["name"]).write_bytes(e["data"]); ok(f"{e['name']} extracted")

def cmd_info(args):
    for p in args.images:
        try:
            i = read_chunk(p)
            print(f"\n{C.B}{p}{C.R} | files: {i['file_count']} | part: {i['idx']+1}/{i['total']} | {C.G}HAS payload{C.R}")
        except ValueError: print(f"\n{C.B}{p}{C.R} | capacity: {usable(p):,} B | {C.Y}empty{C.R}")

def cmd_generate(args):
    arr = np.random.randint(0, 256, (args.size, args.size, 3), dtype=np.uint8)
    Image.fromarray(arr).save(args.output, "PNG"); ok(f"generated {args.output} (capacity {usable(args.output):,} B)")

def main():
    p = argparse.ArgumentParser(description="Mughees Steganography v3.0")
    sub = p.add_subparsers(dest="cmd", required=True)
    ph = sub.add_parser("hide"); ph.add_argument("images", nargs="+"); ph.add_argument("-f", "--files", nargs="+", required=True); ph.add_argument("-o", "--outputs", nargs="+"); ph.add_argument("-p", "--password", required=True); ph.add_argument("--iterations", type=int, default=ITER_DEFAULT); ph.set_defaults(func=cmd_hide)
    pe = sub.add_parser("extract"); pe.add_argument("images", nargs="+"); pe.add_argument("-o", "--output"); pe.add_argument("-p", "--password", required=True); pe.set_defaults(func=cmd_extract)
    pi = sub.add_parser("info"); pi.add_argument("images", nargs="+"); pi.set_defaults(func=cmd_info)
    pg = sub.add_parser("generate"); pg.add_argument("--size", type=int, default=2048); pg.add_argument("-o", "--output", default="cover.png"); pg.set_defaults(func=cmd_generate)
    a = p.parse_args(); banner(); a.func(a)

if __name__ == "__main__": main()
