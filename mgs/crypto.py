"""Streaming authenticated encryption (MGS3 container).

Why this exists: v1.x used Fernet, which must hold the *whole* plaintext and
ciphertext in RAM, so multi-gigabyte files were impossible. MGS3 encrypts in
independent AES-256-GCM chunks, so memory use is constant (~2 chunks) no matter
how large the data is.

Layout (all integers big-endian)::

    header (64 bytes)
        magic        4   b"MGS3"
        version      1
        kdf          1   1 = PBKDF2-HMAC-SHA256
        chunk_log2   1   chunk size = 1 << chunk_log2   (default 22 -> 4 MiB)
        reserved     1
        iterations   4   PBKDF2 iteration count
        salt        16
        nonce_prefix 4   random, per container
        keycheck    32   HMAC-SHA256(check_key, header[:32])
    chunks, repeated
        u32   bit31 = "final chunk" flag, bits 0-30 = ciphertext length
        ciphertext (plaintext + 16 byte GCM tag)

Security properties
    * Key = PBKDF2-HMAC-SHA256(password, random salt, 600k iterations); two
      independent sub-keys (encryption, key-check) are split off with HMAC.
    * Nonce = 4-byte random prefix || 8-byte chunk counter (never repeats for
      a given key, since every container has a fresh salt -> fresh key).
    * AAD = magic || chunk index || final flag, so chunks cannot be reordered,
      duplicated, dropped, or the stream silently truncated (the last chunk
      must carry the final flag).
    * The key-check lets us report "wrong password" separately from
      "corrupted data".
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import FormatError, IntegrityError, UsageError, WrongPasswordError
from .util import ProgressCB, normalize_password

MAGIC = b"MGS3"
FORMAT_VERSION = 1
KDF_PBKDF2_SHA256 = 1
HEADER_LEN = 64
TAG_LEN = 16
FINAL_FLAG = 0x80000000

DEFAULT_ITERATIONS = 600_000
MIN_ITERATIONS = 1_000          # lower values are only meant for unit tests
MAX_ITERATIONS = 200_000_000    # sanity cap so a hostile header cannot hang us
DEFAULT_CHUNK_LOG2 = 22         # 4 MiB
MIN_CHUNK_LOG2, MAX_CHUNK_LOG2 = 12, 26


@dataclass
class Header:
    version: int
    kdf: int
    chunk_log2: int
    iterations: int
    salt: bytes
    nonce_prefix: bytes
    keycheck: bytes
    raw: bytes

    @property
    def chunk_size(self) -> int:
        return 1 << self.chunk_log2


def derive_keys(password: str, salt: bytes, iterations: int):
    master = hashlib.pbkdf2_hmac("sha256", normalize_password(password), salt, iterations, 32)
    enc = hmac.new(master, b"mgs3/enc", hashlib.sha256).digest()
    chk = hmac.new(master, b"mgs3/chk", hashlib.sha256).digest()
    return enc, chk


def parse_header(raw: bytes) -> Header:
    if len(raw) < HEADER_LEN or raw[:4] != MAGIC:
        raise FormatError("Not a Mughees MGS3 container (bad magic).")
    version, kdf, chunk_log2, _res = raw[4], raw[5], raw[6], raw[7]
    iterations = struct.unpack(">I", raw[8:12])[0]
    if version != FORMAT_VERSION:
        raise FormatError(f"Unsupported container version {version}.")
    if kdf != KDF_PBKDF2_SHA256:
        raise FormatError(f"Unsupported key-derivation function id {kdf}.")
    if not MIN_CHUNK_LOG2 <= chunk_log2 <= MAX_CHUNK_LOG2:
        raise FormatError("Container header is damaged (bad chunk size).")
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise FormatError("Container header is damaged (bad KDF iterations).")
    return Header(version, kdf, chunk_log2, iterations, raw[12:28], raw[28:32], raw[32:64], raw[:HEADER_LEN])


def _aad(index: int, final: bool) -> bytes:
    return MAGIC + index.to_bytes(8, "big") + (b"\x01" if final else b"\x00")


def _nonce(prefix: bytes, index: int) -> bytes:
    return prefix + index.to_bytes(8, "big")


class EncryptWriter:
    """File-like sink that encrypts everything written to it into ``sink``."""

    def __init__(
        self,
        sink: BinaryIO,
        password: str,
        *,
        iterations: int = DEFAULT_ITERATIONS,
        chunk_log2: int = DEFAULT_CHUNK_LOG2,
        progress: Optional[ProgressCB] = None,
    ):
        if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
            raise UsageError("KDF iterations out of range.")
        if not MIN_CHUNK_LOG2 <= chunk_log2 <= MAX_CHUNK_LOG2:
            raise UsageError("Chunk size out of range.")
        salt = os.urandom(16)
        nonce_prefix = os.urandom(4)
        head = MAGIC + bytes([FORMAT_VERSION, KDF_PBKDF2_SHA256, chunk_log2, 0])
        head += struct.pack(">I", iterations) + salt + nonce_prefix
        key, chk = derive_keys(password, salt, iterations)
        header = head + hmac.new(chk, head, hashlib.sha256).digest()
        assert len(header) == HEADER_LEN
        self._sink = sink
        self._aes = AESGCM(key)
        self._prefix = nonce_prefix
        self._chunk = 1 << chunk_log2
        self._buf = bytearray()
        self._index = 0
        self._closed = False
        self.bytes_in = 0
        self.bytes_out = HEADER_LEN
        self.progress = progress
        sink.write(header)

    def _emit(self, plain, final: bool) -> None:
        if self._index >= 1 << 40:  # pragma: no cover - ~4 exabytes
            raise UsageError("Container too large.")
        ct = self._aes.encrypt(_nonce(self._prefix, self._index), bytes(plain), _aad(self._index, final))
        self._sink.write(struct.pack(">I", len(ct) | (FINAL_FLAG if final else 0)))
        self._sink.write(ct)
        self._index += 1
        self.bytes_out += 4 + len(ct)

    def write(self, data) -> int:
        if self._closed:
            raise ValueError("write to closed EncryptWriter")
        mv = memoryview(data).cast("B")
        n = len(mv)
        self.bytes_in += n
        if self._buf:
            take = min(self._chunk - len(self._buf), len(mv))
            self._buf += mv[:take]
            mv = mv[take:]
            if len(self._buf) == self._chunk:
                self._emit(self._buf, False)
                self._buf.clear()
        while len(mv) >= self._chunk:
            self._emit(mv[: self._chunk], False)
            mv = mv[self._chunk:]
        if len(mv):
            self._buf += mv
        return n

    def close(self) -> None:
        if self._closed:
            return
        self._emit(self._buf, True)
        self._buf.clear()
        self._closed = True


class _Bounded:
    """Read at most ``length`` bytes from ``f`` starting at its current position."""

    def __init__(self, f: BinaryIO, length: Optional[int]):
        self.f = f
        self.remaining = length

    def read(self, n: int) -> bytes:
        if self.remaining is not None:
            n = min(n, self.remaining)
        data = self.f.read(n) if n > 0 else b""
        if self.remaining is not None:
            self.remaining -= len(data)
        return data


def _read_exact(src, n: int, what: str) -> bytes:
    out = bytearray()
    while len(out) < n:
        b = src.read(n - len(out))
        if not b:
            raise IntegrityError(f"Container is truncated (while reading {what}).")
        out += b
    return bytes(out)


class DecryptReader:
    """File-like source that yields decrypted bytes from an MGS3 container."""

    def __init__(self, source: BinaryIO, password: str, *, length: Optional[int] = None):
        self._src = _Bounded(source, length)
        self._length = length
        try:
            raw = _read_exact(self._src, HEADER_LEN, "header")
        except IntegrityError:
            raise FormatError("Not a Mughees MGS3 container (too short).") from None
        self.header = parse_header(raw)
        key, chk = derive_keys(password, self.header.salt, self.header.iterations)
        expect = hmac.new(chk, raw[: HEADER_LEN - 32], hashlib.sha256).digest()
        if not hmac.compare_digest(expect, self.header.keycheck):
            raise WrongPasswordError("Wrong password (or the container header is damaged).")
        self._aes = AESGCM(key)
        self._index = 0
        self._cur = b""
        self._pos = 0
        self._final_seen = False
        self.bytes_consumed = HEADER_LEN  # raw container bytes read so far

    def _next_chunk(self) -> bool:
        if self._final_seen:
            return False
        prefix = _read_exact(self._src, 4, "chunk header")
        word = struct.unpack(">I", prefix)[0]
        final = bool(word & FINAL_FLAG)
        clen = word & 0x7FFFFFFF
        if clen < TAG_LEN or clen > self.header.chunk_size + TAG_LEN:
            raise IntegrityError("Container is damaged (bad chunk length).")
        ct = _read_exact(self._src, clen, "chunk data")
        try:
            plain = self._aes.decrypt(_nonce(self.header.nonce_prefix, self._index), ct, _aad(self._index, final))
        except InvalidTag:
            raise IntegrityError(
                f"Data failed its integrity check at chunk {self._index} (corrupted, truncated or tampered)."
            ) from None
        self._index += 1
        self.bytes_consumed += 4 + clen
        self._cur, self._pos = plain, 0
        if final:
            self._final_seen = True
            if self._src.remaining:
                raise FormatError("Unexpected extra data after the end of the container.")
        return True

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            parts = []
            while True:
                b = self.read(1 << 22)
                if not b:
                    return b"".join(parts)
                parts.append(b)
        out = bytearray()
        while len(out) < n:
            if self._pos >= len(self._cur):
                if not self._next_chunk():
                    break
                continue
            take = min(n - len(out), len(self._cur) - self._pos)
            out += self._cur[self._pos:self._pos + take]
            self._pos += take
        return bytes(out)

    def read_exact(self, n: int, what: str = "data") -> bytes:
        b = self.read(n)
        if len(b) != n:
            raise IntegrityError(f"Container ended unexpectedly while reading {what}.")
        return b

    def finish(self) -> None:
        """Ensure the final chunk was reached and authenticated."""
        if self._pos < len(self._cur):
            raise FormatError("Container has unread plaintext at the end.")
        while not self._final_seen:
            self._next_chunk()
            if self._cur:
                raise FormatError("Container has unexpected data after the archive end.")
