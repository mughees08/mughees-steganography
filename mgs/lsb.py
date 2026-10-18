"""Image LSB steganography (vectorised with NumPy) + image comparison.

What is hidden is always a small encrypted MGS3 container (see ``crypto``), so
the pixel layer only ever carries ciphertext.

Pixel layout
    * A 25-byte header lives in the first 200 colour-channel slots (1 bit
      each, sequential): ``b"MGL1" | flags | payload_len(u32) | salt(16)``.
    * The payload occupies the remaining slots, ``bits`` bits per slot
      (1-4; 1 is the least visible). By default the slot order is *scattered*
      by a keyed Feistel permutation derived from the password, so the
      changes are spread over the whole image instead of filling the top rows
      (which is what simple LSB detectors look for).

Capacity reality check: an image carries ``width x height x 3 x bits / 8``
bytes. A 12 MP photo holds ~4.5 MB at 1 bit/channel. Gigabytes of data cannot
physically fit in an image; use carrier mode / vaults (see ``container``) for
that.
"""

from __future__ import annotations

import hashlib
import math
import os
import struct
import threading
import time
import warnings
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
from PIL import Image

from . import legacy
from .carrier import guard_no_executables
from .container import pack_bytes, unpack_bytes
from .errors import (
    CapacityError, FormatError, GuardrailError, IntegrityError, UsageError, WrongPasswordError,
)
from .archive import Item, K_FILE
from .util import AtomicWriter, ProgressCB, assert_distinct, normalize_password, unique_path

LSB_MAGIC = b"MGL1"
HEADER_BYTES = 25
HEADER_SLOTS = HEADER_BYTES * 8
FLAG_SCATTER = 0x08
SCATTER_KDF_ITERS = 100_000
BLOCK_BYTES = 12 * (1 << 15)        # payload bytes per processing block
DEFAULT_MAX_PIXELS = 1_000_000_000
TEXT_ENTRY = "message.txt"

_pil_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# Image I/O
# --------------------------------------------------------------------------- #

@contextmanager
def _open_image(path: str, max_pixels: int):
    if not os.path.isfile(path):
        raise UsageError(f"Image not found: {path}")
    with _pil_lock:
        old = Image.MAX_IMAGE_PIXELS
        Image.MAX_IMAGE_PIXELS = None
        try:
            try:
                img = Image.open(path)
            except Exception as exc:  # PIL raises many types
                raise UsageError(f"Cannot open image {path}: {exc}") from exc
        finally:
            Image.MAX_IMAGE_PIXELS = old
    try:
        if img.width * img.height > max_pixels:
            raise UsageError(f"Image is too large ({img.width}x{img.height}); raise max_pixels to allow it.")
        yield img
    finally:
        img.close()


def _to_array(img: Image.Image) -> np.ndarray:
    has_alpha = img.mode in ("RGBA", "LA", "PA") or "transparency" in img.info
    img = img.convert("RGBA" if has_alpha else "RGB")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        arr = np.array(img, dtype=np.uint8)   # writable copy, shape (H, W, C)
    return arr


def _flat_index(slots: np.ndarray, channels: int) -> np.ndarray:
    """Map logical RGB slot numbers to indexes in the flat H*W*C array."""
    slots = slots.astype(np.int64, copy=False)
    return slots if channels == 3 else slots + slots // 3


# --------------------------------------------------------------------------- #
# Keyed permutation (deterministic across NumPy versions: integer ops only)
# --------------------------------------------------------------------------- #

_U = np.uint64
_C1, _C2 = _U(0xFF51AFD7ED558CCD), _U(0xC4CEB9FE1A85EC53)


def _mix(v: np.ndarray) -> np.ndarray:
    v = v ^ (v >> _U(33))
    v = v * _C1
    v = v ^ (v >> _U(29))
    v = v * _C2
    return v ^ (v >> _U(32))


class _Permutation:
    """Bijection on ``[0, n)`` derived from a 32-byte key (Feistel + cycle walking)."""

    ROUNDS = 6

    def __init__(self, n: int, key: bytes):
        self.n = n
        bits = max(2, (max(n - 1, 1)).bit_length())
        self.half = (bits + 1) // 2
        self.mask = _U((1 << self.half) - 1)
        raw = hashlib.sha512(b"mgs-feistel" + key).digest()
        self.keys = [_U(k) for k in struct.unpack(">6Q", raw[:48])]

    def _feistel(self, x: np.ndarray) -> np.ndarray:
        h = _U(self.half)
        left, right = x >> h, x & self.mask
        for k in self.keys:
            left, right = right, left ^ (_mix(right + k) & self.mask)
        return (left << h) | right

    def __call__(self, idx: np.ndarray) -> np.ndarray:
        y = self._feistel(idx.astype(np.uint64))
        bad = y >= _U(self.n)
        while bad.any():
            y[bad] = self._feistel(y[bad])
            bad = y >= _U(self.n)
        return y.astype(np.int64)


def _scatter_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", normalize_password(password), b"mgs-lsb" + salt, SCATTER_KDF_ITERS, 32)


# --------------------------------------------------------------------------- #
# Bit packing helpers
# --------------------------------------------------------------------------- #

def _weights(bits: int) -> np.ndarray:
    return (1 << np.arange(bits - 1, -1, -1)).astype(np.uint8)


def _payload_to_values(chunk: bytes, bits: int, last: bool) -> np.ndarray:
    arr = np.unpackbits(np.frombuffer(chunk, dtype=np.uint8))
    rem = len(arr) % bits
    if rem:
        if not last:  # pragma: no cover - block size is a multiple of every bit width
            raise AssertionError("misaligned block")
        arr = np.concatenate([arr, np.zeros(bits - rem, dtype=np.uint8)])
    if bits == 1:
        return arr
    return (arr.reshape(-1, bits) * _weights(bits)).sum(axis=1).astype(np.uint8)


def _values_to_bits(vals: np.ndarray, bits: int) -> np.ndarray:
    if bits == 1:
        return vals & 1
    return np.unpackbits(vals[:, None].astype(np.uint8), axis=1)[:, 8 - bits:].reshape(-1)


# --------------------------------------------------------------------------- #
# Capacity
# --------------------------------------------------------------------------- #

_OVERHEAD_CACHE: Dict[str, int] = {}


def _container_overhead() -> int:
    if "v" not in _OVERHEAD_CACHE:
        _OVERHEAD_CACHE["v"] = len(pack_bytes([(TEXT_ENTRY, b"")], "probe", iterations=1000))
    return _OVERHEAD_CACHE["v"]


def capacity(image: str, bits: int = 1, max_pixels: int = DEFAULT_MAX_PIXELS) -> Dict[str, Any]:
    _check_bits(bits)
    with _open_image(image, max_pixels) as img:
        w, h = img.size
    slots = w * h * 3 - HEADER_SLOTS
    raw = max(slots * bits // 8, 0)
    overhead = HEADER_BYTES + _container_overhead()
    return {
        "image": image, "width": w, "height": h, "bits_per_channel": bits,
        "raw_bytes": raw, "overhead_bytes": overhead,
        "usable_bytes": max(raw - overhead, 0),
    }


def _check_bits(bits: int) -> None:
    if bits not in (1, 2, 3, 4):
        raise UsageError("bits must be 1, 2, 3 or 4 (1 = least visible).")


# --------------------------------------------------------------------------- #
# Hide
# --------------------------------------------------------------------------- #

def _positions(start: int, count: int, perm: Optional[_Permutation]) -> np.ndarray:
    idx = np.arange(start, start + count, dtype=np.int64)
    if perm is not None:
        idx = perm(idx)
    return idx + HEADER_SLOTS


def hide(
    image: str,
    output: str,
    password: str,
    *,
    text: Optional[str] = None,
    files: Sequence[str] = (),
    bits: int = 1,
    scatter: bool = True,
    overwrite: bool = False,
    iterations: int = 600_000,
    max_pixels: int = DEFAULT_MAX_PIXELS,
    progress: Optional[ProgressCB] = None,
) -> Dict[str, Any]:
    """Hide encrypted text and/or small files in a copy of ``image`` (saved as PNG)."""
    t0 = time.time()
    _check_bits(bits)
    if text is None and not files:
        raise UsageError("Nothing to hide: give text and/or files.")
    assert_distinct(output, image, *files)
    entries: List[Tuple[str, bytes]] = []
    if text is not None:
        entries.append((TEXT_ENTRY, text.encode("utf-8")))
    items = []
    for fp in files:
        if not os.path.isfile(fp):
            raise UsageError(f"Not a file (LSB mode stores single small files only): {fp}")
        with open(fp, "rb") as fh:
            data = fh.read()
        name = os.path.basename(fp)
        if name == TEXT_ENTRY and text is not None:
            raise UsageError(f"A file called {TEXT_ENTRY} clashes with the text message.")
        items.append(Item(K_FILE, name, path=fp, data=data, size=len(data)))
        entries.append((name, data))
    guard_no_executables(items)

    blob = pack_bytes(entries, password, iterations=iterations)
    if len(blob) >= 1 << 32:
        raise CapacityError("Payload too large for LSB mode (4 GiB limit).")

    with _open_image(image, max_pixels) as img:
        arr = _to_array(img)
    h, w, ch = arr.shape
    flat = arr.reshape(-1)
    total_slots = h * w * 3
    n_pay_slots = math.ceil(len(blob) * 8 / bits)
    avail = total_slots - HEADER_SLOTS
    if n_pay_slots > avail:
        raise CapacityError(
            f"Payload needs {len(blob):,} bytes but this image holds only {avail * bits // 8:,} "
            f"at {bits} bit/channel. Use a bigger image, more bits, or carrier mode for large data."
        )

    salt = os.urandom(16)
    flags = (bits - 1) | (FLAG_SCATTER if scatter else 0)
    header = LSB_MAGIC + bytes([flags]) + struct.pack(">I", len(blob)) + salt
    hbits = np.unpackbits(np.frombuffer(header, dtype=np.uint8))
    hidx = _flat_index(np.arange(HEADER_SLOTS), ch)
    flat[hidx] = (flat[hidx] & 0xFE) | hbits

    perm = _Permutation(avail, _scatter_key(password, salt)) if scatter else None
    mask = np.uint8((0xFF << bits) & 0xFF)
    done_slots = 0
    for off in range(0, len(blob), BLOCK_BYTES):
        chunk = blob[off:off + BLOCK_BYTES]
        vals = _payload_to_values(chunk, bits, last=off + BLOCK_BYTES >= len(blob))
        fidx = _flat_index(_positions(done_slots, len(vals), perm), ch)
        flat[fidx] = (flat[fidx] & mask) | vals
        done_slots += len(vals)
        if progress:
            progress(min(off + BLOCK_BYTES, len(blob)), len(blob))

    out_img = Image.fromarray(arr, "RGBA" if ch == 4 else "RGB")
    with AtomicWriter(output, overwrite=overwrite) as fh:
        out_img.save(fh, format="PNG", compress_level=4)
    return {
        "output": os.path.abspath(output), "payload_bytes": len(blob), "bits_per_channel": bits,
        "scatter": scatter, "changed_slots_max": n_pay_slots + HEADER_SLOTS,
        "capacity_used_pct": round(100.0 * len(blob) / max(avail * bits // 8, 1), 3),
        "seconds": time.time() - t0,
    }


# --------------------------------------------------------------------------- #
# Reveal
# --------------------------------------------------------------------------- #

def _read_seq_bytes(flat: np.ndarray, ch: int, nbytes: int, bit_offset: int) -> bytes:
    """Sequential 1-bit reader (used for the header and for v1.4 images)."""
    slots = np.arange(bit_offset, bit_offset + nbytes * 8)
    if len(slots) and slots[-1] >= (flat.size // ch) * 3:
        raise IntegrityError("Image data is corrupted or truncated.")
    return np.packbits(flat[_flat_index(slots, ch)] & 1).tobytes()


def reveal(
    image: str,
    password: str,
    *,
    dest: Optional[str] = None,
    overwrite: bool = False,
    max_pixels: int = DEFAULT_MAX_PIXELS,
) -> Dict[str, Any]:
    """Recover hidden text/files. Returns ``{"text": str|None, "files": [(name, bytes)], "saved": [...]}``.
    Files are written to ``dest`` if given."""
    with _open_image(image, max_pixels) as img:
        arr = _to_array(img)
    h, w, ch = arr.shape
    flat = arr.reshape(-1)
    total_slots = h * w * 3
    if total_slots < HEADER_SLOTS:
        raise FormatError("Image is too small to contain hidden data.")
    header = _read_seq_bytes(flat, ch, HEADER_BYTES, 0)

    if header[:4] != LSB_MAGIC:
        # v1.4 image? (sequential LSB, Fernet payload)
        try:
            text = legacy.reveal_legacy_lsb(lambda n, off: _read_seq_bytes(flat, ch, n, off), password)
        except FormatError:
            raise FormatError("No hidden data found in this image.") from None
        return {"text": text, "files": [], "saved": [], "legacy": True}

    flags = header[4]
    bits = (flags & 0x07) + 1
    if bits > 4:
        raise FormatError("Image header is damaged.")
    length = struct.unpack(">I", header[5:9])[0]
    salt = header[9:25]
    avail = total_slots - HEADER_SLOTS
    n_slots = math.ceil(length * 8 / bits)
    if length == 0 or n_slots > avail:
        raise IntegrityError("Hidden data header is damaged (image modified or re-encoded?).")

    perm = _Permutation(avail, _scatter_key(password, salt)) if flags & FLAG_SCATTER else None
    mask = np.uint8((1 << bits) - 1)
    out = bytearray()
    done = 0
    block_slots = BLOCK_BYTES * 8 // bits
    while done < n_slots:
        count = min(block_slots, n_slots - done)
        fidx = _flat_index(_positions(done, count, perm), ch)
        vals = flat[fidx] & mask
        out += np.packbits(_values_to_bits(vals, bits)).tobytes()
        done += count
    blob = bytes(out[:length])

    try:
        entries = unpack_bytes(blob, password)
    except FormatError:
        if perm is not None:   # positions are keyed by the password, so garbage == wrong password
            raise WrongPasswordError("Wrong password (or the image was modified after hiding).") from None
        raise IntegrityError("Hidden data is damaged (image modified or re-encoded?).") from None
    text = None
    files: List[Tuple[str, bytes]] = []
    for name, data in entries:
        if name == TEXT_ENTRY and text is None:
            text = data.decode("utf-8", "replace")
        else:
            files.append((name, data))
    saved: List[str] = []
    if dest and files:
        os.makedirs(dest, exist_ok=True)
        for name, data in files:
            target = os.path.join(dest, os.path.basename(name))
            if not overwrite:
                target = unique_path(target)
            with open(target, "wb") as fh:
                fh.write(data)
            saved.append(os.path.abspath(target))
    return {"text": text, "files": files, "saved": saved, "legacy": False}


# --------------------------------------------------------------------------- #
# Compare
# --------------------------------------------------------------------------- #

def compare_images(path_a: str, path_b: str, diff_output: Optional[str] = None,
                   overwrite: bool = True, max_pixels: int = DEFAULT_MAX_PIXELS) -> Dict[str, Any]:
    with _open_image(path_a, max_pixels) as ia, _open_image(path_b, max_pixels) as ib:
        if ia.size != ib.size:
            raise UsageError(f"Images differ in size: {ia.size} vs {ib.size}")
        a = np.asarray(ia.convert("RGB"), dtype=np.uint8)
        b = np.asarray(ib.convert("RGB"), dtype=np.uint8)
    diff = a != b
    changed_px = diff.any(axis=2)
    n_changed = int(changed_px.sum())
    total = a.shape[0] * a.shape[1]
    max_abs = int(np.abs(a.astype(np.int16) - b.astype(np.int16)).max()) if n_changed else 0
    mse = float(((a.astype(np.float64) - b.astype(np.float64)) ** 2).mean()) if n_changed else 0.0
    psnr = None if mse == 0 else round(10 * math.log10(255.0 ** 2 / mse), 2)
    res = {
        "width": a.shape[1], "height": a.shape[0], "changed_pixels": n_changed, "total_pixels": total,
        "changed_pct": round(100.0 * n_changed / total, 6), "max_channel_delta": max_abs,
        "psnr_db": psnr, "identical": n_changed == 0,
    }
    if diff_output:
        vis = a.copy()
        vis[changed_px] = (255, 0, 0)
        with AtomicWriter(diff_output, overwrite=overwrite) as fh:
            Image.fromarray(vis, "RGB").save(fh, format="PNG")
        res["diff_image"] = os.path.abspath(diff_output)
    return res
