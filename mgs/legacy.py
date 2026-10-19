"""Read-only support for files produced by Mughees Steganography v1.x (Fernet).

New files are always written in the streaming MGS3 format. These helpers just
make sure nothing you hid with v1.4 is stranded. Fernet needs the whole payload
in memory, so legacy files above ~2 GiB are refused with a clear message.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import shutil
import zipfile
from typing import List

from cryptography.fernet import Fernet, InvalidToken

from .errors import FormatError, IntegrityError, UsageError, WrongPasswordError
from .util import normalize_password, unique_path

LEGACY_VAULT_MAGIC = b"MGSVLT2!"
LEGACY_FILE_MAGIC = b"MGSFILE2"
LEGACY_FILE_FOOTER = b"MGSEND2!"
LEGACY_LSB_MAGIC = b"MGS2"
CHECKSUM_LEN = 32
_LIMIT = 2 * 1024 ** 3


def _key(password: str, salt: bytes) -> bytes:
    return base64.urlsafe_b64encode(hashlib.pbkdf2_hmac("sha256", normalize_password(password), salt, 390_000))


def decrypt_blob(data: bytes, password: str) -> bytes:
    """checksum(32) || salt(16) || fernet_token  ->  plaintext."""
    if len(data) < CHECKSUM_LEN + 17:
        raise IntegrityError("Legacy data is corrupted or truncated.")
    checksum, blob = data[:CHECKSUM_LEN], data[CHECKSUM_LEN:]
    if hashlib.sha256(blob).digest() != checksum:
        raise IntegrityError("Legacy data failed its integrity check (corrupted or truncated).")
    try:
        return Fernet(_key(password, blob[:16])).decrypt(blob[16:])
    except InvalidToken:
        raise WrongPasswordError("Wrong password.") from None


def is_legacy_vault(path: str) -> bool:
    with open(path, "rb") as f:
        return f.read(len(LEGACY_VAULT_MAGIC)) == LEGACY_VAULT_MAGIC


def legacy_carrier_payload(path: str):
    size = os.path.getsize(path)
    if size < 16:
        return None
    with open(path, "rb") as f:
        f.seek(-16, os.SEEK_END)
        t = f.read(16)
        n = int.from_bytes(t[:8], "big")
        if t[8:] != LEGACY_FILE_FOOTER or n > size - 16 or n <= 0:
            return None
        f.seek(size - 16 - n)
        return f.read(n)


def _check_size(path: str) -> None:
    if os.path.getsize(path) > _LIMIT:
        raise UsageError("Legacy v1.x files above 2 GiB cannot be opened (they must fit in memory). "
                         "Open them with v1.4, then re-pack with this version.")


def _parse_named(payload: bytes, magic: bytes):
    if not payload.startswith(magic):
        raise FormatError("Not a legacy Mughees file.")
    pos = len(magic)
    nlen = int.from_bytes(payload[pos:pos + 2], "big")
    pos += 2
    if not nlen or pos + nlen + CHECKSUM_LEN + 17 > len(payload):
        raise IntegrityError("Legacy file is damaged.")
    name = os.path.basename(payload[pos:pos + nlen].decode("utf-8", "replace")) or "restored_file"
    return name, payload[pos + nlen:]


def _write_out(dest: str, name: str, data: bytes, overwrite: bool) -> str:
    os.makedirs(dest, exist_ok=True)
    out = os.path.join(dest, name)
    if not overwrite:
        out = unique_path(out)
    with open(out, "wb") as f:
        f.write(data)
    return out


def open_legacy_vault(path: str, dest: str, password: str, overwrite: bool = False) -> List[str]:
    _check_size(path)
    with open(path, "rb") as f:
        data = f.read()
    name, rest = _parse_named(data, LEGACY_VAULT_MAGIC)
    raw = decrypt_blob(rest, password)
    # v1.4 bundles were a vault holding a .zip with image/ and files/ folders.
    if zipfile.is_zipfile(io.BytesIO(raw)) and name.startswith("mgs_bundle_"):
        out = []
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                parts = info.filename.replace("\\", "/").split("/")
                if len(parts) != 2 or parts[0] not in ("image", "files") or parts[1] in ("", ".", ".."):
                    raise FormatError("Legacy bundle contains an unexpected path.")
                out.append(_write_out(dest, os.path.basename(parts[1]), zf.read(info), overwrite))
        return out
    return [_write_out(dest, name, raw, overwrite)]


def open_legacy_carrier(path: str, dest: str, password: str, overwrite: bool = False) -> List[str]:
    _check_size(path)
    payload = legacy_carrier_payload(path)
    if payload is None:
        raise FormatError("No hidden file payload found.")
    name, rest = _parse_named(payload, LEGACY_FILE_MAGIC)
    return [_write_out(dest, name, decrypt_blob(rest, password), overwrite)]


def reveal_legacy_lsb(flat_lsb_reader, password: str) -> str:
    """``flat_lsb_reader(n_bytes, bit_offset)`` returns bytes read from sequential LSBs."""
    header = flat_lsb_reader(len(LEGACY_LSB_MAGIC) + 4, 0)
    if header[:4] != LEGACY_LSB_MAGIC:
        raise FormatError("No hidden message found in this image.")
    n = int.from_bytes(header[4:8], "big")
    enc = flat_lsb_reader(n, 8 * 8)
    return decrypt_blob(enc, password).decode("utf-8")
