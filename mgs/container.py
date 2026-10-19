"""High-level storage API: vaults, bundles and carrier files (any size).

    pack()      files/folders  ->  .mgsvault / .mgsbundle   or   carrier + payload
    unpack()    vault / bundle / carrier  ->  files
    verify()    decrypt + checksum everything, write nothing
    inspect()   header info (no password) and file list (with password)
"""

from __future__ import annotations

import io
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import legacy
from .archive import (
    K_DIR, ArchiveReader, collect_items, extract_archive, read_archive_to_memory,
    scan_archive, write_archive,
)
from .carrier import (
    FOOTER, TRAILER_LEN, check_carrier, guard_no_executables, read_trailer,
)
from .crypto import (
    DEFAULT_CHUNK_LOG2, DEFAULT_ITERATIONS, HEADER_LEN, MAGIC, DecryptReader, EncryptWriter,
    parse_header,
)
from .errors import FormatError, UsageError
from .util import (
    MiB, AtomicWriter, ProgressCB, assert_distinct, check_free_space, human_bytes,
)


@dataclass
class PackResult:
    output: str
    files: int
    bytes_in: int
    bytes_out: int
    seconds: float
    carrier: Optional[str] = None
    payload_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d = dict(self.__dict__)
        d["throughput_mb_s"] = round(self.bytes_in / MiB / self.seconds, 1) if self.seconds > 0 else None
        return d


@dataclass
class UnpackResult:
    outputs: List[str]
    files: int
    bytes_out: int
    seconds: float
    legacy: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = dict(self.__dict__)
        d["throughput_mb_s"] = round(self.bytes_out / MiB / self.seconds, 1) if self.seconds > 0 else None
        return d


@dataclass
class Located:
    kind: str       # vault | carrier | legacy-vault | legacy-carrier
    offset: int
    length: int


def locate(path: str) -> Located:
    """Work out what kind of Mughees file this is (and where the payload sits)."""
    if not os.path.isfile(path):
        raise UsageError(f"File not found: {path}")
    size = os.path.getsize(path)
    t = read_trailer(path)
    if t:
        return Located("carrier", t[0], t[1])
    with open(path, "rb") as f:
        head = f.read(8)
    if head[:4] == MAGIC:
        return Located("vault", 0, size)
    if head == legacy.LEGACY_VAULT_MAGIC:
        return Located("legacy-vault", 0, size)
    if legacy.legacy_carrier_payload(path) is not None:
        return Located("legacy-carrier", 0, size)
    raise FormatError("No Mughees vault, bundle or hidden payload found in this file.")


# --------------------------------------------------------------------------- #
# pack
# --------------------------------------------------------------------------- #

def pack(
    sources: Sequence[str],
    output: str,
    password: str,
    *,
    carrier: Optional[str] = None,
    extra: Optional[Sequence[Tuple[str, bytes]]] = None,
    overwrite: bool = False,
    iterations: int = DEFAULT_ITERATIONS,
    chunk_log2: int = DEFAULT_CHUNK_LOG2,
    progress: Optional[ProgressCB] = None,
) -> PackResult:
    """Encrypt files and folders of any size into one container.

    With ``carrier`` the encrypted payload is appended to a copy of that file
    (the original is never touched); otherwise ``output`` is a standalone
    vault/bundle.
    """
    t0 = time.time()
    items, nfiles, nbytes = collect_items(sources, extra)
    carrier_size = 0
    if carrier:
        check_carrier(carrier)
        if locate_or_none(carrier):
            raise UsageError("This carrier already contains a hidden payload; use a clean carrier.")
        guard_no_executables(items)
        assert_distinct(output, carrier, *[i.path for i in items if i.path])
        carrier_size = os.path.getsize(carrier)
    else:
        assert_distinct(output, *[i.path for i in items if i.path])
    overhead = (nbytes >> chunk_log2) * 24 + len(items) * 160 + 8192
    check_free_space(os.path.dirname(os.path.abspath(output)), carrier_size + nbytes + overhead)

    with AtomicWriter(output, overwrite=overwrite) as out:
        if carrier:
            with open(carrier, "rb") as src:
                shutil.copyfileobj(src, out, 4 * MiB)
        start = out.tell()
        w = EncryptWriter(out, password, iterations=iterations, chunk_log2=chunk_log2)
        write_archive(w, items, nfiles, nbytes, progress)
        w.close()
        payload = out.tell() - start
        if carrier:
            out.write(payload.to_bytes(8, "big") + FOOTER)
    return PackResult(
        output=os.path.abspath(output), files=nfiles, bytes_in=nbytes,
        bytes_out=os.path.getsize(output), seconds=time.time() - t0,
        carrier=os.path.abspath(carrier) if carrier else None, payload_bytes=payload,
    )


def hide_file(carrier: str, sources, output: str, password: str, **kw) -> PackResult:
    """Append an encrypted payload to a copy of ``carrier`` (see ``pack``)."""
    if isinstance(sources, (str, os.PathLike)):
        sources = [sources]
    return pack(sources, output, password, carrier=carrier, **kw)


def reveal_file(carrier: str, dest: str, password: str, **kw) -> UnpackResult:
    """Recover files hidden with ``hide_file`` (alias of ``unpack``)."""
    return unpack(carrier, dest, password, **kw)


def locate_or_none(path: str) -> Optional[Located]:
    try:
        return locate(path)
    except FormatError:
        return None


# --------------------------------------------------------------------------- #
# unpack / verify / inspect
# --------------------------------------------------------------------------- #

def _open_reader(path: str, password: str) -> Tuple[DecryptReader, Any, Located]:
    loc = locate(path)
    f = open(path, "rb", buffering=MiB)
    try:
        f.seek(loc.offset)
        return DecryptReader(f, password, length=loc.length), f, loc
    except BaseException:
        f.close()
        raise


def unpack(path: str, dest: str, password: str, *, overwrite: bool = False,
           progress: Optional[ProgressCB] = None) -> UnpackResult:
    t0 = time.time()
    loc = locate(path)
    if loc.kind == "legacy-vault":
        outs = legacy.open_legacy_vault(path, dest, password, overwrite)
        return UnpackResult(outs, len(outs), sum(os.path.getsize(o) for o in outs), time.time() - t0, True)
    if loc.kind == "legacy-carrier":
        outs = legacy.open_legacy_carrier(path, dest, password, overwrite)
        return UnpackResult(outs, len(outs), sum(os.path.getsize(o) for o in outs), time.time() - t0, True)
    reader, f, _ = _open_reader(path, password)
    try:
        res = extract_archive(reader, dest, overwrite=overwrite, progress=progress)
    finally:
        f.close()
    return UnpackResult([r.path for r in res], len(res), sum(r.size for r in res), time.time() - t0)


def verify(path: str, password: str, progress: Optional[ProgressCB] = None) -> Dict[str, Any]:
    """Decrypt and checksum everything without writing any output."""
    t0 = time.time()
    loc = locate(path)
    if loc.kind.startswith("legacy"):
        with open(path, "rb") as f:
            data = f.read()
        raw = legacy.decrypt_blob(
            legacy._parse_named(data if loc.kind == "legacy-vault" else legacy.legacy_carrier_payload(path),
                                legacy.LEGACY_VAULT_MAGIC if loc.kind == "legacy-vault" else legacy.LEGACY_FILE_MAGIC)[1],
            password)
        return {"ok": True, "kind": loc.kind, "files": 1, "bytes": len(raw), "seconds": time.time() - t0}
    reader, f, _ = _open_reader(path, password)
    try:
        entries = scan_archive(reader, progress)
    finally:
        f.close()
    files = [e for e in entries if e.is_file]
    return {"ok": True, "kind": loc.kind, "files": len(files), "bytes": sum(e.size for e in files),
            "seconds": time.time() - t0}


def inspect(path: str, password: Optional[str] = None) -> Dict[str, Any]:
    loc = locate(path)
    info: Dict[str, Any] = {
        "path": os.path.abspath(path), "kind": loc.kind, "file_bytes": os.path.getsize(path),
        "payload_offset": loc.offset, "payload_bytes": loc.length,
    }
    if loc.kind.startswith("legacy"):
        info["format"] = "Mughees v1.x (Fernet) - legacy, read-only"
        return info
    with open(path, "rb") as f:
        f.seek(loc.offset)
        h = parse_header(f.read(HEADER_LEN))
    info.update({
        "format": f"MGS3 v{h.version}", "cipher": "AES-256-GCM (chunked)",
        "kdf": f"PBKDF2-HMAC-SHA256 x {h.iterations:,}", "kdf_iterations": h.iterations,
        "chunk_bytes": h.chunk_size,
    })
    if password:
        reader, f, _ = _open_reader(path, password)
        try:
            entries = scan_archive(reader)
        finally:
            f.close()
        info["entries"] = [
            {"name": e.name, "type": "dir" if e.kind == K_DIR else "file", "bytes": e.size,
             "sha256": e.sha256 or None, "mtime": e.mtime}
            for e in entries
        ]
        info["files"] = sum(1 for e in entries if e.is_file)
        info["bytes"] = sum(e.size for e in entries if e.is_file)
    return info


# --------------------------------------------------------------------------- #
# in-memory containers (used by the LSB engine for small payloads)
# --------------------------------------------------------------------------- #

def pack_bytes(entries: Sequence[Tuple[str, bytes]], password: str, *,
               iterations: int = DEFAULT_ITERATIONS) -> bytes:
    items, nfiles, nbytes = collect_items([], entries)
    buf = io.BytesIO()
    w = EncryptWriter(buf, password, iterations=iterations, chunk_log2=16)
    write_archive(w, items, nfiles, nbytes)
    w.close()
    return buf.getvalue()


def unpack_bytes(blob: bytes, password: str, limit: int = 2048 * MiB) -> List[Tuple[str, bytes]]:
    r = DecryptReader(io.BytesIO(blob), password, length=len(blob))
    return read_archive_to_memory(r, limit)
