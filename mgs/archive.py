"""Multi-file archive stored *inside* an MGS3 container.

The archive is a plain stream (it is encrypted by ``crypto.EncryptWriter``)::

    b"MGSA" version(1) total_files(u64) total_bytes(u64)          # prologue
    entry*   : kind(1) name_len(u16) name mtime(i64) size(u64)
               [file only:  <size bytes of data>  sha256(32)]
    end      : 0xFF files(u64) bytes(u64)

Every file carries its own SHA-256, and the end record repeats the totals, so
a damaged or truncated archive is detected even before looking at GCM tags.
Paths are validated on read (no absolute paths, no ``..``, no symlinks), so a
hostile container cannot write outside the chosen output folder.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import struct
import time
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple

from .crypto import DecryptReader, EncryptWriter
from .errors import FormatError, IntegrityError, UsageError
from .util import (
    MiB, ProgressCB, check_free_space, ensure_no_symlink_between, safe_arcname, unique_path,
)

ARCH_MAGIC = b"MGSA"
ARCH_VERSION = 1
K_FILE, K_DIR, K_END = 1, 2, 0xFF
BLOCK = 4 * MiB


# --------------------------------------------------------------------------- #
# Source collection
# --------------------------------------------------------------------------- #

@dataclass
class Item:
    kind: int                      # K_FILE | K_DIR
    arcname: str
    path: Optional[str] = None     # for files read from disk
    data: Optional[bytes] = None   # for in-memory files
    size: int = 0
    mtime: int = 0


def _clean_component(name: str) -> str:
    return name.replace("\\", "_")


def collect_items(paths, extra=None) -> Tuple[List[Item], int, int]:
    """Expand files/directories into archive items.

    ``extra`` is an optional list of ``(arcname, bytes)`` in-memory files.
    Returns ``(items, total_files, total_bytes)``.
    """
    items: List[Item] = []
    seen = set()

    def add(item: Item):
        key = item.arcname
        if key in seen:
            raise UsageError(f"Two inputs would be stored under the same name: {key!r}")
        seen.add(key)
        items.append(item)

    for p in paths or []:
        p = os.path.expanduser(str(p))
        if os.path.islink(p):
            raise UsageError(f"Symbolic links are not supported as inputs: {p}")
        if os.path.isfile(p):
            st = os.stat(p)
            add(Item(K_FILE, _clean_component(os.path.basename(p)), path=p, size=st.st_size, mtime=int(st.st_mtime)))
        elif os.path.isdir(p):
            base = _clean_component(os.path.basename(os.path.abspath(p).rstrip(os.sep)) or "root")
            add(Item(K_DIR, base, mtime=int(os.stat(p).st_mtime)))
            for dirpath, dirnames, filenames in os.walk(p, followlinks=False):
                dirnames.sort()
                rel_dir = os.path.relpath(dirpath, p)
                prefix = base if rel_dir == "." else base + "/" + "/".join(
                    _clean_component(c) for c in rel_dir.split(os.sep))
                if rel_dir != ".":
                    add(Item(K_DIR, prefix, mtime=int(os.stat(dirpath).st_mtime)))
                for fn in sorted(filenames):
                    fp = os.path.join(dirpath, fn)
                    if os.path.islink(fp) or not os.path.isfile(fp):
                        continue  # skip symlinks, sockets, devices
                    st = os.stat(fp)
                    add(Item(K_FILE, prefix + "/" + _clean_component(fn), path=fp,
                             size=st.st_size, mtime=int(st.st_mtime)))
        else:
            raise UsageError(f"Input not found: {p}")
    for name, data in extra or []:
        add(Item(K_FILE, safe_arcname(name), data=bytes(data), size=len(data), mtime=int(time.time())))
    files = [i for i in items if i.kind == K_FILE]
    if not files:
        raise UsageError("Nothing to store: no files were found in the inputs.")
    return items, len(files), sum(i.size for i in files)


# --------------------------------------------------------------------------- #
# Writer
# --------------------------------------------------------------------------- #

def write_archive(w: EncryptWriter, items: List[Item], total_files: int, total_bytes: int,
                  progress: Optional[ProgressCB] = None) -> None:
    w.write(ARCH_MAGIC + bytes([ARCH_VERSION]) + struct.pack(">QQ", total_files, total_bytes))
    done = 0
    files = 0
    for it in items:
        nameb = it.arcname.encode("utf-8")
        if len(nameb) > 65535:
            raise UsageError(f"File name too long: {it.arcname[:60]}...")
        head = bytes([it.kind]) + struct.pack(">H", len(nameb)) + nameb + struct.pack(">qQ", it.mtime, it.size)
        w.write(head)
        if it.kind == K_DIR:
            continue
        h = hashlib.sha256()
        remaining = it.size
        if it.data is not None:
            w.write(it.data)
            h.update(it.data)
            done += len(it.data)
            remaining = 0
        else:
            with open(it.path, "rb", buffering=0) as f:
                while remaining:
                    blk = f.read(min(BLOCK, remaining))
                    if not blk:
                        raise IntegrityError(f"File shrank while being read: {it.path}")
                    w.write(blk)
                    h.update(blk)
                    remaining -= len(blk)
                    done += len(blk)
                    if progress:
                        progress(done, total_bytes)
        w.write(h.digest())
        files += 1
    w.write(bytes([K_END]) + struct.pack(">QQ", files, done))
    if progress:
        progress(done, total_bytes)


# --------------------------------------------------------------------------- #
# Reader
# --------------------------------------------------------------------------- #

@dataclass
class EntryInfo:
    kind: int
    name: str
    mtime: int
    size: int
    sha256: str = ""

    @property
    def is_file(self) -> bool:
        return self.kind == K_FILE


class ArchiveReader:
    def __init__(self, reader: DecryptReader):
        self.r = reader
        head = reader.read(len(ARCH_MAGIC) + 1 + 16)
        if len(head) != len(ARCH_MAGIC) + 17 or head[:4] != ARCH_MAGIC:
            raise FormatError("Container does not hold an MGS archive.")
        if head[4] != ARCH_VERSION:
            raise FormatError(f"Unsupported archive version {head[4]}.")
        self.total_files, self.total_bytes = struct.unpack(">QQ", head[5:])
        self._files = 0
        self._bytes = 0
        self.ended = False

    def entries(self) -> Iterator[Tuple[EntryInfo, Iterator[bytes]]]:
        """Yield ``(info, blocks)``. ``blocks`` must be consumed (or ignored:
        it is drained automatically) before moving to the next entry."""
        while True:
            kind = self.r.read_exact(1, "entry type")[0]
            if kind == K_END:
                files, nbytes = struct.unpack(">QQ", self.r.read_exact(16, "end record"))
                if files != self._files or nbytes != self._bytes or files != self.total_files \
                        or nbytes != self.total_bytes:
                    raise IntegrityError("Archive totals do not match (damaged or truncated).")
                self.r.finish()
                self.ended = True
                return
            if kind not in (K_FILE, K_DIR):
                raise IntegrityError("Archive is damaged (unknown entry type).")
            (nlen,) = struct.unpack(">H", self.r.read_exact(2, "name length"))
            name = safe_arcname(self.r.read_exact(nlen, "name").decode("utf-8", "strict"))
            mtime, size = struct.unpack(">qQ", self.r.read_exact(16, "entry header"))
            info = EntryInfo(kind, name, mtime, size)
            if kind == K_DIR:
                yield info, iter(())
                continue
            state = {"done": False}
            blocks = self._blocks(info, state)
            yield info, blocks
            if not state["done"]:        # caller ignored the data: drain & verify
                for _ in blocks:
                    pass

    def _blocks(self, info: EntryInfo, state) -> Iterator[bytes]:
        h = hashlib.sha256()
        remaining = info.size
        while remaining:
            blk = self.r.read(min(BLOCK, remaining))
            if not blk:
                raise IntegrityError("Archive ended unexpectedly inside a file.")
            h.update(blk)
            remaining -= len(blk)
            self._bytes += len(blk)
            yield blk
        stored = self.r.read_exact(32, "file checksum")
        if stored != h.digest():
            raise IntegrityError(f"Checksum mismatch for {info.name!r} (corrupted or tampered).")
        info.sha256 = stored.hex()
        self._files += 1
        state["done"] = True


# --------------------------------------------------------------------------- #
# High-level extract / verify / list / read-into-memory
# --------------------------------------------------------------------------- #

@dataclass
class Extracted:
    path: str
    name: str
    size: int
    sha256: str


def extract_archive(reader: DecryptReader, dest: str, *, overwrite: bool = False,
                    progress: Optional[ProgressCB] = None,
                    container_total: Optional[int] = None) -> List[Extracted]:
    """Extract to ``dest``. Files are staged and only moved into place once the
    *whole* container has been authenticated, so a bad archive never leaves
    partial output behind."""
    ar = ArchiveReader(reader)
    dest = os.path.abspath(dest)
    os.makedirs(dest, exist_ok=True)
    check_free_space(dest, ar.total_bytes)
    stage = os.path.join(dest, f".mgs-staging-{secrets.token_hex(4)}")
    os.makedirs(stage)
    staged: List[Tuple[str, EntryInfo]] = []
    dirs: List[EntryInfo] = []
    try:
        n = 0
        for info, blocks in ar.entries():
            if info.kind == K_DIR:
                dirs.append(info)
                continue
            part = os.path.join(stage, f"{n:08d}.part")
            n += 1
            with open(part, "wb", buffering=MiB) as out:
                for blk in blocks:
                    out.write(blk)
                    if progress:
                        progress(ar._bytes, ar.total_bytes)
            staged.append((part, info))
        results: List[Extracted] = []
        for d in dirs:
            target = os.path.join(dest, *d.name.split("/"))
            ensure_no_symlink_between(dest, target)
            os.makedirs(target, exist_ok=True)
        for part, info in staged:
            target = os.path.join(dest, *info.name.split("/"))
            ensure_no_symlink_between(dest, os.path.dirname(target))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if not overwrite:
                target = unique_path(target)
            os.replace(part, target)
            if info.mtime > 0:
                try:
                    os.utime(target, (info.mtime, info.mtime))
                except OSError:
                    pass
            results.append(Extracted(target, info.name, info.size, info.sha256))
        for d in dirs:
            target = os.path.join(dest, *d.name.split("/"))
            if d.mtime > 0 and os.path.isdir(target):
                try:
                    os.utime(target, (d.mtime, d.mtime))
                except OSError:
                    pass
        return results
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def scan_archive(reader: DecryptReader, progress: Optional[ProgressCB] = None) -> List[EntryInfo]:
    """Decrypt and checksum everything, writing nothing. Returns the entries."""
    ar = ArchiveReader(reader)
    out: List[EntryInfo] = []
    for info, blocks in ar.entries():
        for _ in blocks:
            if progress:
                progress(ar._bytes, ar.total_bytes)
        out.append(info)
    return out


def read_archive_to_memory(reader: DecryptReader, limit: int = 2 * 1024 * MiB):
    ar = ArchiveReader(reader)
    if ar.total_bytes > limit:
        raise UsageError("Hidden payload is unexpectedly large to load in memory.")
    result = []
    for info, blocks in ar.entries():
        if info.kind == K_DIR:
            continue
        result.append((info.name, b"".join(blocks)))
    return result
