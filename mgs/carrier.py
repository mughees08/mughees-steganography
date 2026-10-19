"""Carrier-file helpers: supported carrier types, payload trailer, guardrail.

Carrier mode appends an encrypted MGS3 container to the end of an ordinary
file (image, video, audio, PDF). Viewers ignore trailing bytes, so the carrier
still opens normally. A 16-byte trailer (payload length + marker) lets us find
the payload again in O(1), even for a 50 GB video.

Honest limits: this is *concealment by appending*, not statistical hiding.
Anyone who knows the format can see the trailer marker, and re-encoding,
re-uploading or "optimising" the carrier (social media, messengers, image
compressors) will strip the payload. The *content* is protected by AES-256-GCM
regardless.
"""

from __future__ import annotations

import os
import zipfile
from typing import Iterable, Optional

from .errors import GuardrailError, UsageError

FOOTER = b"MGSEND3!"
TRAILER_LEN = 16

SUPPORTED_CARRIERS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff",
    ".mp4", ".mov", ".avi", ".mkv", ".webm", ".m4v",
    ".mp3", ".wav", ".flac", ".ogg", ".m4a",
    ".pdf",
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".apk", ".xapk", ".aab", ".dex", ".com", ".scr", ".bat", ".cmd", ".msi", ".dll",
    ".so", ".dylib", ".sh", ".ps1", ".vbs", ".jar",
}

_EXEC_MAGICS = (
    b"MZ", b"\x7fELF", b"#!", b"dex\n",
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
)


def check_carrier(path: str) -> None:
    ext = os.path.splitext(path)[1].lower()
    if ext not in SUPPORTED_CARRIERS:
        raise UsageError(
            f"Unsupported carrier type {ext or '(none)'}. Supported: {', '.join(sorted(SUPPORTED_CARRIERS))}"
        )
    if not os.path.isfile(path):
        raise UsageError(f"Carrier not found: {path}")


def _bytes_look_executable(head: bytes) -> bool:
    return any(head.startswith(m) for m in _EXEC_MAGICS)


def looks_executable(path: Optional[str] = None, data: Optional[bytes] = None, name: str = "") -> bool:
    ext = os.path.splitext(path or name)[1].lower()
    if ext in EXECUTABLE_EXTENSIONS:
        return True
    if data is not None:
        return _bytes_look_executable(data[:8])
    if path is None:
        return False
    try:
        with open(path, "rb") as f:
            head = f.read(8)
        if _bytes_look_executable(head):
            return True
        if head.startswith(b"PK"):
            with zipfile.ZipFile(path) as z:
                names = set(z.namelist())
            if "AndroidManifest.xml" in names or "classes.dex" in names:
                return True
    except (OSError, zipfile.BadZipFile, RuntimeError):
        return False
    return False


def guard_no_executables(items: Iterable) -> None:
    """Refuse to *conceal* executables inside a carrier / image.

    Executables can still be stored in a clearly-labelled ``.mgsvault`` or
    ``.mgsbundle`` (see ``pack``), where nothing pretends to be a picture or video.
    """
    for it in items:
        if getattr(it, "kind", 1) != 1:
            continue
        if looks_executable(path=getattr(it, "path", None), data=getattr(it, "data", None),
                            name=getattr(it, "arcname", "")):
            raise GuardrailError(
                f"Refused: {getattr(it, 'arcname', 'file')!r} looks like an executable/APK. "
                "Programs are never concealed inside images, videos or documents. "
                "Store it openly with `vault-create` / `bundle-create` instead."
            )


def read_trailer(path: str):
    """Return ``(payload_offset, payload_length)`` if ``path`` ends with an MGS3 trailer."""
    size = os.path.getsize(path)
    if size < TRAILER_LEN:
        return None
    with open(path, "rb") as f:
        f.seek(-TRAILER_LEN, os.SEEK_END)
        t = f.read(TRAILER_LEN)
    if t[8:] != FOOTER:
        return None
    length = int.from_bytes(t[:8], "big")
    if length <= 0 or length > size - TRAILER_LEN:
        return None
    return size - TRAILER_LEN - length, length
