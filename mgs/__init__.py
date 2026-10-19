"""Mughees Steganography - public SDK.

    import mgs
    mgs.pack(["movie.mkv"], "secret.mgsvault", "password")
    mgs.unpack("secret.mgsvault", "restored/", "password")

See docs/SDK.md. The CLI is ``mgs`` (or ``python stego.py``), the REST API is
``mgs serve`` and its Python client is ``mgs.client.MGSClient``.
"""

__version__ = "2.0.0"
__author__ = "Muhammad Mughees Abbasi"

from .container import (  # noqa: E402
    PackResult, UnpackResult, hide_file, inspect, locate, pack, pack_bytes, reveal_file, unpack,
    unpack_bytes, verify,
)
from .errors import (  # noqa: E402
    Cancelled, CapacityError, FormatError, GuardrailError, IntegrityError, MGSError, UsageError,
    WrongPasswordError,
)

__all__ = [
    "__version__", "pack", "unpack", "hide_file", "reveal_file", "verify", "inspect", "locate", "pack_bytes", "unpack_bytes",
    "PackResult", "UnpackResult",
    "MGSError", "UsageError", "WrongPasswordError", "IntegrityError", "FormatError",
    "CapacityError", "GuardrailError", "Cancelled",
]


def __getattr__(name):
    # Lazy: numpy/Pillow are only imported when the image engine is used.
    if name in ("lsb_hide", "lsb_reveal", "lsb_capacity", "compare_images"):
        from . import lsb
        return {"lsb_hide": lsb.hide, "lsb_reveal": lsb.reveal, "lsb_capacity": lsb.capacity,
                "compare_images": lsb.compare_images}[name]
    raise AttributeError(name)
