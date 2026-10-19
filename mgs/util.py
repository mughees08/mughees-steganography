"""Small shared helpers: formatting, atomic output, path safety, passwords."""

from __future__ import annotations

import getpass
import hashlib
import os
import re
import secrets
import shutil
import sys
import unicodedata
from typing import Callable, Optional

from .errors import CapacityError, FormatError, MGSError, UsageError

ProgressCB = Callable[[int, int], None]

MiB = 1 << 20
GiB = 1 << 30


# --------------------------------------------------------------------------- #
# Formatting
# --------------------------------------------------------------------------- #

def human_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} TB"


def human_time(seconds: float) -> str:
    seconds = max(0, int(round(seconds)))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


def parse_size(text: str) -> int:
    """Parse '10GB', '512M', '4096' into bytes (binary units)."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgt]?)i?b?\s*", str(text).lower())
    if not m:
        raise UsageError(f"Invalid size: {text!r} (examples: 512MB, 10GB)")
    mult = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}[m.group(2)]
    return int(float(m.group(1)) * mult)


# --------------------------------------------------------------------------- #
# Filesystem safety
# --------------------------------------------------------------------------- #

def same_file(a: str, b: str) -> bool:
    return os.path.realpath(a) == os.path.realpath(b)


def assert_distinct(output: str, *inputs: str) -> None:
    for item in inputs:
        if item and same_file(output, item):
            raise UsageError(f"Output must be a different file than the input: {output}")


def check_free_space(directory: str, needed: int, margin: int = 32 * MiB) -> None:
    d = os.path.abspath(directory)
    while not os.path.isdir(d):
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    free = shutil.disk_usage(d).free
    if needed + margin > free:
        raise CapacityError(
            f"Not enough free disk space in {d}: need about {human_bytes(needed + margin)}, "
            f"only {human_bytes(free)} available."
        )


def unique_path(path: str) -> str:
    if not os.path.lexists(path):
        return path
    stem, ext = os.path.splitext(path)
    n = 1
    while os.path.lexists(f"{stem}_{n}{ext}"):
        n += 1
    return f"{stem}_{n}{ext}"


class AtomicWriter:
    """Write to ``<path>.<rand>.part`` and rename on success, delete on failure.

    A crash, wrong password or Ctrl+C therefore never leaves a half-written
    file under the real name.
    """

    def __init__(self, path: str, overwrite: bool = False):
        self.path = os.path.abspath(path)
        if os.path.lexists(self.path) and not overwrite:
            raise UsageError(f"{path} already exists (use --force to overwrite).")
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.tmp = f"{self.path}.{secrets.token_hex(4)}.part"
        self.f = open(self.tmp, "wb", buffering=MiB)

    def __enter__(self):
        return self.f

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self.f.flush()
                self.f.close()
                os.replace(self.tmp, self.path)
            else:
                self.f.close()
                _silent_remove(self.tmp)
        except BaseException:
            _silent_remove(self.tmp)
            raise
        return False


def _silent_remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def safe_arcname(name: str) -> str:
    """Validate a path stored inside a container; return a clean 'a/b/c' form."""
    if not name or "\x00" in name:
        raise FormatError("Container holds an invalid (empty) file name.")
    n = name.replace("\\", "/")
    if n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        raise FormatError(f"Container holds an absolute path ({name!r}); refusing to extract.")
    out = []
    for part in n.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise FormatError(f"Container holds an unsafe path ({name!r}); refusing to extract.")
        out.append(part)
    if not out or len("/".join(out)) > 4000:
        raise FormatError("Container holds an invalid file name.")
    return "/".join(out)


def ensure_no_symlink_between(root: str, target: str) -> None:
    """Refuse to write through a symlink located below ``root``."""
    root = os.path.abspath(root)
    cur = os.path.abspath(target)
    while cur != root and len(cur) > len(root):
        if os.path.islink(cur):
            raise UsageError(f"Refusing to write through a symlink: {cur}")
        nxt = os.path.dirname(cur)
        if nxt == cur:
            break
        cur = nxt


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #

def normalize_password(password: str) -> bytes:
    if not isinstance(password, str) or password == "":
        raise UsageError("Password cannot be empty.")
    return unicodedata.normalize("NFC", password).encode("utf-8")


def read_password(
    password: Optional[str] = None,
    env: Optional[str] = None,
    file: Optional[str] = None,
    prompt: str = "Password: ",
    confirm: bool = False,
) -> str:
    """Resolve a password from (in order) value, env var, file, interactive prompt."""
    if password:
        return password
    if env:
        value = os.environ.get(env)
        if not value:
            raise UsageError(f"Environment variable {env} is not set or empty.")
        return value
    if file:
        try:
            with open(file, "r", encoding="utf-8") as fh:
                value = fh.read().rstrip("\r\n")
        except OSError as exc:
            raise UsageError(f"Cannot read password file: {exc}") from exc
        if not value:
            raise UsageError("Password file is empty.")
        return value
    if os.environ.get("MGS_PASSWORD"):
        return os.environ["MGS_PASSWORD"]
    if not sys.stdin.isatty():
        raise UsageError(
            "No password supplied. Use --password-env, --password-file or the MGS_PASSWORD "
            "environment variable when running non-interactively."
        )
    pw = getpass.getpass(prompt)
    if confirm:
        if pw != getpass.getpass("Confirm password: "):
            raise UsageError("Passwords do not match.")
    if not pw:
        raise UsageError("Password cannot be empty.")
    return pw


def sha256_file(path: str, progress: Optional[ProgressCB] = None) -> str:
    h = hashlib.sha256()
    total = os.path.getsize(path)
    done = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(4 * MiB)
            if not b:
                break
            h.update(b)
            done += len(b)
            if progress:
                progress(done, total)
    return h.hexdigest()


def wrap_oserror(exc: OSError) -> MGSError:
    return MGSError(f"{exc.strerror or exc}: {getattr(exc, 'filename', '') or ''}".strip(": "))
