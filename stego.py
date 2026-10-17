#!/usr/bin/env python3
"""
Mughees Steganography - Password-protected text steganography in images (LSB method)

Developer: Muhammad Mughees Abbasi
License: MIT

Hides a UTF-8 text message inside the least-significant bits of a PNG
image's pixel data. The message is encrypted with a password before
embedding, so even if someone suspects a hidden message, they cannot
read it without the password.

Version 1.4. Executable files such as APKs are not embedded inside
ordinary-looking images. They can instead be stored in clearly labeled
password-protected vaults (.mgsvault) or bundles (.mgsbundle) alongside an
image, and later recovered with the matching password.

What's new in 1.4:
  - `capacity` command: check how large a message an image can hold
    before you try to hide one.
  - Every hidden/stored payload now carries a SHA-256 integrity
    checksum, so a corrupted or truncated payload is reported clearly
    instead of being confused with a wrong password.
  - Colored, verbose/quiet-aware CLI output (-v/--verbose, -q/--quiet).

Note: the 1.4 payload format (integrity-checked) is not compatible with
files hidden/stored using 1.3 or earlier. Re-hide them with this version.
"""

import argparse
import base64
import getpass
import hashlib
import os
import secrets
import sys
import shutil
import tempfile
import zipfile

from cryptography.fernet import Fernet, InvalidToken
from PIL import Image

MAGIC_HEADER = b"MGS2"          # 4-byte format marker ("Mughees Steganography v2 format")
LENGTH_BITS = 32                # bits used to store payload length
DELIM_BITS_PER_BYTE = 8
CHECKSUM_LEN = 32               # SHA-256 digest size, used as an integrity check


# --------------------------------------------------------------------------- #
# Console output helpers (colored, verbose/quiet aware)
# --------------------------------------------------------------------------- #

_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


class _C:
    RESET = "\033[0m" if _COLOR else ""
    BOLD = "\033[1m" if _COLOR else ""
    GREEN = "\033[92m" if _COLOR else ""
    RED = "\033[91m" if _COLOR else ""
    YELLOW = "\033[93m" if _COLOR else ""
    CYAN = "\033[96m" if _COLOR else ""
    GRAY = "\033[90m" if _COLOR else ""


QUIET = False
VERBOSE = False


def set_output_mode(verbose: bool, quiet: bool):
    global QUIET, VERBOSE
    QUIET = bool(quiet)
    VERBOSE = bool(verbose) and not QUIET


def ok(msg: str):
    print(f"{_C.GREEN}[+]{_C.RESET} {msg}")


def err(msg: str):
    print(f"{_C.RED}[-]{_C.RESET} {msg}", file=sys.stderr)


def info(msg: str):
    if not QUIET:
        print(f"{_C.CYAN}[*]{_C.RESET} {msg}")


def warn(msg: str):
    print(f"{_C.YELLOW}[!]{_C.RESET} {msg}")


def debug(msg: str):
    if VERBOSE:
        print(f"{_C.GRAY}[v]{_C.RESET} {msg}")


# --------------------------------------------------------------------------- #
# Crypto helpers
# --------------------------------------------------------------------------- #

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password + salt using PBKDF2."""
    kdf = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 390_000)
    return base64.urlsafe_b64encode(kdf)


def encrypt_message(message: str, password: str) -> bytes:
    """Encrypt a message and prefix it with a SHA-256 integrity checksum."""
    salt = secrets.token_bytes(16)
    key = _derive_key(password, salt)
    token = Fernet(key).encrypt(message.encode("utf-8"))
    blob = salt + token
    checksum = hashlib.sha256(blob).digest()
    return checksum + blob


def decrypt_message(data: bytes, password: str) -> str:
    if len(data) < CHECKSUM_LEN + 16:
        raise ValueError("Hidden data is corrupted or truncated.")
    checksum, blob = data[:CHECKSUM_LEN], data[CHECKSUM_LEN:]
    if hashlib.sha256(blob).digest() != checksum:
        raise ValueError("Hidden data failed its integrity check (corrupted or truncated).")
    salt, token = blob[:16], blob[16:]
    key = _derive_key(password, salt)
    try:
        return Fernet(key).decrypt(token).decode("utf-8")
    except InvalidToken:
        raise ValueError("Wrong password.")


# --------------------------------------------------------------------------- #
# Bit-level helpers
# --------------------------------------------------------------------------- #

def _bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def _bits_to_bytes(bits):
    data = bytearray()
    cur = 0
    count = 0
    for bit in bits:
        cur = (cur << 1) | bit
        count += 1
        if count == 8:
            data.append(cur)
            cur = 0
            count = 0
    return bytes(data)


# --------------------------------------------------------------------------- #
# Core hide / reveal
# --------------------------------------------------------------------------- #

def hide_message(input_path: str, output_path: str, message: str, password: str):
    img = Image.open(input_path)
    img = img.convert("RGB")
    pixels = bytearray(img.tobytes())

    encrypted = encrypt_message(message, password)
    payload = MAGIC_HEADER + len(encrypted).to_bytes(4, "big") + encrypted

    capacity_bits = len(pixels)  # 1 bit per color channel byte
    needed_bits = len(payload) * 8
    debug(f"Payload size: {len(payload)} bytes ({needed_bits} bits); image capacity: {capacity_bits} bits")
    if needed_bits > capacity_bits:
        raise ValueError(
            f"Message too large for this image. "
            f"Need {needed_bits} bits, image can hold {capacity_bits} bits."
        )

    bit_gen = _bytes_to_bits(payload)
    for i, bit in enumerate(bit_gen):
        pixels[i] = (pixels[i] & 0xFE) | bit

    out_img = Image.frombytes("RGB", img.size, bytes(pixels))
    out_img.save(output_path, format="PNG")


def reveal_message(stego_path: str, password: str) -> str:
    img = Image.open(stego_path).convert("RGB")
    pixels = img.tobytes()

    header_len_bytes = len(MAGIC_HEADER) + 4
    header_bits_needed = header_len_bytes * 8

    header_bits = (pixels[i] & 1 for i in range(header_bits_needed))
    header = _bits_to_bytes(header_bits)

    magic, length_bytes = header[: len(MAGIC_HEADER)], header[len(MAGIC_HEADER):]
    if magic != MAGIC_HEADER:
        raise ValueError("No hidden message found in this image.")

    payload_len = int.from_bytes(length_bytes, "big")
    total_bits_needed = header_bits_needed + payload_len * 8
    if total_bits_needed > len(pixels):
        raise ValueError("Image data is corrupted or truncated.")

    payload_bits = (pixels[i] & 1 for i in range(header_bits_needed, total_bits_needed))
    encrypted = _bits_to_bytes(payload_bits)

    return decrypt_message(encrypted, password)


# --------------------------------------------------------------------------- #
# Capacity check
# --------------------------------------------------------------------------- #

def compute_capacity(image_path: str):
    """Return (width, height), total bit-capacity in bytes, per-message
    overhead in bytes, and usable bytes for a hidden text message."""
    img = Image.open(image_path).convert("RGB")
    capacity_bits = len(img.tobytes())
    capacity_bytes = capacity_bits // 8
    probe = encrypt_message("", "capacity-probe")  # measures real crypto overhead
    overhead = len(MAGIC_HEADER) + 4 + len(probe)
    usable_bytes = max(capacity_bytes - overhead, 0)
    return img.size, capacity_bytes, overhead, usable_bytes


def cmd_capacity(args):
    try:
        size, capacity_bytes, overhead, usable = compute_capacity(args.image)
    except (OSError, ValueError) as e:
        err(str(e))
        sys.exit(1)
    ok(f"Image: {args.image} ({size[0]}x{size[1]}, {capacity_bytes} bytes raw capacity)")
    info(f"Format overhead per hidden message: ~{overhead} bytes (encryption + headers + checksum)")
    ok(f"Usable space for a hidden text message: ~{usable} bytes")
    print(f"  (~{usable} ASCII characters; fewer for multi-byte UTF-8 text, e.g. Urdu or emoji)")


# --------------------------------------------------------------------------- #
# Compare
# --------------------------------------------------------------------------- #

def compare_images(path_a: str, path_b: str, diff_output: str = None):
    img_a = Image.open(path_a).convert("RGB")
    img_b = Image.open(path_b).convert("RGB")

    if img_a.size != img_b.size:
        warn(f"Images differ in size: {img_a.size} vs {img_b.size}")
        return

    pixels_a = img_a.load()
    pixels_b = img_b.load()
    width, height = img_a.size

    diff_img = Image.new("RGB", (width, height))
    diff_pixels = diff_img.load()
    changed = 0

    for y in range(height):
        for x in range(width):
            pa, pb = pixels_a[x, y], pixels_b[x, y]
            if pa != pb:
                changed += 1
                diff_pixels[x, y] = (255, 0, 0)   # highlight changed pixel in red
            else:
                diff_pixels[x, y] = pa

    total = width * height
    ok(f"Changed pixels: {changed} / {total} ({changed / total * 100:.4f}%)")

    if diff_output:
        diff_img.save(diff_output, format="PNG")
        info(f"Diff image saved to: {diff_output}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _get_password(confirm: bool = False) -> str:
    pw = getpass.getpass("Password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            err("Passwords do not match.")
            sys.exit(1)
    if not pw:
        err("Password cannot be empty.")
        sys.exit(1)
    return pw


def cmd_hide(args):
    message = args.message
    if message is None:
        info("Enter the message to hide (end with Ctrl+D):")
        message = sys.stdin.read().rstrip("\n")

    password = args.password or _get_password(confirm=True)
    output = args.output or _default_output_name(args.image)

    debug(f"Message length: {len(message.encode('utf-8'))} bytes (before encryption)")
    try:
        hide_message(args.image, output, message, password)
    except (ValueError, OSError) as e:
        err(str(e))
        sys.exit(1)
    ok("Hidden message embedded.")
    info(f"Original image (unchanged): {args.image}")
    ok(f"New image with hidden message: {output}")


def cmd_reveal(args):
    password = args.password or getpass.getpass("Password: ")
    try:
        message = reveal_message(args.image, password)
    except ValueError as e:
        err(str(e))
        sys.exit(1)
    ok("Hidden message found:")
    print(message)


def cmd_compare(args):
    compare_images(args.image_a, args.image_b, args.diff_output)


def _default_output_name(input_path: str) -> str:
    base, ext = os.path.splitext(input_path)
    return f"{base}_hidden.png"


# --------------------------------------------------------------------------- #
# Encrypted file-in-carrier mode (non-executable payloads only)
# --------------------------------------------------------------------------- #

FILE_MAGIC = b"MGSFILE2"
FILE_FOOTER = b"MGSEND2!"
EXECUTABLE_EXTENSIONS = {".exe", ".apk", ".com", ".scr", ".bat", ".cmd", ".msi", ".dll", ".so", ".sh", ".ps1"}
SUPPORTED_CARRIERS = {".png", ".jpg", ".jpeg", ".mp4", ".mov", ".avi", ".mkv", ".pdf"}


def hide_file(carrier_path: str, secret_path: str, output_path: str, password: str):
    """Append an encrypted, recoverable non-executable file payload to a carrier copy."""
    secret_ext = os.path.splitext(secret_path)[1].lower()
    if secret_ext in EXECUTABLE_EXTENSIONS:
        raise ValueError("For safety, EXE/APK/scripts cannot be concealed as payloads. Use a clearly named encrypted archive instead.")
    carrier_ext = os.path.splitext(carrier_path)[1].lower()
    if carrier_ext not in SUPPORTED_CARRIERS:
        raise ValueError(f"Unsupported carrier type: {carrier_ext}. Supported: {', '.join(sorted(SUPPORTED_CARRIERS))}")
    if os.path.abspath(carrier_path) == os.path.abspath(output_path):
        raise ValueError("Output must be a new file; the original carrier will not be overwritten.")
    with open(secret_path, "rb") as f:
        raw = f.read()
    if not raw:
        raise ValueError("The file to hide is empty.")
    debug(f"Secret file size: {len(raw)} bytes")
    salt = secrets.token_bytes(16)
    key = _derive_key(password, salt)
    blob = salt + Fernet(key).encrypt(raw)
    checksum = hashlib.sha256(blob).digest()
    name = os.path.basename(secret_path).encode("utf-8")
    if len(name) > 4096:
        raise ValueError("Filename is too long.")
    # Format: marker + filename length + filename + checksum + encrypted data + payload length + footer
    payload = FILE_MAGIC + len(name).to_bytes(2, "big") + name + checksum + blob
    with open(carrier_path, "rb") as src, open(output_path, "wb") as dst:
        shutil.copyfileobj(src, dst)
        dst.write(payload)
        dst.write(len(payload).to_bytes(8, "big"))
        dst.write(FILE_FOOTER)


def reveal_file(stego_path: str, output_dir: str, password: str):
    """Recover and decrypt an appended file payload."""
    with open(stego_path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size < 16:
            raise ValueError("No hidden file payload found.")
        f.seek(-16, os.SEEK_END)
        trailer = f.read(16)
        payload_len = int.from_bytes(trailer[:8], "big")
        if trailer[8:] != FILE_FOOTER or payload_len > size - 16:
            raise ValueError("No hidden file payload found.")
        f.seek(size - 16 - payload_len)
        payload = f.read(payload_len)
    if not payload.startswith(FILE_MAGIC) or len(payload) < len(FILE_MAGIC) + 2:
        raise ValueError("No hidden file payload found.")
    pos = len(FILE_MAGIC)
    name_len = int.from_bytes(payload[pos:pos + 2], "big")
    pos += 2
    if name_len == 0 or pos + name_len + CHECKSUM_LEN >= len(payload):
        raise ValueError("Hidden payload is corrupted.")
    name = os.path.basename(payload[pos:pos + name_len].decode("utf-8", "replace"))
    pos += name_len
    checksum = payload[pos:pos + CHECKSUM_LEN]
    pos += CHECKSUM_LEN
    blob = payload[pos:]
    if len(blob) < 17:
        raise ValueError("Hidden payload is corrupted.")
    if hashlib.sha256(blob).digest() != checksum:
        raise ValueError("Hidden file failed its integrity check (corrupted or truncated).")
    salt, token = blob[:16], blob[16:]
    key = _derive_key(password, salt)
    try:
        raw = Fernet(key).decrypt(token)
    except InvalidToken:
        raise ValueError("Wrong password.")
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, name or "recovered_file")
    # Avoid overwriting an existing file.
    root, ext = os.path.splitext(out_path)
    i = 1
    while os.path.exists(out_path):
        out_path = f"{root}_{i}{ext}"
        i += 1
    with open(out_path, "wb") as f:
        f.write(raw)
    debug(f"Recovered file size: {len(raw)} bytes")
    return out_path


def cmd_hide_file(args):
    password = args.password or _get_password(confirm=True)
    output = args.output or _default_file_output(args.carrier)
    try:
        hide_file(args.carrier, args.file, output, password)
    except (ValueError, OSError) as e:
        err(str(e))
        sys.exit(1)
    ok("Encrypted file payload added to a new carrier copy.")
    info(f"Original carrier (unchanged): {args.carrier}")
    ok(f"Output: {output}")


def cmd_reveal_file(args):
    password = args.password or getpass.getpass("Password: ")
    try:
        recovered = reveal_file(args.carrier, args.output_dir, password)
    except ValueError as e:
        err(str(e))
        sys.exit(1)
    ok(f"Recovered file: {recovered}")


def _default_file_output(path: str) -> str:
    base, ext = os.path.splitext(path)
    return f"{base}_with_secret{ext}"


# --------------------------------------------------------------------------- #
# Encrypted file vault (including APK/EXE as ordinary encrypted files)
# --------------------------------------------------------------------------- #

VAULT_MAGIC = b"MGSVLT2!"


def create_vault(input_path: str, output_path: str, password: str):
    """Encrypt any file into a clearly identified .mgsvault container."""
    if not password:
        raise ValueError("Password cannot be empty.")
    if os.path.abspath(input_path) == os.path.abspath(output_path):
        raise ValueError("Vault output must be a different file.")
    with open(input_path, "rb") as f:
        raw = f.read()
    if not raw:
        raise ValueError("Input file is empty.")
    debug(f"Input file size: {len(raw)} bytes")
    filename = os.path.basename(input_path).encode("utf-8")
    if len(filename) > 4096:
        raise ValueError("Filename is too long.")
    salt = secrets.token_bytes(16)
    key = _derive_key(password, salt)
    token = Fernet(key).encrypt(raw)
    blob = salt + token
    checksum = hashlib.sha256(blob).digest()
    payload = VAULT_MAGIC + len(filename).to_bytes(2, "big") + filename + checksum + blob
    with open(output_path, "wb") as f:
        f.write(payload)
    return output_path


def open_vault(vault_path: str, output_dir: str, password: str):
    """Decrypt a .mgsvault container and safely restore its original filename."""
    with open(vault_path, "rb") as f:
        data = f.read()
    if not data.startswith(VAULT_MAGIC) or len(data) < len(VAULT_MAGIC) + 2 + CHECKSUM_LEN + 16 + 1:
        raise ValueError("This is not a valid Mughees vault.")
    pos = len(VAULT_MAGIC)
    name_len = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    if not name_len or pos + name_len + CHECKSUM_LEN + 16 >= len(data):
        raise ValueError("Vault is damaged.")
    name = os.path.basename(data[pos:pos + name_len].decode("utf-8", "replace"))
    pos += name_len
    checksum = data[pos:pos + CHECKSUM_LEN]
    pos += CHECKSUM_LEN
    blob = data[pos:]
    if hashlib.sha256(blob).digest() != checksum:
        raise ValueError("Vault failed its integrity check (corrupted or truncated).")
    salt, token = blob[:16], blob[16:]
    try:
        raw = Fernet(_derive_key(password, salt)).decrypt(token)
    except InvalidToken:
        raise ValueError("Wrong password.")
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, name or "restored_file")
    stem, ext = os.path.splitext(out_path)
    n = 1
    while os.path.exists(out_path):
        out_path = f"{stem}_{n}{ext}"
        n += 1
    with open(out_path, "wb") as f:
        f.write(raw)
    debug(f"Restored file size: {len(raw)} bytes")
    return out_path


def cmd_vault_create(args):
    password = args.password or _get_password(confirm=True)
    output = args.output or (args.file + ".mgsvault")
    try:
        create_vault(args.file, output, password)
    except (ValueError, OSError) as e:
        err(str(e))
        sys.exit(1)
    ok(f"Encrypted vault created: {output}")
    info("The original file was not changed. This is a clearly labeled encrypted container, not an image disguise.")


def cmd_vault_open(args):
    password = args.password or getpass.getpass("Vault password: ")
    try:
        restored = open_vault(args.vault, args.output_dir, password)
    except ValueError as e:
        err(str(e))
        sys.exit(1)
    ok(f"File restored: {restored}")


def create_bundle(image_path: str, file_path: str, output_path: str, password: str):
    """Package an image and a file into a clearly labeled encrypted bundle."""
    if not os.path.isfile(image_path) or not os.path.isfile(file_path):
        raise ValueError("Both the image and the file must exist.")
    if os.path.abspath(output_path) in (os.path.abspath(image_path), os.path.abspath(file_path)):
        raise ValueError("Bundle output must be a different file.")
    out_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(out_dir, exist_ok=True)
    fd, archive_path = tempfile.mkstemp(suffix=".zip", prefix="mgs_bundle_")
    os.close(fd)
    try:
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(image_path, arcname="image/" + os.path.basename(image_path))
            zf.write(file_path, arcname="files/" + os.path.basename(file_path))
        create_vault(archive_path, output_path, password)
    finally:
        try:
            os.remove(archive_path)
        except OSError:
            pass
    return output_path


def open_bundle(bundle_path: str, output_dir: str, password: str):
    """Decrypt a bundle and restore its image and file without extracting unsafe paths."""
    os.makedirs(output_dir, exist_ok=True)
    temp_dir = tempfile.mkdtemp(prefix="mgs_bundle_open_")
    try:
        archive_path = open_vault(bundle_path, temp_dir, password)
        restored = []
        with zipfile.ZipFile(archive_path, "r") as zf:
            for info_ in zf.infolist():
                if info_.is_dir():
                    continue
                # Accept only the two expected, flat bundle folders and plain filenames.
                parts = info_.filename.replace("\\", "/").split("/")
                if len(parts) != 2 or parts[0] not in ("image", "files") or parts[1] in ("", ".", ".."):
                    raise ValueError("Bundle contains an unexpected path.")
                name = os.path.basename(parts[1])
                if name != parts[1]:
                    raise ValueError("Bundle contains an unsafe filename.")
                destination = os.path.join(output_dir, name)
                stem, ext = os.path.splitext(destination)
                n = 1
                while os.path.exists(destination):
                    destination = f"{stem}_{n}{ext}"
                    n += 1
                with zf.open(info_, "r") as src, open(destination, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                restored.append(destination)
        if not restored:
            raise ValueError("Bundle is empty or invalid.")
        return restored
    except zipfile.BadZipFile as exc:
        raise ValueError("Bundle contents are damaged or invalid.") from exc
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def cmd_bundle_create(args):
    password = args.password or _get_password(confirm=True)
    output = args.output or (os.path.splitext(args.file)[0] + ".mgsbundle")
    try:
        create_bundle(args.image, args.file, output, password)
    except (ValueError, OSError) as e:
        err(str(e))
        sys.exit(1)
    ok(f"Encrypted bundle created: {output}")
    info("Contains the image and file in a clearly labeled encrypted container; it is not disguised as an image.")


def cmd_bundle_open(args):
    password = args.password or getpass.getpass("Bundle password: ")
    try:
        restored = open_bundle(args.bundle, args.output_dir, password)
    except ValueError as e:
        err(str(e))
        sys.exit(1)
    ok("Restored files:")
    for path in restored:
        print(f"  {path}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="mughees-stego",
        description="Mughees Steganography - password-protected text steganography and encrypted file storage.",
    )
    parser.add_argument("--version", action="version", version="Mughees Steganography 1.4 by Muhammad Mughees Abbasi")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Show extra details (payload sizes, capacity usage). Place before the subcommand.")
    parser.add_argument("-q", "--quiet", action="store_true",
                         help="Only show the final result and errors. Place before the subcommand.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_hide = sub.add_parser("hide", help="Hide a text message inside an image")
    p_hide.add_argument("image", help="Path to the cover image (e.g. photo.png)")
    p_hide.add_argument("-m", "--message", help="Message to hide (omit to type/paste it)")
    p_hide.add_argument("-p", "--password", help="Password (omit to be prompted securely)")
    p_hide.add_argument("-o", "--output", help="Output image path (default: <name>_hidden.png)")
    p_hide.set_defaults(func=cmd_hide)

    p_reveal = sub.add_parser("reveal", help="Reveal a hidden text message from an image")
    p_reveal.add_argument("image", help="Path to the image containing a hidden message")
    p_reveal.add_argument("-p", "--password", help="Password (omit to be prompted securely)")
    p_reveal.set_defaults(func=cmd_reveal)

    p_capacity = sub.add_parser("capacity", help="Check how large a message an image can hide")
    p_capacity.add_argument("image", help="Path to the cover image")
    p_capacity.set_defaults(func=cmd_capacity)

    p_hidefile = sub.add_parser("hide-file", help="Store an encrypted non-executable file in a carrier copy")
    p_hidefile.add_argument("carrier", help="Carrier: PNG/JPG/video/PDF")
    p_hidefile.add_argument("file", help="Non-executable file to encrypt and store")
    p_hidefile.add_argument("-p", "--password", help="Password (omit to be prompted securely)")
    p_hidefile.add_argument("-o", "--output", help="Output carrier path (default: *_with_secret)")
    p_hidefile.set_defaults(func=cmd_hide_file)

    p_revealfile = sub.add_parser("reveal-file", help="Recover an encrypted file from a carrier")
    p_revealfile.add_argument("carrier", help="Carrier containing the hidden payload")
    p_revealfile.add_argument("-p", "--password", help="Password (omit to be prompted securely)")
    p_revealfile.add_argument("-d", "--output-dir", default="recovered", help="Directory for recovered file")
    p_revealfile.set_defaults(func=cmd_reveal_file)

    p_vc = sub.add_parser("vault-create", help="Encrypt any file (including APK/EXE) into a .mgsvault container")
    p_vc.add_argument("file", help="File to encrypt")
    p_vc.add_argument("-p", "--password", help="Password (omit to be prompted securely)")
    p_vc.add_argument("-o", "--output", help="Vault output path (default: <file>.mgsvault)")
    p_vc.set_defaults(func=cmd_vault_create)

    p_vo = sub.add_parser("vault-open", help="Decrypt and restore a .mgsvault file")
    p_vo.add_argument("vault", help="Mughees .mgsvault container")
    p_vo.add_argument("-p", "--password", help="Password (omit to be prompted securely)")
    p_vo.add_argument("-d", "--output-dir", default="restored", help="Folder for restored file")
    p_vo.set_defaults(func=cmd_vault_open)

    p_bc = sub.add_parser("bundle-create", help="Encrypt an image and a file (including APK) together in a .mgsbundle")
    p_bc.add_argument("image", help="Image to include (PNG/JPG, for example)")
    p_bc.add_argument("file", help="File to include (APK is supported)")
    p_bc.add_argument("-p", "--password", help="Password (omit to be prompted securely)")
    p_bc.add_argument("-o", "--output", help="Output bundle path (default: <file>.mgsbundle)")
    p_bc.set_defaults(func=cmd_bundle_create)

    p_bo = sub.add_parser("bundle-open", help="Decrypt a .mgsbundle and restore its image and file")
    p_bo.add_argument("bundle", help="Encrypted .mgsbundle file")
    p_bo.add_argument("-p", "--password", help="Password (omit to be prompted securely)")
    p_bo.add_argument("-d", "--output-dir", default="restored_bundle", help="Folder for restored files")
    p_bo.set_defaults(func=cmd_bundle_open)

    p_compare = sub.add_parser("compare", help="Compare two images and highlight changed pixels")
    p_compare.add_argument("image_a", help="First image (e.g. original)")
    p_compare.add_argument("image_b", help="Second image (e.g. with hidden message)")
    p_compare.add_argument("-d", "--diff-output", help="Save a visual diff image to this path")
    p_compare.set_defaults(func=cmd_compare)

    return parser


def _ask(prompt: str) -> str:
    return input(prompt).strip().strip('"').strip("'")


def interactive_menu():
    while True:
        print(f"\n{_C.BOLD}===== Mughees Steganography v1.4 ====={_C.RESET}")
        print("1. Hide a message in a picture")
        print("2. Reveal a message from a picture")
        print("3. Compare two pictures (highlights changed pixels)")
        print("4. Hide a file inside a carrier copy (non-executable)")
        print("5. Reveal a file from a carrier")
        print("6. Create encrypted vault (.mgsvault, any file incl. APK)")
        print("7. Open encrypted vault")
        print("8. Create encrypted bundle (.mgsbundle: image + file)")
        print("9. Open encrypted bundle")
        print("10. Check how much a picture can hide (capacity)")
        print("0. Quit")
        choice = input("Choose 0-10: ").strip()

        try:
            if choice == "1":
                image = _ask("Which picture do you want to use? (e.g. photo.png): ")
                print("What message do you want to hide? ")
                message = input()
                password = _get_password(confirm=True)
                output = _default_output_name(image)
                hide_message(image, output, message, password)
                ok("Done! Your message is hidden in a copy of your picture.")
                info(f"Original picture (unchanged): {image}")
                ok(f"Copy with the hidden message: {output}")

            elif choice == "2":
                image = _ask("Which picture do you want to check? ")
                password = getpass.getpass("Password: ")
                message = reveal_message(image, password)
                ok("Hidden message found:")
                print(message)

            elif choice == "3":
                image_a = _ask("Original picture: ")
                image_b = _ask("Picture with the hidden message: ")
                diff = _ask("Save a diff image? (path, or leave blank to skip): ")
                compare_images(image_a, image_b, diff or None)

            elif choice == "4":
                carrier = _ask("Carrier (PNG/JPG/MP4/MOV/AVI/MKV/PDF): ")
                secret = _ask("File to hide (non-executable): ")
                password = _get_password(confirm=True)
                output = _default_file_output(carrier)
                hide_file(carrier, secret, output, password)
                ok("Encrypted file payload added to a new carrier copy.")
                info(f"Original carrier (unchanged): {carrier}")
                ok(f"Output: {output}")

            elif choice == "5":
                carrier = _ask("Carrier containing the hidden file: ")
                outdir = _ask("Folder for recovered file (blank = recovered): ") or "recovered"
                password = getpass.getpass("Password: ")
                ok(f"Recovered file: {reveal_file(carrier, outdir, password)}")

            elif choice == "6":
                path = _ask("File to encrypt into a vault: ")
                password = _get_password(confirm=True)
                output = path + ".mgsvault"
                create_vault(path, output, password)
                ok(f"Encrypted vault created: {output}")
                info("The original file was not changed.")

            elif choice == "7":
                vault = _ask("Vault file (.mgsvault): ")
                outdir = _ask("Folder for restored file (blank = restored): ") or "restored"
                password = getpass.getpass("Vault password: ")
                ok(f"File restored: {open_vault(vault, outdir, password)}")

            elif choice == "8":
                image = _ask("Image to include: ")
                path = _ask("File to include (APK etc.): ")
                password = _get_password(confirm=True)
                output = os.path.splitext(path)[0] + ".mgsbundle"
                create_bundle(image, path, output, password)
                ok(f"Encrypted bundle created: {output}")

            elif choice == "9":
                bundle = _ask("Bundle file (.mgsbundle): ")
                outdir = _ask("Folder for restored files (blank = restored_bundle): ") or "restored_bundle"
                password = getpass.getpass("Bundle password: ")
                ok("Restored files:")
                for path in open_bundle(bundle, outdir, password):
                    print(f"  {path}")

            elif choice == "10":
                image = _ask("Which picture do you want to check? ")
                cmd_capacity(argparse.Namespace(image=image))

            elif choice in ("0", "q", "Q"):
                print("Goodbye.")
                break
            else:
                print("Please choose a number from 0 to 10.")
        except (ValueError, OSError) as e:
            err(str(e))


def main():
    if len(sys.argv) == 1:
        interactive_menu()
        return

    parser = build_parser()
    args = parser.parse_args()
    set_output_mode(getattr(args, "verbose", False), getattr(args, "quiet", False))
    args.func(args)


if __name__ == "__main__":
    main()
