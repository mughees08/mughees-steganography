# Mughees Steganography (v1.4)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/<your-username>/mughees-steganography/actions/workflows/ci.yml/badge.svg)](https://github.com/<your-username>/mughees-steganography/actions/workflows/ci.yml)
[![Platforms](https://img.shields.io/badge/platforms-Kali%20%7C%20Ubuntu%20%7C%20BlackArch%20%7C%20Termux%20%7C%20macOS-success.svg)](#supported-platforms)

A password-protected text steganography tool with an encrypted file-in-carrier mode, an encrypted file vault, and an encrypted image+file bundle. Hide a secret text message inside a picture, and reveal it later with the correct password. Also includes a pixel-diff comparison tool and an image-capacity checker.

**Developer:** Muhammad Mughees Abbasi

---

## Features

- **Hide** a text message inside a PNG image using LSB (Least Significant
  Bit) steganography.
- **Encrypt** the message with a password before hiding it (PBKDF2 +
  Fernet/AES), so the message cannot be read even if someone suspects a
  hidden payload.
- **Reveal** the message back, given the correct password.
- **Integrity-checked**: every hidden/stored payload carries a SHA-256
  checksum, so a corrupted or truncated file is reported clearly instead
  of being confused with a wrong password.
- **Capacity check**: see how large a message an image can hold before
  you try to hide one.
- **Compare** two images pixel by pixel and highlight exactly which
  pixels changed, with an optional visual diff image.
- **Hide a file** (non-executable) as an encrypted payload appended to a copy of a PNG/JPG/video/PDF carrier.
- **Vault**: encrypt any file (including APK/EXE) into a clearly labeled `.mgsvault` container.
- **Bundle**: encrypt an image and a file together into a clearly labeled `.mgsbundle` container.
- **Colored, verbose/quiet CLI** output (`-v/--verbose`, `-q/--quiet`), plus a full numbered interactive menu.

## What this tool does NOT do

The image LSB mode is **text-only**. The `hide-file` mode only accepts
non-executable files and stores them as an encrypted appended payload.
Executables (EXE, APK, scripts) are **never** hidden inside or disguised as
an image, video or PDF, and nothing here makes a file run from an image.
They can only be stored as ordinary encrypted files in a clearly labeled
`.mgsvault` / `.mgsbundle` container (see below). This is not a binder,
dropper, or crypter; the project is for learning/demoing how LSB
steganography and password-based encryption work.

## How it works (short version)

Every pixel in an image is made of color channel bytes (Red, Green,
Blue). This tool rewrites just the **last bit** of each channel byte to
store your encrypted message, one bit at a time. Changing the last bit
shifts a color value by at most 1 out of 255 — invisible to the human
eye, but readable in the pixel data by the person who has this tool and
your password.

The message itself is encrypted (not just hidden) with your password
before it ever touches the image, and a SHA-256 checksum is stored
alongside it, so even raw LSB-extraction by someone else won't reveal
the plaintext, and a damaged file is detected before decryption is even
attempted.

> **Format note (v1.4):** the payload format changed to add integrity
> checksums. Images/files hidden with v1.3 or earlier must be re-hidden
> with v1.4 to be readable by this version.

---

## Installation

### Requirements
- Python 3.8+
- pip

### Supported platforms
Kali Linux, Ubuntu, BlackArch, macOS, and Termux (Android) — including
Termux + **proot-distro** (Kali/Ubuntu chroot on Android).

### Setup

```bash
git clone https://github.com/<your-username>/mughees-steganography.git
cd mughees-steganography/stego-tool
pip install -r requirements.txt
```

On Debian/Ubuntu/Kali, if `pip install` is blocked by the system package
manager:

```bash
pip install --break-system-packages -r requirements.txt
```

### Termux (Android, no root)

```bash
pkg update && pkg install python libjpeg-turbo -y
pip install -r requirements.txt
python stego.py --version
```

### Termux + proot-distro (full Kali/Ubuntu on Android)

If you want the real Kali Linux or Ubuntu userland on your phone instead
of plain Termux, use `proot-distro`:

```bash
pkg update && pkg install proot-distro -y

# Pick ONE distro:
proot-distro install kali-linux
proot-distro install ubuntu

# Log in to the distro:
proot-distro login kali-linux      # or: proot-distro login ubuntu
```

Once inside the distro's shell, install the tool the normal Linux way:

```bash
apt update && apt install -y python3 python3-pip git
git clone https://github.com/<your-username>/mughees-steganography.git
cd mughees-steganography/stego-tool
pip install --break-system-packages -r requirements.txt
python3 stego.py --version
```

Notes:
- `proot-distro login <distro>` drops you back into Termux's `$HOME`
  by default; your project files stay wherever you cloned them inside
  that session.
- Clipboard, file access and GUI tools don't carry over automatically
  from the distro into Termux — stick to the CLI/interactive menu.
- Everything else in this README (commands, flags, menu) works
  identically once you're inside the distro's shell.

### BlackArch

```bash
pacman -S python python-pip
pip install --break-system-packages -r requirements.txt
```

---

## Usage

### Interactive mode (menu-driven)

```bash
python3 stego.py
```

This launches a numbered menu with every feature:

```
1. Hide a message in a picture
2. Reveal a message from a picture
3. Compare two pictures
4. Hide a file inside a carrier copy
5. Reveal a file from a carrier
6. Create encrypted vault (.mgsvault)
7. Open encrypted vault
8. Create encrypted bundle (.mgsbundle)
9. Open encrypted bundle
10. Check how much a picture can hide (capacity)
0. Quit
```

### Command-line mode

**Hide a message:**
```bash
python3 stego.py hide photo.png -m "This is my secret" -o photo_hidden.png
```
If you omit `-m`, you'll be prompted to type/paste the message. If you
omit `-p/--password`, you'll be securely prompted (input hidden).

**Reveal a message:**
```bash
python3 stego.py reveal photo_hidden.png
```
You'll be prompted for the password. A wrong password and a corrupted
file now give **different** errors, so you know which one happened.

**Check capacity before hiding:**
```bash
python3 stego.py capacity photo.png
```
Prints the image's raw bit capacity, the format/encryption overhead,
and roughly how many characters of text it can actually hide.

**Compare two images:**
```bash
python3 stego.py compare photo.png photo_hidden.png -d diff.png
```
Prints the number/percentage of changed pixels and optionally saves a
visual diff image with changed pixels highlighted in red.

**Verbose / quiet output:**
```bash
python3 stego.py -v hide photo.png -m "secret" -p pw -o photo_hidden.png   # extra detail
python3 stego.py -q hide photo.png -m "secret" -p pw -o photo_hidden.png   # final result only
```
Place `-v`/`-q` **before** the subcommand. Colors are automatically
disabled when output isn't a terminal, or when `NO_COLOR` is set.

---

## Notes

- Always use **PNG** as your cover/output image format. JPEG uses lossy
  compression and will destroy the hidden bits.
- Larger images can hide longer messages. Capacity = (width × height ×
  3) bits — use the `capacity` command to get an exact usable figure
  for a specific image.
- Keep your password safe — there is no recovery; it's intentionally
  one-way encryption.

## License

MIT License — see [LICENSE](LICENSE).

## Author

**Muhammad Mughees Abbasi**

---

## Encrypted file-in-carrier mode

The `hide-file` / `reveal-file` commands encrypt a non-executable file and append it to a copy of a PNG/JPG, video (MP4/MOV/AVI/MKV), or PDF carrier. The original carrier is left unchanged. This is an encrypted appended payload, not invisible pixel-level steganography, and some media applications may reject files with appended data. Test compatibility with your intended viewer before relying on it.

```bash
python3 stego.py hide-file photo.png notes.txt -o photo_with_secret.png
python3 stego.py reveal-file photo_with_secret.png -d recovered
```

The tool prompts for a password if `-p` is omitted. Executable payloads (including EXE/APK and scripts) are deliberately blocked. Use a clearly named encrypted archive/vault for executable files instead.

## Encrypted APK / EXE vault

APK and EXE files can be stored as ordinary encrypted files in a clearly
identified `.mgsvault` container. This does **not** disguise an executable as
an image or make it run from an image.

Create a vault:

```bash
python3 stego.py vault-create my-app.apk
```

Open a vault:

```bash
python3 stego.py vault-open my-app.apk.mgsvault -d restored
```

The tool prompts for the password securely. The original file is left unchanged.
Do not lose the password: there is no password-reset or recovery mechanism.

## Encrypted bundle (image + APK or another file)

You can package a picture and an APK together inside a password-protected `.mgsbundle` container. The container is clearly labeled as encrypted data; it is **not** a normal PNG/JPG and does not disguise the APK as an image.

Create a bundle (you will be prompted for a password if `-p` is omitted):

```bash
python stego.py bundle-create cover.png app.apk -o my-files.mgsbundle
```

Open the bundle and restore both files:

```bash
python stego.py bundle-open my-files.mgsbundle -d restored_files
```

For automated/testing use, `-p YOUR_PASSWORD` can be added to either command. Avoid putting real passwords in shell history where possible.

The original image and APK are not modified. Keep a backup of the `.mgsbundle` and remember the password; the password cannot be recovered if lost.

---

## Contributing

Bug reports, platform-compatibility notes, and small focused pull
requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
