# Contributing to Mughees Steganography

Thanks for your interest in improving this project. It's a small,
single-file CLI tool, so contributions are easiest if they stay focused.

## Reporting a bug

Open an issue and include:
- Your OS/platform (Kali, Ubuntu, BlackArch, Termux, Termux+proot-distro, macOS)
- Python version (`python3 --version`)
- The exact command you ran
- The full output, including any traceback

Please **do not** include real passwords or the contents of a real
hidden message/file in a bug report — use throwaway test data instead.

## Suggesting a feature

Open an issue describing the use case before sending a pull request,
especially for anything that touches the crypto or payload format —
format changes affect compatibility with files other people have
already hidden.

## Development setup

```bash
git clone https://github.com/<your-username>/mughees-steganography.git
cd mughees-steganography/stego-tool
pip install -r requirements.txt
```

## Making a pull request

1. Keep changes focused — one feature or fix per PR.
2. Match the existing style (the file has no external formatter/linter
   dependency; keep it readable with plain Python).
3. Manually test the commands you touched:
   `hide`/`reveal`, `compare`, `capacity`, `hide-file`/`reveal-file`,
   `vault-create`/`vault-open`, `bundle-create`/`bundle-open`, and the
   interactive menu (`python3 stego.py` with no args).
4. If you change the on-disk payload format (magic bytes, header
   layout), bump the version and call it out clearly in the PR and the
   README — old hidden files will stop being readable.
5. Never add code that embeds, disguises, or auto-runs an executable
   payload from inside an image/video/PDF. Pull requests that move the
   project toward being a binder/dropper/crypter will be declined.

## Security

This tool encrypts with password-derived keys (PBKDF2-HMAC-SHA256 +
Fernet/AES) and has no password-recovery mechanism by design. If you
find an actual cryptographic weakness (not "I forgot my password"),
please open an issue describing it.
