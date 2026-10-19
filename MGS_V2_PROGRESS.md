# v2.0 work in progress (not finished)

Done and tested (package `mgs/`):
- crypto.py   streaming AES-256-GCM container (constant memory, 10GB+ capable)
- archive.py  multi-file/folder archive with per-file SHA-256, safe extraction
- container.py pack/unpack/verify/inspect, carrier mode, in-memory containers
- carrier.py  carrier trailer + guardrail (executables are never concealed)
- lsb.py      NumPy LSB hide/reveal (keyed scatter, 1-4 bits), compare
- legacy.py   reads v1.4 files

NOT done yet: new CLI/interface, bulk runner, REST API, client SDK, tests, docs.
`stego.py` is still the original v1.4 script and does not use `mgs/` yet.
Use the SDK directly, e.g. `import mgs; mgs.pack([...], "x.mgsvault", "pw")`.
