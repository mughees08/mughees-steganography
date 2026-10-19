import subprocess, sys
from PIL import Image
import numpy as np

def test_roundtrip(tmp_path):
    cover = tmp_path / "cover.png"
    Image.fromarray(np.random.randint(0, 255, (256, 256, 3), dtype=np.uint8)).save(cover)
    secret = tmp_path / "secret.txt"
    secret.write_text("hello mughees steg")
    hidden = tmp_path / "vault.png"
    subprocess.run([sys.executable, "stego-tool/mughees_steg.py", "hide", str(cover), "-f", str(secret), "-o", str(hidden), "-p", "Str0ng!Pass", "--force"], check=True)
    out = tmp_path / "out"
    subprocess.run([sys.executable, "stego-tool/mughees_steg.py", "extract", str(hidden), "-o", str(out), "-p", "Str0ng!Pass"], check=True)
    assert (out / "secret.txt").read_text() == "hello mughees steg"
