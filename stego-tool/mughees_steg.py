#!/usr/bin/env python3
import os, sys, struct, hashlib, lzma, getpass, time, io, zipfile, shutil, random, string
from PIL import Image, ImageChops
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CY = "\033[96m"; GN = "\033[92m"; YL = "\033[93m"
RD = "\033[91m"; BL = "\033[94m"; RS = "\033[0m"; BD = "\033[1m"; DM = "\033[2m"

MAGIC_EOF = b"MGS_EOF_V8"
CHUNK_SIZE = 5 * 1024 * 1024 

def clear(): os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    clear()
    print(f"""{CY}{BD}
  ╔══════════════════════════════════════════════════════════════════╗
  ║  ███╗   ███╗ ██╗   ██╗ ██████╗ ██╗  ██╗███████╗███████╗███████╗  ║
  ║  ████╗ ████║ ██║   ██║██╔════╝ ██║  ██║██╔════╝██╔════╝██╔════╝  ║
  ║  ██╔████╔██║ ██║   ██║██║  ███╗███████║█████╗  ███████╗███████╗  ║
  ║  ██║╚██╔╝██║ ██║   ██║██║   ██║██╔══██║██╔══╝  ╚════██║╚════██║  ║
  ║  ██║ ╚═╝ ██║ ╚██████╔╝╚██████╔╝██║  ██║███████╗███████║███████║  ║
  ║  ╚═╝     ╚═╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝  ║
  ║      S T E G A N O G R A P H Y  ( T I T A N I U M  v8.0 )         ║
  ╚══════════════════════════════════════════════════════════════════╝{RS}
  {GN}Developer: Muhammad Mughees Abbasi{RS} | {YL}20 Advanced Features{RS}
""")

def get_key(pwd, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=500000)
    return kdf.derive(pwd.encode())

def progress_bar(iteration, total, prefix='', suffix='', length=30):
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled = int(length * iteration // total)
    bar = "█" * filled + "░" * (length - filled)
    sys.stdout.write(f'\r  {CY}{prefix}{RS} |{bar}| {percent}% {suffix}')
    sys.stdout.flush()

def hide_eof(carrier, file_path, out_path, pwd):
    file_size = os.path.getsize(file_path)
    salt = os.urandom(16); key = get_key(pwd, salt); nonce_base = os.urandom(8)
    fname = os.path.basename(file_path).encode()
    
    print(f"{CY}[*] Copying Carrier...{RS}")
    shutil.copyfile(carrier, out_path)
    orig_size = os.path.getsize(out_path)
    
    print(f"{CY}[*] Encrypting Data...{RS}")
    with open(out_path, "ab") as f_out, open(file_path, "rb") as f_in:
        total_chunks = (file_size // CHUNK_SIZE) + 1
        for i, chunk in enumerate(iter(lambda: f_in.read(CHUNK_SIZE), b"")):
            nonce = nonce_base + struct.pack(">I", i)
            ciphertext = AESGCM(key).encrypt(nonce, chunk, None)
            f_out.write(struct.pack(">I", len(ciphertext)) + ciphertext)
            progress_bar(i+1, total_chunks, prefix="Hiding", suffix=f"{i+1}/{total_chunks}")
            
        footer = MAGIC_EOF + salt + nonce_base + struct.pack(">QQH", orig_size, file_size, len(fname)) + fname
        f_out.write(footer)
    print(f"\n{GN}[✓] SUCCESS! Hidden inside: {out_path}{RS}")

def extract_eof(carrier_path, pwd):
    file_size = os.path.getsize(carrier_path)
    with open(carrier_path, "rb") as f:
        f.seek(max(0, file_size - 1000))
        tail = f.read()
        magic_pos = tail.find(MAGIC_EOF)
        if magic_pos == -1: return print(f"{RD}[✗] No payload found!{RS}")
        
        footer = tail[magic_pos + len(MAGIC_EOF):]
        salt = footer[:16]; nonce_base = footer[16:24]
        orig_size, hidden_size, fname_len = struct.unpack(">QQH", footer[24:42])
        fname = footer[42:42+fname_len].decode()
        
        key = get_key(pwd, salt)
        f.seek(orig_size)
        
        out_file = "extracted_" + fname
        total_chunks = (hidden_size // CHUNK_SIZE) + 1
        
        with open(out_file, "wb") as f_out:
            extracted = 0; i = 0
            while extracted < hidden_size:
                len_bytes = f.read(4)
                if not len_bytes: break
                chunk_len = struct.unpack(">I", len_bytes)[0]
                ciphertext = f.read(chunk_len)
                nonce = nonce_base + struct.pack(">I", i)
                try: chunk = AESGCM(key).decrypt(nonce, ciphertext, None)
                except Exception: return print(f"\n{RD}[✗] Wrong password!{RS}")
                f_out.write(chunk)
                extracted += len(chunk); i += 1
                progress_bar(i, total_chunks, prefix="Extract", suffix=f"{i}/{total_chunks}")
                
    print(f"\n{GN}[✓] SUCCESS! Extracted: {out_file}{RS}")

def hide_lsb(img_path, file_path, out_path, pwd):
    try: img = Image.open(img_path).convert("RGB")
    except Exception as e: return print(f"{RD}[✗] Error: {e}{RS}")
    pixels = list(img.getdata()); total_pixels = len(pixels) * 3
    with open(file_path, "rb") as f: raw = f.read()
    fname = os.path.basename(file_path).encode()
    
    comp = lzma.compress(raw, preset=6)
    payload = struct.pack(">H", len(fname)) + fname + comp
    salt = os.urandom(16); key = get_key(pwd, salt); nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, payload, None)
    
    header = b"MGS_LSB_V1" + salt + nonce + struct.pack(">I", len(ciphertext))
    h_bits = ''.join(f'{b:08b}' for b in header); d_bits = ''.join(f'{b:08b}' for b in ciphertext)
    
    if (len(h_bits) + len(d_bits)) > total_pixels: return print(f"{RD}[✗] Image too small for LSB!{RS}")

    new_pixels = list(pixels); idx = 0
    for bit in h_bits:
        p_idx = idx // 3; c_idx = idx % 3; p = list(new_pixels[p_idx])
        p[c_idx] = (p[c_idx] & 0xFE) | int(bit); new_pixels[p_idx] = tuple(p); idx += 1
        
    rev_data_bits = d_bits[::-1]; idx = total_pixels - 1
    for bit in rev_data_bits:
        p_idx = idx // 3; c_idx = idx % 3; p = list(new_pixels[p_idx])
        p[c_idx] = (p[c_idx] & 0xFE) | int(bit); new_pixels[p_idx] = tuple(p); idx -= 1

    new_img = Image.new("RGB", img.size); new_img.putdata(new_pixels); new_img.save(out_path, "PNG")
    print(f"{GN}[✓] SUCCESS! Hidden via LSB: {out_path}{RS}")

def extract_lsb(img_path, pwd):
    try: img = Image.open(img_path).convert("RGB")
    except Exception as e: return print(f"{RD}[✗] Error: {e}{RS}")
    pixels = list(img.getdata()); total_pixels = len(pixels) * 3
    h_bits = "".join(str(pixels[i // 3][i % 3] & 1) for i in range(288))
    header = bytes(int(h_bits[i:i+8], 2) for i in range(0, len(h_bits), 8))
    
    if not header.startswith(b"MGS_LSB_V1"): return print(f"{RD}[✗] No LSB payload found!{RS}")
    salt = header[10:26]; nonce = header[26:38]; data_len = struct.unpack(">I", header[38:42])[0]
    
    data_bits = ""; idx = total_pixels - 1
    for _ in range(data_len * 8):
        data_bits += str(pixels[idx // 3][idx % 3] & 1); idx -= 1
    ciphertext = bytes(int(data_bits[i:i+8], 2) for i in range(0, len(data_bits), 8))[::-1][::-1]
    
    try:
        key = get_key(pwd, salt); payload = AESGCM(key).decrypt(nonce, ciphertext, None)
        fname_len = struct.unpack(">H", payload[:2])[0]; fname = payload[2:2+fname_len].decode()
        raw = lzma.decompress(payload[2+fname_len:])
        out_file = "extracted_" + fname
        with open(out_file, "wb") as f: f.write(raw)
        print(f"{GN}[✓] SUCCESS! Extracted: {out_file}{RS}")
    except Exception: print(f"{RD}[✗] Wrong password!{RS}")

def act_compare():
    i1 = input(f"{YL}[?] First Image: {RS}").strip(); i2 = input(f"{YL}[?] Second Image: {RS}").strip()
    try:
        diff = ImageChops.difference(Image.open(i1).convert("RGB"), Image.open(i2).convert("RGB"))
        print(f"{RD}[!] Images differ.{RS}" if diff.getbbox() else f"{GN}[✓] Images identical!{RS}")
    except Exception as e: print(f"{RD}[✗] Error: {e}{RS}")

def act_batch_hide():
    print(f"\n{YL}--- BATCH IMAGE HIDE ---{RS}")
    f_path = input(f"{YL}[?] File to hide: {RS}").strip()
    out_prefix = input(f"{YL}[?] Output Prefix: {RS}").strip() or "part"
    pwd = getpass.getpass(f"{YL}[?] Password: {RS}")
    size = os.path.getsize(f_path)
    parts = int(input(f"{YL}[?] In how many images?: {RS}"))
    
    chunk_size = size // parts + 1
    with open(f_path, "rb") as f:
        for i in range(parts):
            chunk = f.read(chunk_size)
            if not chunk: break
            tmp = f"tmp_{i}.bin"
            with open(tmp, "wb") as t: t.write(chunk)
            Image.fromarray(__import__('numpy').random.randint(0, 255, (2048, 2048, 3), dtype=__import__('numpy').uint8)).save(f"cover_{i}.png")
            hide_eof(f"cover_{i}.png", tmp, f"{out_prefix}_{i+1}.png", pwd)
            os.remove(tmp); os.remove(f"cover_{i}.png")

def act_audio():
    print(f"\n{YL}--- AUDIO STEGANOGRAPHY ---{RS}")
    ch = input(f"  [1] Hide File in Audio\n  [2] Extract File from Audio\n  > ")
    audio = input(f"{YL}[?] Audio Path (MP3/WAV): {RS}").strip()
    if ch == '1':
        f_path = input(f"{YL}[?] File to hide: {RS}").strip()
        pwd = getpass.getpass(f"{YL}[?] Password: {RS}")
        hide_eof(audio, f_path, "hidden_audio.mp3", pwd)
    elif ch == '2':
        pwd = getpass.getpass(f"{YL}[?] Password: {RS}")
        extract_eof(audio, pwd)

def act_shred():
    print(f"\n{YL}--- SECURE DELETE ---{RS}")
    f_path = input(f"{YL}[?] File to securely delete: {RS}").strip()
    if not os.path.exists(f_path): return print(f"{RD}[✗] Not found!{RS}")
    confirm = input(f"{RD}[!] WARNING: Type 'YES': {RS}")
    if confirm == 'YES':
        size = os.path.getsize(f_path)
        with open(f_path, "wb") as f: f.write(os.urandom(size))
        os.remove(f_path)
        print(f"{GN}[✓] File shredded forever!{RS}")

def act_hash():
    print(f"\n{YL}--- FILE HASH ---{RS}")
    f_path = input(f"{YL}[?] File: {RS}").strip()
    try:
        with open(f_path, "rb") as f: h = hashlib.sha256(f.read()).hexdigest()
        print(f"{GN}[✓] SHA-256: {h}{RS}")
    except Exception as e: print(f"{RD}[✗] Error: {e}{RS}")

def act_hex():
    print(f"\n{YL}--- HEX INSPECTOR ---{RS}")
    f_path = input(f"{YL}[?] File: {RS}").strip()
    try:
        with open(f_path, "rb") as f: data = f.read(128)
        for i in range(0, len(data), 16):
            print(f"{CY}{i:08x}{RS}  {data[i:i+16].hex(' ').upper()}")
    except Exception as e: print(f"{RD}[✗] Error: {e}{RS}")

def act_strip_meta():
    print(f"\n{YL}--- STRIP EXIF ---{RS}")
    img_p = input(f"{YL}[?] Image: {RS}").strip()
    try:
        img = Image.open(img_p)
        data = list(img.getdata())
        clean = Image.new(img.mode, img.size); clean.putdata(data)
        clean.save("clean_" + img_p)
        print(f"{GN}[✓] Metadata removed. Saved: clean_{img_p}{RS}")
    except Exception as e: print(f"{RD}[✗] Error: {e}{RS}")

def act_gen_pass():
    print(f"\n{YL}--- PASSWORD GENERATOR ---{RS}")
    pwd = ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*", k=24))
    print(f"{GN}[✓] Password: {pwd}{RS}")

def main():
    banner()
    print(f"{BL}{BD} [ MUGHEES STEGANOGRAPHY v8.0 - MAIN MENU ]{RS}")
    print(f"  {GN}--- APK & VIDEO ---{RS}")
    print(f"  {YL}[1]{RS} Hide APK in PNG/JPG   |  {YL}[2]{RS} Extract APK from Image")
    print(f"  {YL}[3]{RS} Hide APK in Video     |  {YL}[4]{RS} Extract APK from Video")
    print(f"\n  {GN}--- TEXT & SMALL FILES ---{RS}")
    print(f"  {YL}[5]{RS} Hide Text/File (LSB)  |  {YL}[6]{RS} Extract Text/File (LSB)")
    print(f"  {YL}[7]{RS} Check Capacity        |  {YL}[8]{RS} Compare Images")
    print(f"\n  {GN}--- VAULT & AUDIO ---{RS}")
    print(f"  {YL}[9]{RS} Encrypt Vault         |  {YL}[10]{RS} Decrypt Vault")
    print(f"  {YL}[11]{RS} Hide in Audio        |  {YL}[12]{RS} Extract from Audio")
    print(f"\n  {GN}--- ADVANCED (INDUSTRIAL) ---{RS}")
    print(f"  {YL}[13]{RS} Batch Hide (Split)   |  {YL}[14]{RS} Generate Cover Image")
    print(f"  {YL}[15]{RS} Strip EXIF Metadata  |  {YL}[16]{RS} File Hash (SHA-256)")
    print(f"  {YL}[17]{RS} Secure Delete (Shred)|  {YL}[18]{RS} Hex Inspector")
    print(f"  {YL}[19]{RS} Generate Password    |  {YL}[20]{RS} Show Dev Info")
    print(f"  {YL}[0]{RS}  Exit\n")
    
    ch = input(f"{CY}mughees@stego ❯ {RS}").strip()
    try:
        if ch == '1': hide_eof(input(f"{YL}[?] Image: {RS}").strip(), input(f"{YL}[?] APK: {RS}").strip(), input(f"{YL}[?] Out: {RS}").strip() or "hidden_app.png", getpass.getpass(f"{YL}[?] Pass: {RS}"))
        elif ch == '2': extract_eof(input(f"{YL}[?] Image: {RS}").strip(), getpass.getpass(f"{YL}[?] Pass: {RS}"))
        elif ch == '3': hide_eof(input(f"{YL}[?] Video: {RS}").strip(), input(f"{YL}[?] APK: {RS}").strip(), input(f"{YL}[?] Out: {RS}").strip() or "hidden_vid.mp4", getpass.getpass(f"{YL}[?] Pass: {RS}"))
        elif ch == '4': extract_eof(input(f"{YL}[?] Video: {RS}").strip(), getpass.getpass(f"{YL}[?] Pass: {RS}"))
        elif ch == '5': hide_lsb(input(f"{YL}[?] Image: {RS}").strip(), input(f"{YL}[?] File/Text: {RS}").strip(), input(f"{YL}[?] Out: {RS}").strip() or "secret.png", getpass.getpass(f"{YL}[?] Pass: {RS}"))
        elif ch == '6': extract_lsb(input(f"{YL}[?] Image: {RS}").strip(), getpass.getpass(f"{YL}[?] Pass: {RS}"))
        elif ch == '7': 
            try: im = Image.open(input(f"{YL}[?] Image: {RS}").strip()); print(f"{GN}[✓] Cap: {(im.width*im.height*3)//8:,} Bytes{RS}")
            except: print(f"{RD}[✗] Error{RS}")
        elif ch == '8': act_compare()
        elif ch == '9':
            f_path = input(f"{YL}[?] File: {RS}").strip(); pwd = getpass.getpass(f"{YL}[?] Pass: {RS}")
            with open(f_path, "rb") as f: raw = f.read()
            salt = os.urandom(16); nonce = os.urandom(12)
            with open(f_path + ".mgsvault", "wb") as f: f.write(salt + nonce + AESGCM(get_key(pwd, salt)).encrypt(nonce, raw, None))
            print(f"{GN}[✓] Vault Created!{RS}")
        elif ch == '10':
            f_path = input(f"{YL}[?] .mgsvault: {RS}").strip(); pwd = getpass.getpass(f"{YL}[?] Pass: {RS}")
            with open(f_path, "rb") as f: data = f.read()
            try: raw = AESGCM(get_key(pwd, data[:16])).decrypt(data[16:28], data[28:], None); open(f_path+".dec", "wb").write(raw); print(f"{GN}[✓] Decrypted!{RS}")
            except: print(f"{RD}[✗] Wrong pass!{RS}")
        elif ch == '11': act_audio()
        elif ch == '12': act_audio()
        elif ch == '13': act_batch_hide()
        elif ch == '14':
            try: __import__('numpy'); Image.fromarray(__import__('numpy').random.randint(0,255,(2048,2048,3),dtype=__import__('numpy').uint8)).save("cover.png"); print(f"{GN}[✓] cover.png created!{RS}")
            except: print(f"{RD}[✗] numpy not installed! pip install numpy{RS}")
        elif ch == '15': act_strip_meta()
        elif ch == '16': act_hash()
        elif ch == '17': act_shred()
        elif ch == '18': act_hex()
        elif ch == '19': act_gen_pass()
        elif ch == '20': print(f"{GN}Dev: Muhammad Mughees Abbasi\nVersion: 8.0 Titanium\nGitHub: mughees08{RS}")
        elif ch == '0': sys.exit(0)
    except Exception as e: print(f"{RD}[✗] Error: {e}{RS}")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print(f"\n{RD}Exiting...{RS}")
