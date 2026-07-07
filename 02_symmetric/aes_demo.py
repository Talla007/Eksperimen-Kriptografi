#!/usr/bin/env python3
"""
=============================================================
  EKSPERIMEN 2A: AES (Advanced Encryption Standard)
  Mata Kuliah Kriptografi - Semester 4 Cyber Security

  Topik:
    - AES-256 Mode CBC (Cipher Block Chaining)
    - AES-256 Mode CTR (Counter Mode)
    - PKCS7 Padding
    - Perbandingan Mode Operasi
    - Pentingnya IV (Initialization Vector)

  AES adalah standar enkripsi simetris NIST (2001):
    - Block size: 128-bit
    - Key size: 128 / 192 / 256-bit
    - Jumlah ronde: 10 / 12 / 14
=============================================================
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import utils  # noqa: sets up UTF-8


import os
import hashlib
import time

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Util import Counter
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""


def check_library():
    if not HAS_CRYPTO:
        print(Fore.RED + Style.BRIGHT + """
  [ERROR] Library 'pycryptodome' tidak terinstal!
  Jalankan: pip install pycryptodome
  Atau    : pip install -r requirements.txt
""")
        return False
    return True


# ─────────────────────────────────────────────
# FUNGSI AES CBC
# ─────────────────────────────────────────────

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Enkripsi menggunakan AES-CBC dengan PKCS7 padding."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Dekripsi menggunakan AES-CBC dengan PKCS7 padding."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


# ─────────────────────────────────────────────
# FUNGSI AES CTR
# ─────────────────────────────────────────────

def aes_ctr_encrypt(plaintext: bytes, key: bytes, nonce: int = 0) -> bytes:
    """Enkripsi menggunakan AES-CTR (tidak perlu padding)."""
    ctr = Counter.new(128, initial_value=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(plaintext)


def aes_ctr_decrypt(ciphertext: bytes, key: bytes, nonce: int = 0) -> bytes:
    """Dekripsi menggunakan AES-CTR (enkripsi = dekripsi)."""
    ctr = Counter.new(128, initial_value=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(ciphertext)


# ─────────────────────────────────────────────
# FUNGSI UTILITAS
# ─────────────────────────────────────────────

def derive_key(password: str, length: int = 32) -> bytes:
    """Menurunkan kunci dari password menggunakan SHA-256."""
    return hashlib.sha256(password.encode()).digest()[:length]


def bytes_to_hex_blocks(data: bytes, block_size: int = 16) -> list[str]:
    """Konversi bytes ke hex, dibagi per blok."""
    hex_str = data.hex()
    return [hex_str[i:i + block_size * 2] for i in range(0, len(hex_str), block_size * 2)]


# ─────────────────────────────────────────────
# VISUALISASI
# ─────────────────────────────────────────────

def print_header():
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════╗
║      EKSPERIMEN 2A: AES-256 ENCRYPTION               ║
║      CBC Mode & CTR Mode + PKCS7 Padding             ║
╚══════════════════════════════════════════════════════╝""")


def print_section(title: str):
    print(Fore.YELLOW + Style.BRIGHT + f"\n  ┌─ {title}")
    print(Fore.YELLOW + "  │")


def show_pkcs7_padding(plaintext: bytes):
    """Menampilkan cara PKCS7 padding bekerja."""
    print_section("PKCS7 Padding (Block 128-bit = 16 byte)")
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    padded = pad(plaintext, 16)
    padded_blocks = [padded[i:i+16] for i in range(0, len(padded), 16)]

    print(Fore.WHITE + f"  │  Plaintext ({len(plaintext)} byte):")
    for i, block in enumerate(blocks):
        print(Fore.CYAN + f"  │    Block {i}: {block.hex():<32}  '{block.decode('utf-8','replace')}'")

    pad_len = 16 - (len(plaintext) % 16)
    if pad_len == 16:
        pad_len = 16
    print(Fore.WHITE + f"\n  │  Setelah Padding (pad_len={pad_len}):")
    for i, block in enumerate(padded_blocks):
        if i == len(padded_blocks) - 1:
            print(Fore.GREEN + f"  │    Block {i}: {block.hex():<32}  (+ {pad_len} byte padding 0x{pad_len:02X})")
        else:
            print(Fore.CYAN + f"  │    Block {i}: {block.hex():<32}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_cbc_encryption(plaintext: bytes, key: bytes, iv: bytes):
    """Demonstrasi AES-CBC."""
    print_section("AES-256 CBC Mode (Cipher Block Chaining)")
    print(Fore.WHITE + f"  │  Plaintext ({len(plaintext)} byte)   : {plaintext.decode()[:50]}")
    print(Fore.WHITE + f"  │  Key (32 byte hex)     : {key.hex()[:32]}...")
    print(Fore.WHITE + f"  │  IV  (16 byte hex)     : {iv.hex()}")

    t0 = time.perf_counter()
    ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    t1 = time.perf_counter()

    decrypted = aes_cbc_decrypt(ciphertext, key, iv)
    t2 = time.perf_counter()

    print(Fore.GREEN  + f"  │  Ciphertext ({len(ciphertext)} byte)  : {ciphertext.hex()[:50]}...")
    print(Fore.CYAN   + f"  │  Decrypted             : {decrypted.decode()[:50]}")
    print(Fore.WHITE  + f"  │  Waktu Enkripsi        : {(t1-t0)*1000:.4f} ms")
    print(Fore.WHITE  + f"  │  Waktu Dekripsi        : {(t2-t1)*1000:.4f} ms")
    print(Fore.GREEN  + f"  │  Verifikasi            : {'✔ SAMA' if decrypted == plaintext else '✘ BERBEDA!'}")

    # Blok-blok ciphertext
    print(Fore.WHITE + f"\n  │  Blok-blok Ciphertext (CBC - setiap blok bergantung pada sebelumnya):")
    for i, block_hex in enumerate(bytes_to_hex_blocks(ciphertext)):
        print(Fore.CYAN + f"  │    Blok {i:02d}: {block_hex}")
    print(Fore.YELLOW + "  └" + "─" * 54)
    return ciphertext


def show_ctr_encryption(plaintext: bytes, key: bytes, nonce: int):
    """Demonstrasi AES-CTR."""
    print_section("AES-256 CTR Mode (Counter Mode - Stream Cipher)")
    print(Fore.WHITE + f"  │  Plaintext ({len(plaintext)} byte)   : {plaintext.decode()[:50]}")
    print(Fore.WHITE + f"  │  Key (32 byte hex)     : {key.hex()[:32]}...")
    print(Fore.WHITE + f"  │  Nonce                 : {nonce} (0x{nonce:032x})")
    print(Fore.WHITE + f"  │  Padding diperlukan?   : TIDAK (CTR = stream cipher)")

    t0 = time.perf_counter()
    ciphertext = aes_ctr_encrypt(plaintext, key, nonce)
    t1 = time.perf_counter()

    decrypted = aes_ctr_decrypt(ciphertext, key, nonce)

    print(Fore.GREEN  + f"  │  Ciphertext ({len(ciphertext)} byte)  : {ciphertext.hex()[:50]}...")
    print(Fore.CYAN   + f"  │  Decrypted             : {decrypted.decode()[:50]}")
    print(Fore.WHITE  + f"  │  Waktu Enkripsi        : {(t1-t0)*1000:.4f} ms")
    print(Fore.GREEN  + f"  │  Verifikasi            : {'✔ SAMA' if decrypted == plaintext else '✘ BERBEDA!'}")
    print(Fore.YELLOW + "  └" + "─" * 54)
    return ciphertext


def show_iv_importance(plaintext: bytes, key: bytes):
    """Demonstrasi pentingnya IV yang berbeda setiap sesi."""
    print_section("Pentingnya Randomisasi IV (CBC Mode)")
    iv1 = os.urandom(16)
    iv2 = os.urandom(16)
    iv_fixed = bytes(16)  # IV = 000...0 (berbahaya!)

    ct1 = aes_cbc_encrypt(plaintext, key, iv1)
    ct2 = aes_cbc_encrypt(plaintext, key, iv2)
    ct_fixed1 = aes_cbc_encrypt(plaintext, key, iv_fixed)
    ct_fixed2 = aes_cbc_encrypt(plaintext, key, iv_fixed)

    print(Fore.WHITE + f"  │  Plaintext sama, kunci sama, beda IV:")
    print(Fore.CYAN  + f"  │    IV₁ (random): {ct1.hex()[:32]}...")
    print(Fore.GREEN + f"  │    IV₂ (random): {ct2.hex()[:32]}...")
    print(Fore.WHITE + f"  │  → Ciphertext BERBEDA (aman!)")
    print()
    print(Fore.WHITE + f"  │  IV tetap (all zeros) - BERBAHAYA:")
    print(Fore.RED   + f"  │    Enc₁: {ct_fixed1.hex()[:32]}...")
    print(Fore.RED   + f"  │    Enc₂: {ct_fixed2.hex()[:32]}...")
    print(Fore.RED   + f"  │  → Ciphertext {'SAMA' if ct_fixed1 == ct_fixed2 else 'berbeda'} (pola terlihat!)")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_mode_comparison(plaintext: bytes, key: bytes, iv: bytes, nonce: int):
    """Perbandingan CBC vs CTR."""
    print_section("Perbandingan Mode CBC vs CTR")
    ct_cbc = aes_cbc_encrypt(plaintext, key, iv)
    ct_ctr = aes_ctr_encrypt(plaintext, key, nonce)

    print(Fore.WHITE + f"  │  {'Aspek':<30} {'CBC':^20} {'CTR':^20}")
    print(Fore.WHITE + f"  │  {'─'*30} {'─'*20} {'─'*20}")
    rows = [
        ("Tipe",             "Block Cipher",      "Stream Cipher"),
        ("Padding",          "Ya (PKCS7)",         "Tidak"),
        ("Paralelisasi Enc", "Tidak",              "Ya"),
        ("Paralelisasi Dec", "Ya",                 "Ya"),
        ("IV/Nonce",         "IV (16 byte)",       "Nonce (counter)"),
        ("Ukuran Output",    f"{len(ct_cbc)} byte", f"{len(ct_ctr)} byte"),
        ("Gunakan untuk",    "Data tersimpan",     "Stream/data besar"),
    ]
    for aspect, cbc_val, ctr_val in rows:
        print(Fore.CYAN + f"  │  {aspect:<30} {cbc_val:^20} {ctr_val:^20}")
    print(Fore.YELLOW + "  └" + "─" * 54)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    if not check_library():
        return

    print_header()

    password  = "CyberSecurity2024!"
    plaintext = b"Ini adalah pesan rahasia untuk eksperimen AES-256 di kelas kriptografi semester 4!"
    key       = derive_key(password, 32)
    iv        = os.urandom(16)
    nonce     = int.from_bytes(os.urandom(16), 'big')

    print_section("Informasi Kunci")
    print(Fore.WHITE + f"  │  Password (input)     : '{password}'")
    print(Fore.GREEN + f"  │  Key SHA-256 (32 byte): {key.hex()}")
    print(Fore.WHITE + f"  │  IV  (16 byte)        : {iv.hex()}")
    print(Fore.WHITE + f"  │  Nonce CTR            : 0x{nonce:032x}"[:60])
    print(Fore.YELLOW + "  └" + "─" * 54)

    show_pkcs7_padding(plaintext)
    show_cbc_encryption(plaintext, key, iv)
    show_ctr_encryption(plaintext, key, nonce)
    show_iv_importance(b"DATA SENSITIF YANG SAMA", key)
    show_mode_comparison(plaintext, key, iv, nonce)

    print(Fore.CYAN + Style.BRIGHT + """
  ╔══════════════════════════════════════════════════════╗
  ║  KESIMPULAN                                          ║
  ║  ─────────────────────────────────────────────────  ║
  ║  ✔ AES-256 adalah standar enkripsi modern (NIST)    ║
  ║  ✔ CBC cocok untuk file/data tersimpan              ║
  ║  ✔ CTR cocok untuk streaming (tidak perlu padding)  ║
  ║  ⚠ IV/Nonce HARUS berbeda setiap sesi enkripsi!    ║
  ║  ✘ Kunci tidak boleh pernah dikompromikan           ║
  ╚══════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
