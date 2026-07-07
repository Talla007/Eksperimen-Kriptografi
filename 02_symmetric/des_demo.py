#!/usr/bin/env python3
"""
=============================================================
  EKSPERIMEN 2B: DES & Triple-DES (3DES)
  Mata Kuliah Kriptografi - Semester 4 Cyber Security

  Topik:
    - DES (Data Encryption Standard) - 56-bit key (usang)
    - 3DES / Triple-DES - 112/168-bit effective key
    - Perbandingan keamanan DES vs 3DES vs AES
    - Mengapa DES sudah tidak aman

  DES (1977): Block cipher 64-bit, kunci 56-bit efektif
  3DES: Enc(K3) → Dec(K2) → Enc(K1) pada setiap blok
=============================================================
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import utils  # noqa: sets up UTF-8


import os
import time
import hashlib

try:
    from Crypto.Cipher import DES, DES3, AES
    from Crypto.Util.Padding import pad, unpad
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
        print(Fore.RED + "  [ERROR] Install: pip install pycryptodome")
        return False
    return True


# ─────────────────────────────────────────────
# FUNGSI INTI
# ─────────────────────────────────────────────

def des_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Enkripsi DES-CBC (kunci 8 byte / 64-bit)."""
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, DES.block_size))


def des_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Dekripsi DES-CBC."""
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES.block_size)


def des3_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Enkripsi 3DES-CBC (kunci 16 atau 24 byte)."""
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, DES3.block_size))


def des3_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Dekripsi 3DES-CBC."""
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES3.block_size)


def aes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Enkripsi AES-256-CBC untuk perbandingan."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def derive_key(password: str, length: int) -> bytes:
    raw = hashlib.sha256(password.encode()).digest()
    return (raw * 4)[:length]


# ─────────────────────────────────────────────
# VISUALISASI
# ─────────────────────────────────────────────

def print_header():
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════╗
║       EKSPERIMEN 2B: DES & Triple-DES (3DES)         ║
║    Evolusi Standar Enkripsi: DES → 3DES → AES        ║
╚══════════════════════════════════════════════════════╝""")


def print_section(title: str):
    print(Fore.YELLOW + Style.BRIGHT + f"\n  ┌─ {title}")
    print(Fore.YELLOW + "  │")


def show_des_structure():
    """Menampilkan struktur DES."""
    print_section("Struktur DES (Feistel Network - 16 Ronde)")
    print(Fore.WHITE + """  │
  │   Plaintext (64-bit)
  │        ↓
  │   ┌─────────────┐
  │   │  Initial     │  Permutasi IP
  │   │  Permutation │
  │   └──────┬───────┘
  │       L₀ │ R₀  (masing-masing 32-bit)
  │          ↓
  │   ┌──────────────────┐   ┌───────────┐
  │   │   Ronde 1-16     │ ← │  Key Sch  │  56-bit → 16 subkunci 48-bit
  │   │  Lᵢ = Rᵢ₋₁      │   └───────────┘
  │   │  Rᵢ = Lᵢ₋₁⊕f(R,K)│
  │   └──────────────────┘
  │          ↓
  │   ┌─────────────┐
  │   │   Inverse   │  Permutasi IP⁻¹
  │   │  Permutation│
  │   └──────┬───────┘
  │          ↓
  │   Ciphertext (64-bit)""")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_3des_structure():
    """Menampilkan struktur 3DES (EDE)."""
    print_section("Struktur 3DES / Triple-DES (EDE Mode)")
    print(Fore.WHITE + """  │
  │   Plaintext
  │       ↓
  │   ┌──────────┐
  │   │  DES Enc │  ← K₁ (56-bit)
  │   └────┬─────┘
  │        ↓
  │   ┌──────────┐
  │   │  DES Dec │  ← K₂ (56-bit)   Jika K₁=K₂=K₃ → setara DES biasa
  │   └────┬─────┘
  │        ↓
  │   ┌──────────┐
  │   │  DES Enc │  ← K₃ (56-bit)
  │   └────┬─────┘
  │        ↓
  │   Ciphertext
  │
  │   Panjang kunci efektif: 112-bit (K₁≠K₃) atau 168-bit (K₁≠K₂≠K₃)""")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_des_demo(plaintext: bytes, des_key: bytes, iv_des: bytes):
    """Demo DES enkripsi/dekripsi."""
    print_section(f"Demo DES Enkripsi (Kunci 8 byte = 64-bit, efektif 56-bit)")
    print(Fore.WHITE + f"  │  Plaintext  : {plaintext.decode()}")
    print(Fore.WHITE + f"  │  Key (hex)  : {des_key.hex()}")
    print(Fore.WHITE + f"  │  IV  (hex)  : {iv_des.hex()}")

    ct = des_encrypt(plaintext, des_key, iv_des)
    dt = des_decrypt(ct, des_key, iv_des)

    print(Fore.GREEN + f"  │  Ciphertext : {ct.hex()}")
    print(Fore.CYAN  + f"  │  Decrypted  : {dt.decode()}")
    print(Fore.GREEN + f"  │  Verifikasi : {'✔ SAMA' if dt == plaintext else '✘ BERBEDA!'}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_3des_demo(plaintext: bytes, key_3des: bytes, iv_des: bytes):
    """Demo 3DES enkripsi/dekripsi."""
    print_section(f"Demo 3DES Enkripsi (Kunci 24 byte = 168-bit, efektif 112-bit)")
    print(Fore.WHITE + f"  │  Plaintext   : {plaintext.decode()}")
    print(Fore.WHITE + f"  │  Key (hex)   : {key_3des.hex()[:32]}...")
    print(Fore.WHITE + f"  │  IV  (hex)   : {iv_des.hex()}")

    ct = des3_encrypt(plaintext, key_3des, iv_des)
    dt = des3_decrypt(ct, key_3des, iv_des)

    print(Fore.GREEN + f"  │  Ciphertext  : {ct.hex()}")
    print(Fore.CYAN  + f"  │  Decrypted   : {dt.decode()}")
    print(Fore.GREEN + f"  │  Verifikasi  : {'✔ SAMA' if dt == plaintext else '✘ BERBEDA!'}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_performance_comparison(plaintext: bytes,
                                 des_key: bytes, iv_des: bytes,
                                 key_3des: bytes, iv_aes: bytes,
                                 key_aes: bytes):
    """Perbandingan performa DES, 3DES, AES."""
    print_section("Perbandingan Performa & Keamanan: DES vs 3DES vs AES-256")

    iterations = 1000
    # DES
    t0 = time.perf_counter()
    for _ in range(iterations):
        des_encrypt(plaintext, des_key, iv_des)
    t_des = (time.perf_counter() - t0) * 1000 / iterations

    # 3DES
    t0 = time.perf_counter()
    for _ in range(iterations):
        des3_encrypt(plaintext, key_3des, iv_des)
    t_3des = (time.perf_counter() - t0) * 1000 / iterations

    # AES
    t0 = time.perf_counter()
    for _ in range(iterations):
        aes_encrypt(plaintext, key_aes, iv_aes)
    t_aes = (time.perf_counter() - t0) * 1000 / iterations

    ct_des  = des_encrypt(plaintext, des_key, iv_des)
    ct_3des = des3_encrypt(plaintext, key_3des, iv_des)
    ct_aes  = aes_encrypt(plaintext, key_aes, iv_aes)

    print(Fore.WHITE + f"  │  {'Aspek':<28} {'DES':^15} {'3DES':^15} {'AES-256':^15}")
    print(Fore.WHITE + f"  │  {'─'*28} {'─'*15} {'─'*15} {'─'*15}")
    rows = [
        ("Tahun Standar",    "1977",          "1999",          "2001"),
        ("Ukuran Blok",      "64-bit",        "64-bit",        "128-bit"),
        ("Panjang Kunci",    "56-bit eff.",   "112-bit eff.",  "256-bit"),
        ("Jumlah Ronde",     "16",            "48",            "14"),
        ("Ukuran Output",    f"{len(ct_des)}B", f"{len(ct_3des)}B", f"{len(ct_aes)}B"),
        ("Waktu/enkripsi",   f"{t_des:.4f}ms", f"{t_3des:.4f}ms", f"{t_aes:.4f}ms"),
        ("Status Keamanan",  "✘ USANG",       "⚠ DEPRECATED",  "✔ AMAN"),
    ]
    colors = [Fore.WHITE, Fore.WHITE, Fore.WHITE, Fore.WHITE,
              Fore.WHITE, Fore.CYAN, Fore.GREEN]
    for i, (aspect, v_des, v_3des, v_aes) in enumerate(rows):
        clr = colors[i]
        print(clr + f"  │  {aspect:<28} {v_des:^15} {v_3des:^15} {v_aes:^15}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_key_space_attack():
    """Menampilkan ancaman brute force berdasarkan ukuran key space."""
    print_section("Analisis Key Space & Ketahanan Brute Force")
    print(Fore.WHITE + f"  │  {'Cipher':<15} {'Key Bits':^12} {'Combinations':^22} {'Waktu Brute Force':^20}")
    print(Fore.WHITE + f"  │  {'─'*15} {'─'*12} {'─'*22} {'─'*20}")
    items = [
        ("Caesar",    5,   "26",                           "< 1 detik"),
        ("DES",      56,   f"2⁵⁶ ≈ 7.2×10¹⁶",             "22 jam (EFF DES)"),
        ("3DES-EDE", 112,  f"2¹¹² ≈ 5.2×10³³",             "> Usia alam semesta"),
        ("AES-128",  128,  f"2¹²⁸ ≈ 3.4×10³⁸",             "~1 triliun tahun"),
        ("AES-256",  256,  f"2²⁵⁶ ≈ 1.2×10⁷⁷",             "Mustahil"),
    ]
    status_colors = [Fore.RED, Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.GREEN]
    for i, (name, bits, combo, duration) in enumerate(items):
        print(status_colors[i] + f"  │  {name:<15} {bits:^12} {combo:^22} {duration:^20}")
    print(Fore.YELLOW + "  └" + "─" * 54)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    if not check_library():
        return

    print_header()

    password  = "CyberSec2024"
    plaintext = b"Pesan rahasia eksperimen DES dan 3DES kriptografi"

    des_key  = derive_key(password, 8)
    key_3des = derive_key(password, 24)
    key_aes  = derive_key(password, 32)
    iv_des   = os.urandom(8)   # DES IV = 8 byte
    iv_aes   = os.urandom(16)  # AES IV = 16 byte

    show_des_structure()
    show_3des_structure()
    show_des_demo(plaintext, des_key, iv_des)
    show_3des_demo(plaintext, key_3des, iv_des)
    show_performance_comparison(plaintext, des_key, iv_des, key_3des, iv_aes, key_aes)
    show_key_space_attack()

    print(Fore.CYAN + Style.BRIGHT + """
  ╔══════════════════════════════════════════════════════╗
  ║  KESIMPULAN                                          ║
  ║  ─────────────────────────────────────────────────  ║
  ║  ✘ DES (56-bit) sudah TIDAK AMAN sejak 1998!        ║
  ║  ⚠ 3DES masih digunakan namun mulai deprecated      ║
  ║  ✔ AES adalah standar saat ini (NIST FIPS 197)      ║
  ║  ✔ Gunakan AES-128 atau AES-256 untuk keamanan      ║
  ║  → Sejarah: DES → crackers 1998 → 3DES → AES 2001  ║
  ╚══════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
