#!/usr/bin/env python3
"""
=============================================================
  EKSPERIMEN 1A: CAESAR CIPHER
  Mata Kuliah Kriptografi - Semester 4 Cyber Security

  Topik:
    - Enkripsi & Dekripsi Caesar Cipher
    - Brute Force Attack (cryptanalysis)
    - Visualisasi pergeseran karakter

  Caesar Cipher menggeser setiap huruf sejauh 'k' posisi
  dalam alfabet.
    E(x) = (x + k) mod 26
    D(x) = (x - k) mod 26
=============================================================
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import utils  # noqa: sets up UTF-8


import string

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""


# ─────────────────────────────────────────────
# FUNGSI INTI
# ─────────────────────────────────────────────

def caesar_encrypt(plaintext: str, key: int) -> str:
    """Enkripsi teks menggunakan Caesar Cipher."""
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shifted = (ord(ch) - base + key) % 26
            result.append(chr(base + shifted))
        else:
            result.append(ch)
    return "".join(result)


def caesar_decrypt(ciphertext: str, key: int) -> str:
    """Dekripsi teks menggunakan Caesar Cipher."""
    return caesar_encrypt(ciphertext, -key)


def brute_force_attack(ciphertext: str) -> list[tuple[int, str]]:
    """Mencoba semua 26 kemungkinan kunci (brute force)."""
    results = []
    for key in range(26):
        decrypted = caesar_decrypt(ciphertext, key)
        results.append((key, decrypted))
    return results


def score_english(text: str) -> float:
    """
    Memberikan skor berdasarkan frekuensi huruf bahasa Inggris.
    Skor lebih tinggi = lebih mirip bahasa Inggris.
    """
    freq = {
        'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97,
        'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25,
        'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36,
        'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.29,
        'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07
    }
    text_lower = text.lower()
    score = sum(freq.get(ch, 0) for ch in text_lower if ch.isalpha())
    return score


def auto_crack(ciphertext: str) -> tuple[int, str]:
    """Memilih kunci terbaik berdasarkan skor frekuensi bahasa Inggris."""
    candidates = brute_force_attack(ciphertext)
    best_key, best_text = max(candidates, key=lambda x: score_english(x[1]))
    return best_key, best_text


# ─────────────────────────────────────────────
# VISUALISASI
# ─────────────────────────────────────────────

def print_header():
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════╗
║          EKSPERIMEN 1A: CAESAR CIPHER                ║
║      Enkripsi Klasik & Brute Force Attack            ║
╚══════════════════════════════════════════════════════╝""")


def print_section(title: str):
    print(Fore.YELLOW + Style.BRIGHT + f"\n  ┌─ {title}")
    print(Fore.YELLOW + "  │")


def show_shift_table(key: int):
    """Menampilkan tabel pergeseran alfabet."""
    print_section(f"Tabel Pergeseran (Key = {key})")
    alphabet = string.ascii_uppercase
    shifted = alphabet[key:] + alphabet[:key]
    print(Fore.WHITE + f"  │  Original : {' '.join(alphabet)}")
    print(Fore.GREEN  + f"  │  Shifted  : {' '.join(shifted)}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_encrypt_decrypt(plaintext: str, key: int):
    """Demonstrasi enkripsi dan dekripsi."""
    ciphertext = caesar_encrypt(plaintext, key)
    decrypted  = caesar_decrypt(ciphertext, key)

    print_section("Demonstrasi Enkripsi & Dekripsi")
    print(Fore.WHITE  + f"  │  Plaintext   : {Style.BRIGHT}{plaintext}")
    print(Fore.WHITE  + f"  │  Key (shift) : {Style.BRIGHT}{key}")
    print(Fore.GREEN  + f"  │  Ciphertext  : {Style.BRIGHT}{ciphertext}")
    print(Fore.CYAN   + f"  │  Decrypted   : {Style.BRIGHT}{decrypted}")
    print(Fore.YELLOW + "  └" + "─" * 54)

    # Tampilkan proses karakter per karakter
    print_section("Proses Enkripsi (karakter per karakter)")
    print(Fore.WHITE + f"  │  {'Char':^6} {'ASCII':^8} {'Shift':^8} {'Result':^8} {'Cipher':^8}")
    print(Fore.WHITE + f"  │  {'─'*6} {'─'*8} {'─'*8} {'─'*8} {'─'*8}")
    for ch in plaintext[:10]:  # Tampilkan maksimal 10 karakter
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            orig_pos = ord(ch) - base
            new_pos  = (orig_pos + key) % 26
            cipher_ch = chr(base + new_pos)
            print(Fore.WHITE + f"  │  {ch:^6} {ord(ch):^8d} {key:^8d} {new_pos:^8d} {cipher_ch:^8}")
        else:
            print(Fore.WHITE + f"  │  {ch:^6} {'─':^8} {'─':^8} {'─':^8} {ch:^8}")
    if len(plaintext) > 10:
        print(Fore.WHITE + f"  │  ... (dan {len(plaintext)-10} karakter lainnya)")
    print(Fore.YELLOW + "  └" + "─" * 54)

    return ciphertext


def show_brute_force(ciphertext: str):
    """Menampilkan hasil brute force attack."""
    print_section(f"Brute Force Attack pada: '{ciphertext}'")
    all_results = brute_force_attack(ciphertext)
    best_key, best_text = auto_crack(ciphertext)

    print(Fore.WHITE + f"  │  {'Key':^6} {'Decrypted Text':<40} {'Score':>8}")
    print(Fore.WHITE + f"  │  {'─'*6} {'─'*40} {'─'*8}")

    for key, text in all_results:
        score = score_english(text)
        if key == best_key:
            color = Fore.GREEN + Style.BRIGHT
            marker = " ◀ BEST FIT"
        else:
            color = Fore.WHITE
            marker = ""
        print(color + f"  │  {key:^6} {text[:40]:<40} {score:>8.2f}{marker}")

    print(Fore.YELLOW + "  └" + "─" * 54)
    print(Fore.GREEN + Style.BRIGHT + f"\n  ✔  Kunci yang ditemukan: {best_key} → '{best_text}'")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print_header()

    # ── Demo 1: Enkripsi & Dekripsi ──
    plaintext = "HELLO WORLD, THIS IS CRYPTOGRAPHY CLASS"
    key       = 13  # ROT13 (salah satu Caesar yg populer)

    show_shift_table(key)
    ciphertext = show_encrypt_decrypt(plaintext, key)

    # ── Demo 2: Key lain ──
    print_section("Contoh Kunci Berbeda")
    for k in [3, 7, 21]:
        ct = caesar_encrypt("CRYPTOGRAPHY", k)
        dt = caesar_decrypt(ct, k)
        print(Fore.WHITE + f"  │  Key={k:2d}  |  CT: {ct:<18} |  DT: {dt}")
    print(Fore.YELLOW + "  └" + "─" * 54)

    # ── Demo 3: Brute Force ──
    cipher_challenge = "KHOOR ZRUOG, WKLV LV FUBSWRJUDSKB FODVV"
    show_brute_force(cipher_challenge)

    # ── Kesimpulan ──
    print(Fore.CYAN + Style.BRIGHT + """
  ╔══════════════════════════════════════════════════════╗
  ║  KESIMPULAN                                          ║
  ║  ─────────────────────────────────────────────────  ║
  ║  ✔ Caesar Cipher mudah diimplementasi               ║
  ║  ✔ Hanya ada 25 kunci yang mungkin (Key Space: 26)  ║
  ║  ✘ Rentan terhadap Brute Force Attack (exhaustive)  ║
  ║  ✘ Rentan terhadap Frequency Analysis               ║
  ║  → Tidak aman untuk penggunaan modern               ║
  ╚══════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
