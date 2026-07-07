#!/usr/bin/env python3
"""
=============================================================
  EKSPERIMEN 1C: PLAYFAIR CIPHER
  Mata Kuliah Kriptografi - Semester 4 Cyber Security

  Topik:
    - Enkripsi & Dekripsi Playfair Cipher
    - Pembentukan Playfair Key Matrix 5x5
    - Aturan digram (pasangan huruf)

  Playfair mengenkripsi dua huruf sekaligus (digraph):
    - Huruf pada baris sama → geser kanan
    - Huruf pada kolom sama → geser bawah
    - Berbeda baris & kolom → rectangle swap
=============================================================
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import utils  # noqa: sets up UTF-8


import re

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

def build_key_matrix(key: str) -> list[list[str]]:
    """
    Membangun key matrix 5x5 Playfair.
    Huruf I dan J dianggap sama.
    """
    key = key.upper().replace('J', 'I')
    seen = []
    for ch in key:
        if ch.isalpha() and ch not in seen:
            seen.append(ch)
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # tanpa J
    for ch in alphabet:
        if ch not in seen:
            seen.append(ch)
    matrix = [seen[i*5:(i+1)*5] for i in range(5)]
    return matrix


def find_position(matrix: list[list[str]], ch: str) -> tuple[int, int]:
    """Mencari posisi huruf dalam matrix."""
    ch = ch.upper().replace('J', 'I')
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return r, c
    raise ValueError(f"Huruf '{ch}' tidak ditemukan dalam matrix")


def prepare_text(text: str) -> list[tuple[str, str]]:
    """
    Menyiapkan teks menjadi pasangan digram.
    - Ganti J dengan I
    - Sisipkan X jika dua huruf sama dalam pasangan
    - Tambah X jika panjang ganjil
    """
    text = re.sub(r'[^A-Za-z]', '', text).upper().replace('J', 'I')
    pairs: list[tuple[str, str]] = []
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 < len(text):
            b = text[i + 1]
            if a == b:
                pairs.append((a, 'X'))
                i += 1
            else:
                pairs.append((a, b))
                i += 2
        else:
            pairs.append((a, 'X'))
            i += 1
    return pairs


def encrypt_pair(matrix: list[list[str]], a: str, b: str) -> tuple[str, str]:
    """Enkripsi satu pasangan huruf."""
    ra, ca = find_position(matrix, a)
    rb, cb = find_position(matrix, b)
    if ra == rb:                     # Baris sama → geser kanan
        return matrix[ra][(ca + 1) % 5], matrix[rb][(cb + 1) % 5]
    elif ca == cb:                   # Kolom sama → geser bawah
        return matrix[(ra + 1) % 5][ca], matrix[(rb + 1) % 5][cb]
    else:                            # Rectangle → swap kolom
        return matrix[ra][cb], matrix[rb][ca]


def decrypt_pair(matrix: list[list[str]], a: str, b: str) -> tuple[str, str]:
    """Dekripsi satu pasangan huruf."""
    ra, ca = find_position(matrix, a)
    rb, cb = find_position(matrix, b)
    if ra == rb:                     # Baris sama → geser kiri
        return matrix[ra][(ca - 1) % 5], matrix[rb][(cb - 1) % 5]
    elif ca == cb:                   # Kolom sama → geser atas
        return matrix[(ra - 1) % 5][ca], matrix[(rb - 1) % 5][cb]
    else:                            # Rectangle → swap kolom
        return matrix[ra][cb], matrix[rb][ca]


def playfair_encrypt(plaintext: str, key: str) -> str:
    """Enkripsi plaintext dengan Playfair Cipher."""
    matrix = build_key_matrix(key)
    pairs  = prepare_text(plaintext)
    result = []
    for a, b in pairs:
        ea, eb = encrypt_pair(matrix, a, b)
        result.extend([ea, eb])
    return "".join(result)


def playfair_decrypt(ciphertext: str, key: str) -> str:
    """Dekripsi ciphertext dengan Playfair Cipher."""
    matrix = build_key_matrix(key)
    pairs  = [(ciphertext[i], ciphertext[i+1])
              for i in range(0, len(ciphertext), 2)]
    result = []
    for a, b in pairs:
        da, db = decrypt_pair(matrix, a, b)
        result.extend([da, db])
    return "".join(result)


# ─────────────────────────────────────────────
# VISUALISASI
# ─────────────────────────────────────────────

def print_header():
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════╗
║         EKSPERIMEN 1C: PLAYFAIR CIPHER               ║
║        Digraph Substitution Cipher (1854)            ║
╚══════════════════════════════════════════════════════╝""")


def print_section(title: str):
    print(Fore.YELLOW + Style.BRIGHT + f"\n  ┌─ {title}")
    print(Fore.YELLOW + "  │")


def show_key_matrix(matrix: list[list[str]], key: str):
    """Menampilkan key matrix 5x5."""
    print_section(f"Key Matrix 5×5 (Keyword: '{key}')")
    print(Fore.WHITE + "  │     " + "  ".join([f"C{i}" for i in range(5)]))
    print(Fore.WHITE + "  │  " + "─" * 22)
    colors = [Fore.GREEN, Fore.CYAN, Fore.MAGENTA, Fore.YELLOW, Fore.WHITE]
    for r, row in enumerate(matrix):
        colored_row = [colors[r] + Style.BRIGHT + ch + Style.RESET_ALL for ch in row]
        print(Fore.WHITE + f"  │  R{r}  " + "  ".join(colored_row))
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_pair_encryption(matrix: list[list[str]], pairs: list[tuple[str, str]]):
    """Menampilkan proses enkripsi per pasangan."""
    print_section("Proses Enkripsi per Digram")
    print(Fore.WHITE + f"  │  {'Pasangan':^10} {'Aturan':^25} {'Hasil':^10}")
    print(Fore.WHITE + f"  │  {'─'*10} {'─'*25} {'─'*10}")
    for a, b in pairs:
        ra, ca = find_position(matrix, a)
        rb, cb = find_position(matrix, b)
        ea, eb = encrypt_pair(matrix, a, b)
        if ra == rb:
            rule = f"Baris sama (R{ra})"
        elif ca == cb:
            rule = f"Kolom sama (C{ca})"
        else:
            rule = f"Rectangle ({ra},{ca})↔({rb},{cb})"
        print(Fore.CYAN + f"  │  {a+b:^10} {rule:^25} {ea+eb:^10}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_encrypt_decrypt(plaintext: str, key: str):
    """Demo enkripsi dan dekripsi."""
    matrix = build_key_matrix(key)
    pairs  = prepare_text(plaintext)

    ciphertext = playfair_encrypt(plaintext, key)
    decrypted  = playfair_decrypt(ciphertext, key)

    print_section("Demonstrasi Enkripsi & Dekripsi")
    print(Fore.WHITE  + f"  │  Plaintext   : {Style.BRIGHT}{plaintext}")
    print(Fore.WHITE  + f"  │  Key         : {Style.BRIGHT}{key}")
    print(Fore.WHITE  + f"  │  Prepared    : {Style.BRIGHT}{''.join(a+b for a,b in pairs)}")
    print(Fore.GREEN  + f"  │  Ciphertext  : {Style.BRIGHT}{ciphertext}")
    print(Fore.CYAN   + f"  │  Decrypted   : {Style.BRIGHT}{decrypted}")
    print(Fore.YELLOW + "  └" + "─" * 54)

    show_pair_encryption(matrix, pairs[:6])
    return ciphertext


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print_header()

    key       = "CYBERSECURITY"
    plaintext = "ATTACK AT DAWN"

    matrix = build_key_matrix(key)
    show_key_matrix(matrix, key)
    ciphertext = show_encrypt_decrypt(plaintext, key)

    # Contoh tambahan
    print_section("Contoh Enkripsi Lainnya")
    examples = [
        ("HELLO WORLD", "PLAYFAIR"),
        ("SECRET MESSAGE", "NETWORK"),
        ("CRYPTOGRAPHY", "INDONESIA"),
    ]
    print(Fore.WHITE + f"  │  {'Plaintext':<20} {'Key':<15} {'Ciphertext'}")
    print(Fore.WHITE + f"  │  {'─'*20} {'─'*15} {'─'*20}")
    for pt, k in examples:
        ct = playfair_encrypt(pt, k)
        print(Fore.CYAN + f"  │  {pt:<20} {k:<15} {ct}")
    print(Fore.YELLOW + "  └" + "─" * 54)

    print(Fore.CYAN + Style.BRIGHT + """
  ╔══════════════════════════════════════════════════════╗
  ║  KESIMPULAN                                          ║
  ║  ─────────────────────────────────────────────────  ║
  ║  ✔ Playfair mengenkripsi PASANGAN huruf (digraph)   ║
  ║  ✔ Lebih kuat dari monoalphabetic substitution      ║
  ║  ✔ Frekuensi huruf tunggal tidak mudah dianalisis   ║
  ║  ✘ Frekuensi digram masih bisa dianalisis           ║
  ║  ✘ Key matrix 5×5 terbatas pada 25 huruf (I=J)     ║
  ╚══════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
