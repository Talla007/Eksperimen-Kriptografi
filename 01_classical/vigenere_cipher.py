#!/usr/bin/env python3
"""
=============================================================
  EKSPERIMEN 1B: VIGENERE CIPHER
  Mata Kuliah Kriptografi - Semester 4 Cyber Security

  Topik:
    - Enkripsi & Dekripsi Vigenere Cipher (poly-alphabetic)
    - Index of Coincidence (IoC) Analysis
    - Kasiski Test untuk menentukan panjang kunci

  Vigenere Cipher menggunakan kunci berulang (keyword):
    E(i) = (P(i) + K(i mod m)) mod 26
    D(i) = (C(i) - K(i mod m)) mod 26
  di mana m = panjang kunci.
=============================================================
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import utils  # noqa: sets up UTF-8


import math
import string
from collections import Counter

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

def vigenere_encrypt(plaintext: str, key: str) -> str:
    """Enkripsi dengan Vigenere Cipher."""
    key = key.upper()
    result = []
    key_idx = 0
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            k = ord(key[key_idx % len(key)]) - ord('A')
            result.append(chr((ord(ch) - base + k) % 26 + base))
            key_idx += 1
        else:
            result.append(ch)
    return "".join(result)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Dekripsi dengan Vigenere Cipher."""
    key = key.upper()
    result = []
    key_idx = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            k = ord(key[key_idx % len(key)]) - ord('A')
            result.append(chr((ord(ch) - base - k) % 26 + base))
            key_idx += 1
        else:
            result.append(ch)
    return "".join(result)


def index_of_coincidence(text: str) -> float:
    """
    Menghitung Index of Coincidence (IoC).
    IoC bahasa Inggris ≈ 0.065
    IoC teks random ≈ 0.038
    """
    text = ''.join(c.upper() for c in text if c.isalpha())
    n = len(text)
    if n < 2:
        return 0.0
    freq = Counter(text)
    numerator = sum(f * (f - 1) for f in freq.values())
    denominator = n * (n - 1)
    return numerator / denominator


def kasiski_test(ciphertext: str, max_key_length: int = 10) -> dict[int, float]:
    """
    Kasiski Test: memperkirakan panjang kunci dengan IoC.
    Membagi ciphertext menjadi kolom berdasarkan panjang kunci,
    lalu menghitung IoC rata-rata setiap kolom.
    """
    text = ''.join(c.upper() for c in ciphertext if c.isalpha())
    scores = {}
    for klen in range(2, max_key_length + 1):
        columns = [''.join(text[i::klen]) for i in range(klen)]
        avg_ioc = sum(index_of_coincidence(col) for col in columns) / klen
        scores[klen] = avg_ioc
    return scores


def find_repeated_sequences(ciphertext: str, seq_len: int = 3) -> dict[str, list[int]]:
    """Menemukan urutan berulang dalam ciphertext (Kasiski Examination)."""
    text = ''.join(c.upper() for c in ciphertext if c.isalpha())
    occurrences: dict[str, list[int]] = {}
    for i in range(len(text) - seq_len + 1):
        seq = text[i:i + seq_len]
        occurrences.setdefault(seq, []).append(i)
    return {seq: pos for seq, pos in occurrences.items() if len(pos) > 1}


def gcd_of_spacings(positions: list[int]) -> int:
    """Mencari GCD dari jarak antar posisi berulang."""
    spacings = [positions[i + 1] - positions[i] for i in range(len(positions) - 1)]
    if not spacings:
        return 0
    result = spacings[0]
    for s in spacings[1:]:
        result = math.gcd(result, s)
    return result


# ─────────────────────────────────────────────
# VISUALISASI
# ─────────────────────────────────────────────

ENGLISH_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
    'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
    'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
}


def print_header():
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════╗
║       EKSPERIMEN 1B: VIGENERE CIPHER                 ║
║   Poly-alphabetic Cipher & Kasiski Analysis          ║
╚══════════════════════════════════════════════════════╝""")


def print_section(title: str):
    print(Fore.YELLOW + Style.BRIGHT + f"\n  ┌─ {title}")
    print(Fore.YELLOW + "  │")


def show_vigenere_square(key: str):
    """Menampilkan Vigenere Square (tabula recta) untuk kunci."""
    print_section(f"Vigenere Tableau (untuk kunci '{key}')")
    alphabet = string.ascii_uppercase
    print(Fore.WHITE + "  │       " + "  ".join(alphabet))
    print(Fore.WHITE + "  │  " + "─" * 55)
    for ki, kchar in enumerate(key.upper()):
        k = ord(kchar) - ord('A')
        row = alphabet[k:] + alphabet[:k]
        color = Fore.GREEN if ki % 2 == 0 else Fore.CYAN
        print(color + f"  │  {kchar}  |  " + "  ".join(row))
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_encrypt_decrypt(plaintext: str, key: str):
    """Demonstrasi enkripsi dan dekripsi."""
    ciphertext = vigenere_encrypt(plaintext, key)
    decrypted  = vigenere_decrypt(ciphertext, key)

    print_section("Demonstrasi Enkripsi & Dekripsi")
    print(Fore.WHITE  + f"  │  Plaintext  : {Style.BRIGHT}{plaintext}")
    print(Fore.WHITE  + f"  │  Key        : {Style.BRIGHT}{key}")
    print(Fore.GREEN  + f"  │  Ciphertext : {Style.BRIGHT}{ciphertext}")
    print(Fore.CYAN   + f"  │  Decrypted  : {Style.BRIGHT}{decrypted}")
    print(Fore.YELLOW + "  └" + "─" * 54)

    # Proses per karakter
    print_section("Proses Enkripsi (karakter per karakter)")
    print(Fore.WHITE + f"  │  {'Plain':^6} {'Key':^6} {'P_pos':^7} {'K_pos':^7} {'Sum':^7} {'Cipher':^7}")
    print(Fore.WHITE + f"  │  {'─'*6} {'─'*6} {'─'*7} {'─'*7} {'─'*7} {'─'*7}")
    key_upper = key.upper()
    key_idx = 0
    for i, ch in enumerate(plaintext[:12]):
        if ch.isalpha():
            k_char = key_upper[key_idx % len(key_upper)]
            p_pos = ord(ch.upper()) - ord('A')
            k_pos = ord(k_char) - ord('A')
            c_pos = (p_pos + k_pos) % 26
            c_char = chr(ord('A') + c_pos)
            print(Fore.WHITE + f"  │  {ch:^6} {k_char:^6} {p_pos:^7d} {k_pos:^7d} {c_pos:^7d} {c_char:^7}")
            key_idx += 1
        else:
            print(Fore.WHITE + f"  │  {ch:^6} {'─':^6} {'─':^7} {'─':^7} {'─':^7} {ch:^7}")
    print(Fore.YELLOW + "  └" + "─" * 54)
    return ciphertext


def show_kasiski_analysis(ciphertext: str):
    """Analisis Kasiski Test dan Index of Coincidence."""
    print_section("Kasiski Test - Memperkirakan Panjang Kunci")

    # Tampilkan IoC per kemungkinan panjang kunci
    scores = kasiski_test(ciphertext, max_key_length=12)
    print(Fore.WHITE + f"  │  {'Key Len':^10} {'Avg. IoC':^12} {'Penilaian':^20}")
    print(Fore.WHITE + f"  │  {'─'*10} {'─'*12} {'─'*20}")

    best_klen = max(scores, key=scores.get)
    for klen, ioc in sorted(scores.items()):
        if klen == best_klen:
            color  = Fore.GREEN + Style.BRIGHT
            marker = "◀ PALING MUNGKIN"
        elif ioc > 0.055:
            color  = Fore.CYAN
            marker = "Mirip Eng."
        else:
            color  = Fore.WHITE
            marker = ""
        print(color + f"  │  {klen:^10} {ioc:^12.4f} {marker:^20}")
    print(Fore.YELLOW + "  └" + "─" * 54)

    # Urutan berulang
    print_section("Urutan Berulang dalam Ciphertext (Kasiski Examination)")
    repeats = find_repeated_sequences(ciphertext, seq_len=3)
    if repeats:
        print(Fore.WHITE + f"  │  {'Urutan':^10} {'Posisi':^30} {'GCD':^8}")
        print(Fore.WHITE + f"  │  {'─'*10} {'─'*30} {'─'*8}")
        for seq, positions in list(repeats.items())[:8]:
            g = gcd_of_spacings(positions)
            pos_str = str(positions[:5])
            print(Fore.CYAN + f"  │  {seq:^10} {pos_str:^30} {g:^8}")
    else:
        print(Fore.WHITE + "  │  Tidak ada urutan berulang yang signifikan.")
    print(Fore.YELLOW + "  └" + "─" * 54)

    return best_klen


def show_ioc_comparison(ciphertext: str, plaintext: str):
    """Perbandingan IoC plaintext vs ciphertext."""
    ioc_plain  = index_of_coincidence(plaintext)
    ioc_cipher = index_of_coincidence(ciphertext)
    print_section("Perbandingan Index of Coincidence (IoC)")
    print(Fore.WHITE  + f"  │  IoC Plaintext  : {ioc_plain:.4f}  (Eng. ≈ 0.065)")
    print(Fore.GREEN  + f"  │  IoC Ciphertext : {ioc_cipher:.4f}  (Random ≈ 0.038)")
    if ioc_cipher < 0.052:
        print(Fore.CYAN + "  │  → Cipher terlihat seperti teks acak (baik!)")
    print(Fore.YELLOW + "  └" + "─" * 54)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print_header()

    plaintext = (
        "CRYPTOGRAPHY IS THE PRACTICE AND STUDY OF TECHNIQUES FOR "
        "SECURE COMMUNICATION IN THE PRESENCE OF ADVERSARIAL BEHAVIOR"
    )
    key = "CYBER"

    show_vigenere_square(key)
    ciphertext = show_encrypt_decrypt(plaintext, key)
    show_ioc_comparison(ciphertext, plaintext)
    best_klen = show_kasiski_analysis(ciphertext)

    # Demo dengan kunci yang salah
    print_section("Demonstrasi Dekripsi dengan Kunci Salah")
    wrong_dec = vigenere_decrypt(ciphertext, "WRONG")
    print(Fore.WHITE + f"  │  Kunci Salah  : 'WRONG'")
    print(Fore.RED   + f"  │  Hasil        : {wrong_dec[:60]}...")
    print(Fore.WHITE + f"  │  Kunci Benar  : '{key}'")
    print(Fore.GREEN + f"  │  Hasil        : {vigenere_decrypt(ciphertext, key)[:60]}...")
    print(Fore.YELLOW + "  └" + "─" * 54)

    print(Fore.CYAN + Style.BRIGHT + f"""
  ╔══════════════════════════════════════════════════════╗
  ║  KESIMPULAN                                          ║
  ║  ─────────────────────────────────────────────────  ║
  ║  ✔ Vigenere lebih kuat dari Caesar (poly-alphabet)  ║
  ║  ✔ Key space jauh lebih besar                       ║
  ║  ✘ Kasiski Test dapat memperkirakan panjang kunci   ║
  ║  ✘ Index of Coincidence mengungkap pola             ║
  ║  → Perkiraan panjang kunci terbaik: {best_klen} huruf          
  ╚══════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
