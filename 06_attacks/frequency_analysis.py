#!/usr/bin/env python3
"""
=============================================================
  EKSPERIMEN 6A: FREQUENCY ANALYSIS ATTACK
  Mata Kuliah Kriptografi - Semester 4 Cyber Security

  Topik:
    - Analisis frekuensi huruf pada ciphertext
    - Menyerang monoalphabetic substitution cipher
    - Teknik kriptanalisis klasik (Al-Kindi, abad ke-9)
    - Index of Coincidence untuk deteksi cipher type

  Frekuensi huruf bahasa Inggris:
    E(12.7%) > T(9.1%) > A(8.2%) > O(7.5%) > I(7.0%)
    Frekuensi huruf bahasa Indonesia:
    A(20.8%) > N(9.4%) > I(7.2%) > E(5.9%) > T(5.4%)
=============================================================
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import utils  # noqa: sets up UTF-8


import re
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
# FREKUENSI HURUF
# ─────────────────────────────────────────────

# Frekuensi huruf bahasa Inggris (%)
ENGLISH_FREQ: dict[str, float] = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
    'N': 6.75,  'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
    'L': 4.03,  'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
    'F': 2.23,  'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29,
    'V': 0.98,  'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07,
}

# Frekuensi huruf bahasa Indonesia (%)
INDONESIAN_FREQ: dict[str, float] = {
    'A': 20.80, 'N': 9.40, 'I': 7.20, 'E': 5.90, 'T': 5.40,
    'R': 5.10,  'U': 4.80, 'K': 4.50, 'S': 3.80, 'G': 3.60,
    'D': 3.10,  'M': 3.00, 'L': 2.90, 'P': 2.70, 'B': 2.50,
    'O': 2.40,  'H': 2.20, 'Y': 1.80, 'J': 1.50, 'C': 1.40,
    'W': 1.30,  'F': 0.80, 'V': 0.30, 'Z': 0.10, 'Q': 0.05, 'X': 0.03,
}


def count_frequency(text: str) -> dict[str, float]:
    """Menghitung frekuensi huruf dalam teks (%)."""
    text_upper = ''.join(c.upper() for c in text if c.isalpha())
    n = len(text_upper)
    if n == 0:
        return {}
    freq = Counter(text_upper)
    return {ch: (count / n * 100) for ch, count in freq.most_common()}


def caesar_encrypt(plaintext: str, key: int) -> str:
    """Caesar Cipher untuk membuat ciphertext target."""
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + key) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def caesar_decrypt(ciphertext: str, key: int) -> str:
    return caesar_encrypt(ciphertext, -key)


def score_text(text: str, lang_freq: dict[str, float] = ENGLISH_FREQ) -> float:
    """Memberikan skor kemiripan teks dengan bahasa referensi."""
    text_upper = text.upper()
    return sum(lang_freq.get(ch, 0) for ch in text_upper if ch.isalpha())


def frequency_attack_caesar(ciphertext: str) -> tuple[int, str, float]:
    """
    Menyerang Caesar Cipher dengan frequency analysis.
    Mencoba semua 26 kunci dan memilih yang paling mungkin.
    """
    best_key, best_text, best_score = 0, ciphertext, 0.0
    for key in range(26):
        candidate = caesar_decrypt(ciphertext, key)
        score = score_text(candidate)
        if score > best_score:
            best_key, best_text, best_score = key, candidate, score
    return best_key, best_text, best_score


def build_substitution_guess(cipher_freq: dict[str, float],
                              ref_freq: dict[str, float] = ENGLISH_FREQ) -> dict[str, str]:
    """
    Membuat tebakan kunci substitusi berdasarkan ranking frekuensi.
    Huruf ciphertext terhuruf → dicocokkan dengan huruf terhuruf bahasa referensi.
    """
    cipher_sorted = [k for k, _ in sorted(cipher_freq.items(), key=lambda x: -x[1])]
    ref_sorted    = [k for k, _ in sorted(ref_freq.items(), key=lambda x: -x[1])]
    mapping = {}
    for i, c in enumerate(cipher_sorted):
        if i < len(ref_sorted):
            mapping[c] = ref_sorted[i]
    return mapping


def apply_substitution(ciphertext: str, mapping: dict[str, str]) -> str:
    """Menerapkan mapping substitusi pada ciphertext."""
    result = []
    for ch in ciphertext:
        upper = ch.upper()
        if upper in mapping:
            dec = mapping[upper]
            result.append(dec if ch.isupper() else dec.lower())
        else:
            result.append(ch)
    return "".join(result)


def index_of_coincidence(text: str) -> float:
    """Menghitung Index of Coincidence."""
    text = ''.join(c.upper() for c in text if c.isalpha())
    n = len(text)
    if n < 2:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


# ─────────────────────────────────────────────
# VISUALISASI
# ─────────────────────────────────────────────

def print_header():
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════╗
║      EKSPERIMEN 6A: FREQUENCY ANALYSIS ATTACK        ║
║   Kriptanalisis Cipher Klasik Tanpa Mengetahui Kunci ║
╚══════════════════════════════════════════════════════╝""")


def print_section(title: str):
    print(Fore.YELLOW + Style.BRIGHT + f"\n  ┌─ {title}")
    print(Fore.YELLOW + "  │")


def show_english_frequency():
    """Menampilkan frekuensi huruf bahasa Inggris sebagai bar chart ASCII."""
    print_section("Distribusi Frekuensi Huruf Bahasa Inggris (Referensi)")
    MAX_BAR = 30
    sorted_freq = sorted(ENGLISH_FREQ.items(), key=lambda x: -x[1])
    for letter, pct in sorted_freq[:15]:
        bar_len = int(pct / 12.7 * MAX_BAR)
        bar     = "█" * bar_len
        color   = Fore.GREEN if letter in "ETAOIN" else Fore.CYAN
        print(color + f"  │  {letter}  {bar:<{MAX_BAR}} {pct:.2f}%")
    print(Fore.WHITE + f"  │  ... (dst. hingga Z)")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_cipher_frequency(ciphertext: str):
    """Menampilkan frekuensi huruf dalam ciphertext."""
    print_section("Frekuensi Huruf dalam Ciphertext")
    freq = count_frequency(ciphertext)
    MAX_BAR = 30
    max_pct = max(freq.values()) if freq else 1

    for letter, pct in list(freq.items())[:15]:
        bar_len = int(pct / max_pct * MAX_BAR)
        bar     = "░" * bar_len
        print(Fore.CYAN + f"  │  {letter}  {bar:<{MAX_BAR}} {pct:.2f}%")
    if len(freq) > 15:
        print(Fore.WHITE + f"  │  ...")
    print(Fore.YELLOW + "  └" + "─" * 54)
    return freq


def show_caesar_attack(ciphertext: str, true_key: int):
    """Demonstrasi frequency analysis attack pada Caesar Cipher."""
    print_section("Frequency Analysis Attack pada Caesar Cipher")
    print(Fore.WHITE + f"  │  Ciphertext (first 60 chars): '{ciphertext[:60]}...'")
    print(Fore.WHITE + f"  │  Kunci sebenarnya (tersembunyi): {true_key}")
    print()
    print(Fore.WHITE + f"  │  Mencoba semua 26 kemungkinan kunci...")
    print(Fore.WHITE + f"  │  {'Key':^5} {'Score':^8} {'Plaintext (50 char)':^52}")
    print(Fore.WHITE + f"  │  {'─'*5} {'─'*8} {'─'*52}")

    results = []
    for k in range(26):
        candidate = caesar_decrypt(ciphertext, k)
        sc        = score_text(candidate)
        results.append((k, sc, candidate))

    results.sort(key=lambda x: -x[1])
    best_key, best_score, best_text = results[0]

    for k, sc, text in results[:5]:
        marker = Fore.GREEN + Style.BRIGHT + " ◀ TERBAIK" if k == best_key else ""
        color  = Fore.GREEN if k == best_key else Fore.WHITE
        print(color + f"  │  {k:^5} {sc:^8.2f} '{text[:50]}'")
        if marker:
            print(Fore.WHITE + "  │           " + Fore.GREEN + Style.BRIGHT + " ↑ Kunci Ditemukan!")

    print(Fore.GREEN + Style.BRIGHT + f"\n  │  ✔ Kunci ditemukan: {best_key}")
    print(Fore.GREEN + f"  │  ✔ Plaintext: '{best_text[:60]}...'")
    print(Fore.WHITE + f"  │  ✔ Kunci asli: {true_key} → {'Benar!' if best_key == true_key else 'Salah.'}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def vigenere_encrypt_local(plaintext: str, key: str) -> str:
    """Vigenere Cipher lokal (tidak perlu import modul lain)."""
    key = key.upper()
    result, key_idx = [], 0
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            k = ord(key[key_idx % len(key)]) - ord('A')
            result.append(chr((ord(ch) - base + k) % 26 + base))
            key_idx += 1
        else:
            result.append(ch)
    return "".join(result)


def show_ioc_classification(texts: list[tuple[str, str]]):
    """Mengklasifikasi jenis cipher berdasarkan IoC."""
    print_section("Index of Coincidence untuk Klasifikasi Tipe Cipher")
    print(Fore.WHITE + "  │  IoC bahasa Inggris = ~0.065")
    print(Fore.WHITE + "  │  IoC random/vigenere = ~0.038")
    print()
    print(Fore.WHITE + f"  │  {'Tipe':<28} {'IoC':^10} {'Interpretasi'}")
    print(Fore.WHITE + f"  │  {'─'*28} {'─'*10} {'─'*30}")

    for label, text in texts:
        ioc = index_of_coincidence(text)
        if ioc > 0.060:
            interpretation = "Monoalphabetic / Plaintext"
            color = Fore.GREEN
        elif ioc > 0.045:
            interpretation = "Mungkin Caesar/Simple subst."
            color = Fore.YELLOW
        else:
            interpretation = "Poly-alphabetic / Random"
            color = Fore.RED
        print(color + f"  │  {label:<28} {ioc:^10.4f} {interpretation}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_substitution_attack(ciphertext: str):
    """Demonstrasi frequency attack pada simple substitution."""
    print_section("Partial Substitution Attack (Ranking Frekuensi)")
    cipher_freq = count_frequency(ciphertext)
    mapping     = build_substitution_guess(cipher_freq)
    partial     = apply_substitution(ciphertext[:120], mapping)

    print(Fore.WHITE + f"  │  Mapping frekuensi (cipher → plaintext guess):")
    items = list(mapping.items())
    for i in range(0, min(10, len(items)), 5):
        row = "   ".join([f"{a}→{b}" for a, b in items[i:i+5]])
        print(Fore.CYAN + f"  │    {row}")
    print()
    print(Fore.WHITE + f"  │  Ciphertext (120 chars):")
    print(Fore.RED   + f"  │    {ciphertext[:120]}")
    print(Fore.WHITE + f"  │  Partial Decryption (frekuensi saja, belum sempurna):")
    print(Fore.YELLOW + f"  │    {partial}")
    print(Fore.WHITE + f"  │  → Analisis lanjutan dibutuhkan (bigram, konteks, dsb.)")
    print(Fore.YELLOW + "  └" + "─" * 54)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

SAMPLE_TEXT = (
    "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG "
    "IN CRYPTOGRAPHY WE STUDY THE ART AND SCIENCE OF COMMUNICATING "
    "IN THE PRESENCE OF ADVERSARIAL BEHAVIOR THE GOAL IS TO KEEP "
    "MESSAGES CONFIDENTIAL WHILE ALSO ENSURING THEIR INTEGRITY "
    "AND AUTHENTICITY IN THE MODERN WORLD CRYPTOGRAPHY IS EVERYWHERE "
    "FROM HTTPS TO END TO END ENCRYPTED MESSAGING APPLICATIONS"
)


def main():
    print_header()
    true_key   = 17
    ciphertext = caesar_encrypt(SAMPLE_TEXT, true_key)

    show_english_frequency()
    cipher_freq = show_cipher_frequency(ciphertext)
    show_caesar_attack(ciphertext, true_key)

    # IoC comparison
    import hashlib
    random_text = hashlib.sha256(b"random").hexdigest().upper() * 5
    vig_ct = vigenere_encrypt_local(SAMPLE_TEXT, "CYBER")

    texts = [
        ("Plaintext (English)",        SAMPLE_TEXT),
        ("Caesar Cipher (key=17)",     ciphertext),
        ("Vigenere Cipher (key=CYBER)", vig_ct),
        ("Random/Noise (SHA256 hex)",  random_text[:200]),
    ]

    show_ioc_classification(texts)
    show_substitution_attack(ciphertext)

    print(Fore.CYAN + Style.BRIGHT + """
  ╔══════════════════════════════════════════════════════╗
  ║  KESIMPULAN                                          ║
  ║  ─────────────────────────────────────────────────  ║
  ║  ✔ Frequency analysis efektif pada cipher klasik    ║
  ║  ✔ Caesar Cipher dapat di-crack dalam milidetik     ║
  ║  ✔ IoC membantu mengidentifikasi tipe cipher        ║
  ║  ✘ Tidak efektif pada cipher modern (AES, dll.)     ║
  ║  → Kriptografi modern dirancang agar frekuensi      ║
  ║    ciphertext seragam (tidak bisa dianalisis)       ║
  ╚══════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()


