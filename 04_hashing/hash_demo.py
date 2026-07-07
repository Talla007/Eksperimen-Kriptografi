#!/usr/bin/env python3
"""
=============================================================
  EKSPERIMEN 4A: FUNGSI HASH KRIPTOGRAFI
  Mata Kuliah Kriptografi - Semester 4 Cyber Security

  Topik:
    - MD5, SHA-1, SHA-256, SHA-512, SHA-3-256
    - Sifat hash: one-way, deterministic, avalanche effect
    - Collision resistance
    - Penggunaan hash dalam keamanan

  Sifat Fungsi Hash yang Baik:
    1. Deterministic         → input sama → output sama
    2. Pre-image Resistance  → tidak bisa balik dari hash ke input
    3. Second Pre-image      → sulit temukan input lain dengan hash sama
    4. Collision Resistance  → sulit temukan 2 input berbeda, hash sama
    5. Avalanche Effect      → perubahan 1 bit input → ~50% bit hash berubah
=============================================================
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import utils  # noqa: sets up UTF-8


import hashlib
import time
import os

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""


# ─────────────────────────────────────────────
# FUNGSI HASH
# ─────────────────────────────────────────────

HASH_ALGORITHMS = {
    "MD5":      hashlib.md5,
    "SHA-1":    hashlib.sha1,
    "SHA-256":  hashlib.sha256,
    "SHA-512":  hashlib.sha512,
    "SHA3-256": hashlib.sha3_256,
    "SHA3-512": hashlib.sha3_512,
    "BLAKE2b":  lambda: hashlib.blake2b(digest_size=32),
}


def compute_hash(data: bytes, algorithm: str) -> str:
    """Menghitung hash dari data dengan algoritma tertentu."""
    h = HASH_ALGORITHMS[algorithm]()
    h.update(data)
    return h.hexdigest()


def bit_string(hex_digest: str) -> str:
    """Konversi hex digest menjadi string bit."""
    return bin(int(hex_digest, 16))[2:].zfill(len(hex_digest) * 4)


def hamming_distance(bits1: str, bits2: str) -> int:
    """Menghitung Hamming distance antara dua string bit."""
    return sum(b1 != b2 for b1, b2 in zip(bits1, bits2))


def measure_avalanche(msg1: bytes, msg2: bytes, algo: str) -> tuple[str, str, int, float]:
    """Mengukur avalanche effect antara dua pesan."""
    h1   = compute_hash(msg1, algo)
    h2   = compute_hash(msg2, algo)
    b1   = bit_string(h1)
    b2   = bit_string(h2)
    dist = hamming_distance(b1, b2)
    pct  = dist / len(b1) * 100
    return h1, h2, dist, pct


# ─────────────────────────────────────────────
# VISUALISASI
# ─────────────────────────────────────────────

def print_header():
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════╗
║       EKSPERIMEN 4A: FUNGSI HASH KRIPTOGRAFI         ║
║   MD5 · SHA-1 · SHA-256 · SHA-512 · SHA-3 · BLAKE2  ║
╚══════════════════════════════════════════════════════╝""")


def print_section(title: str):
    print(Fore.YELLOW + Style.BRIGHT + f"\n  ┌─ {title}")
    print(Fore.YELLOW + "  │")


def show_all_hashes(message: str):
    """Menampilkan hash dari semua algoritma."""
    print_section(f"Perbandingan Algoritma Hash untuk: '{message}'")
    data = message.encode()

    SECURITY_STATUS = {
        "MD5":      (Fore.RED,    "✘ USANG - Collision ditemukan"),
        "SHA-1":    (Fore.RED,    "✘ USANG - SHAttered attack 2017"),
        "SHA-256":  (Fore.GREEN,  "✔ AMAN - Digunakan Bitcoin, TLS"),
        "SHA-512":  (Fore.GREEN,  "✔ AMAN - Output lebih panjang"),
        "SHA3-256": (Fore.GREEN,  "✔ AMAN - Keccak, standar 2015"),
        "SHA3-512": (Fore.GREEN,  "✔ AMAN - Keccak, 512-bit output"),
        "BLAKE2b":  (Fore.GREEN,  "✔ AMAN - Cepat, digunakan di libsodium"),
    }

    print(Fore.WHITE + f"  │  {'Algoritma':<12} {'Output (Hex)':^65} {'Bits':^6} {'Status'}")
    print(Fore.WHITE + f"  │  {'─'*12} {'─'*65} {'─'*6} {'─'*36}")
    for algo in HASH_ALGORITHMS:
        t0 = time.perf_counter()
        h  = compute_hash(data, algo)
        t1 = time.perf_counter()
        bits = len(h) * 4
        color, status = SECURITY_STATUS[algo]
        print(color + f"  │  {algo:<12} {h[:64]:^65} {bits:^6} {status}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_determinism(message: str):
    """Menampilkan sifat deterministik hash."""
    print_section("Sifat 1: Deterministic (Input Sama → Output Sama)")
    data = message.encode()
    results = [compute_hash(data, "SHA-256") for _ in range(3)]
    for i, h in enumerate(results, 1):
        print(Fore.CYAN + f"  │  Percobaan {i}: {h}")
    all_same = len(set(results)) == 1
    print(Fore.GREEN + f"  │  → Semua sama? {'✔ YA' if all_same else '✘ TIDAK'}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_avalanche(message: str):
    """Menampilkan avalanche effect."""
    print_section("Sifat 2: Avalanche Effect (Perubahan 1 Bit = ~50% Output Berubah)")

    data1 = message.encode()
    # Ubah 1 karakter terakhir
    data2 = (message[:-1] + chr(ord(message[-1]) ^ 1)).encode()

    print(Fore.WHITE + f"  │  Input 1 : '{data1.decode()}'")
    print(Fore.WHITE + f"  │  Input 2 : '{data2.decode()}'  (1 karakter berbeda)")
    print()
    print(Fore.WHITE + f"  │  {'Algo':<10} {'Hash 1':<35} {'Hash 2':<35} {'Δbits':>6} {'%':>6}")
    print(Fore.WHITE + f"  │  {'─'*10} {'─'*35} {'─'*35} {'─'*6} {'─'*6}")

    for algo in ["MD5", "SHA-256", "SHA3-256"]:
        h1, h2, dist, pct = measure_avalanche(data1, data2, algo)
        color = Fore.GREEN if 40 <= pct <= 60 else Fore.YELLOW
        print(color + f"  │  {algo:<10} {h1[:32]:<35} {h2[:32]:<35} {dist:>6} {pct:>5.1f}%")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_hash_fixed_length():
    """Menampilkan output hash selalu panjang tetap."""
    print_section("Sifat 3: Fixed-Length Output (Berapapun Input-nya)")
    inputs = [
        b"a",
        b"Hello",
        b"Kriptografi Semester 4 Peminatan Cybersecurity Universitas",
        os.urandom(10000),  # 10KB data acak
    ]
    print(Fore.WHITE + f"  │  {'Input (truncated)':<45} {'Input Len':^12} {'SHA-256 Hash'}")
    print(Fore.WHITE + f"  │  {'─'*45} {'─'*12} {'─'*64}")
    for data in inputs:
        label = data.decode('utf-8', 'replace')[:42] + ("..." if len(data) > 42 else "")
        if not all(32 <= b < 127 for b in data):
            label = f"[{len(data)} byte random data]"
        h = compute_hash(data, "SHA-256")
        print(Fore.CYAN + f"  │  {label:<45} {len(data):^12} {h}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_preimage_resistance():
    """Menampilkan one-way (pre-image resistance)."""
    print_section("Sifat 4: One-Way / Pre-image Resistance")
    secret   = b"password123"
    h        = compute_hash(secret, "SHA-256")
    print(Fore.WHITE + f"  │  Input (plaintext) : {secret.decode()}")
    print(Fore.GREEN + f"  │  SHA-256 Hash       : {h}")
    print(Fore.WHITE + f"\n  │  Dari hash di atas, kita TIDAK BISA menghitung balik input-nya.")
    print(Fore.RED   + f"  │  Satu-satunya cara: brute force atau dictionary attack")

    # Demonstrasi betapa lamanya brute force
    guesses = ["password", "123456", "qwerty", "password123", "secret"]
    print(Fore.WHITE + f"\n  │  Simulasi Dictionary Attack:")
    print(Fore.WHITE + f"  │  {'Tebakan':<20} {'Hash':<66} {'Match?'}")
    print(Fore.WHITE + f"  │  {'─'*20} {'─'*66} {'─'*8}")
    for guess in guesses:
        gh = compute_hash(guess.encode(), "SHA-256")
        match = gh == h
        color = Fore.GREEN if match else Fore.WHITE
        print(color + f"  │  {guess:<20} {gh[:64]:<66} {'✔ KETEMU!' if match else '✘'}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_performance():
    """Benchmark performa hash algorithms."""
    print_section("Benchmark Performa Hash (1 MB Data)")
    data = os.urandom(1024 * 1024)  # 1MB data acak
    print(Fore.WHITE + f"  │  {'Algoritma':<12} {'Waktu':^12} {'Kecepatan':^15} {'Output':^8}")
    print(Fore.WHITE + f"  │  {'─'*12} {'─'*12} {'─'*15} {'─'*8}")
    for algo in HASH_ALGORITHMS:
        t0 = time.perf_counter()
        h  = compute_hash(data, algo)
        t1 = time.perf_counter()
        elapsed  = t1 - t0
        speed_mb = 1 / elapsed
        print(Fore.CYAN + f"  │  {algo:<12} {elapsed*1000:>8.2f} ms   {speed_mb:>10.1f} MB/s   {len(h)*4:>4} bit")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_hash_applications():
    """Menampilkan penggunaan nyata hash."""
    print_section("Aplikasi Nyata Fungsi Hash")
    apps = [
        ("Password Storage",    "SHA-256(password+salt) → simpan di DB"),
        ("File Integrity",      "Checksum download = SHA-256 file asli"),
        ("Digital Signature",   "Sign(SHA256(pesan)) dengan kunci privat"),
        ("Blockchain",          "SHA-256 untuk chaining blok Bitcoin"),
        ("Certificate (TLS)",   "SHA-256 dalam X.509 sertifikat SSL/TLS"),
        ("Git Commit Hash",     "SHA-1 (legacy) / SHA-256 untuk content"),
        ("HMAC",                "HMAC = hash(key || message) untuk MAC"),
    ]
    for use_case, detail in apps:
        print(Fore.WHITE + f"  │  {Fore.GREEN}▸ {Fore.CYAN}{use_case:<25}{Fore.WHITE} {detail}")
    print(Fore.YELLOW + "  └" + "─" * 54)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print_header()

    message = "Kriptografi Semester 4"

    show_all_hashes(message)
    show_determinism(message)
    show_avalanche(message)
    show_hash_fixed_length()
    show_preimage_resistance()
    show_performance()
    show_hash_applications()

    print(Fore.CYAN + Style.BRIGHT + """
  ╔══════════════════════════════════════════════════════╗
  ║  KESIMPULAN                                          ║
  ║  ─────────────────────────────────────────────────  ║
  ║  ✘ MD5 dan SHA-1 sudah TIDAK AMAN (collision)       ║
  ║  ✔ Gunakan SHA-256 / SHA-3-256 / BLAKE2b            ║
  ║  ✔ Hash: one-way, deterministic, avalanche effect   ║
  ║  ⚠ Hash bukan enkripsi! Tidak bisa di-dekripsi      ║
  ║  ⚠ Untuk password: gunakan bcrypt/Argon2, bukan SHA ║
  ╚══════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
