#!/usr/bin/env python3
"""
=============================================================
  EKSPERIMEN 6B: BIRTHDAY ATTACK SIMULATION
  Mata Kuliah Kriptografi - Semester 4 Cyber Security

  Topik:
    - Birthday Paradox dan probabilitas collision
    - Birthday Attack pada fungsi hash
    - Collision resistance dalam kriptografi
    - Mengapa MD5/SHA-1 rentan dan SHA-256 aman

  Birthday Paradox:
    Dalam kelompok 23 orang, probabilitas ada 2 orang
    dengan ulang tahun sama ≈ 50%.

  Birthday Attack:
    Untuk fungsi hash n-bit:
    - Diperlukan ~2^(n/2) percobaan untuk menemukan collision
    - MD5 (128-bit): ~2^64 ≈ terlalu mudah dengan HW modern
    - SHA-1 (160-bit): 2^80 → ditemukan 2017 (Google SHAttered)
    - SHA-256 (256-bit): ~2^128 → aman saat ini
=============================================================
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import utils  # noqa: sets up UTF-8


import hashlib
import os
import math
import time
import random
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
# BIRTHDAY PARADOX
# ─────────────────────────────────────────────

def birthday_probability(n_people: int, n_days: int = 365) -> float:
    """
    Menghitung probabilitas collision (birthday paradox).
    P(collision) = 1 - P(no collision)
                 = 1 - (N! / (N^k * (N-k)!))
    Approx: P ≈ 1 - e^(-k(k-1)/(2N))
    """
    if n_people > n_days:
        return 1.0
    no_collision = 1.0
    for i in range(n_people):
        no_collision *= (n_days - i) / n_days
    return 1 - no_collision


def birthday_expected_collisions(n_bits: int) -> float:
    """
    Jumlah percobaan yang dibutuhkan untuk menemukan collision
    pada hash n-bit (birthday bound ≈ 2^(n/2)).
    """
    return 2 ** (n_bits / 2)


# ─────────────────────────────────────────────
# SIMULASI COLLISION PADA HASH PENDEK
# ─────────────────────────────────────────────

def truncate_hash(data: bytes, bits: int) -> str:
    """Hash dengan output dipotong ke 'bits' bit (untuk simulasi)."""
    h = hashlib.sha256(data).hexdigest()
    hex_chars = bits // 4
    return h[:hex_chars]


def find_collision_short_hash(bits: int = 16, max_attempts: int = 200_000) -> dict:
    """
    Menemukan collision pada hash yang sangat pendek (untuk demo).
    Menggunakan birthday attack: simpan semua hash yang sudah dibuat.
    """
    seen: dict[str, bytes] = {}
    attempts = 0

    for i in range(max_attempts):
        data   = os.urandom(8) + i.to_bytes(4, 'big')
        digest = truncate_hash(data, bits)
        attempts += 1

        if digest in seen and seen[digest] != data:
            # Collision ditemukan!
            return {
                "found":    True,
                "attempts": attempts,
                "hash":     digest,
                "input1":   seen[digest],
                "input2":   data,
                "bits":     bits,
            }
        seen[digest] = data

    return {"found": False, "attempts": attempts, "bits": bits}


# ─────────────────────────────────────────────
# SIMULASI COLLISION MD5 (demo konseptual)
# ─────────────────────────────────────────────

def find_partial_md5_collision(prefix_bits: int = 20, max_tries: int = 5_000_000) -> dict:
    """
    Menemukan partial collision pada MD5.
    Menemukan dua pesan yang MD5-nya sama pada prefix_bits bit pertama.
    """
    prefix_hex_chars = prefix_bits // 4
    seen: dict[str, bytes] = {}

    for i in range(max_tries):
        data = i.to_bytes(8, 'big')
        h    = hashlib.md5(data).hexdigest()[:prefix_hex_chars]
        if h in seen and seen[h] != data:
            return {
                "found":    True,
                "attempts": i + 1,
                "prefix":   h,
                "bits":     prefix_bits,
                "input1":   seen[h],
                "input2":   data,
                "hash1":    hashlib.md5(seen[h]).hexdigest(),
                "hash2":    hashlib.md5(data).hexdigest(),
            }
        seen[h] = data

    return {"found": False, "attempts": max_tries, "bits": prefix_bits}


# ─────────────────────────────────────────────
# VISUALISASI
# ─────────────────────────────────────────────

def print_header():
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════╗
║       EKSPERIMEN 6B: BIRTHDAY ATTACK SIMULATION      ║
║   Memahami Collision Resistance dalam Hash Function  ║
╚══════════════════════════════════════════════════════╝""")


def print_section(title: str):
    print(Fore.YELLOW + Style.BRIGHT + f"\n  ┌─ {title}")
    print(Fore.YELLOW + "  │")


def show_birthday_paradox():
    """Menampilkan Birthday Paradox dengan tabel probabilitas."""
    print_section("Birthday Paradox (Probabilitas Collision Ulang Tahun)")
    print(Fore.WHITE + f"  │  Berapa orang yang dibutuhkan agar P(2 orang ulang tahun sama) ≥ 50%?")
    print()
    print(Fore.WHITE + f"  │  {'Jumlah Orang':^15} {'Probabilitas':^15} {'Visualisasi'}")
    print(Fore.WHITE + f"  │  {'─'*15} {'─'*15} {'─'*30}")

    milestones = [5, 10, 15, 20, 23, 30, 40, 50, 70, 100, 200, 365]
    for n in milestones:
        p = birthday_probability(n)
        bar_len = int(p * 25)
        bar = "█" * bar_len + "░" * (25 - bar_len)
        if p >= 0.5:
            color = Fore.GREEN
        elif p >= 0.3:
            color = Fore.YELLOW
        else:
            color = Fore.WHITE
        marker = " ◀ ≥50%!" if 0.49 <= p <= 0.55 else ""
        print(color + f"  │  {n:^15} {p*100:^14.1f}% {bar}{marker}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_birthday_bound():
    """Menampilkan birthday bound untuk berbagai ukuran hash."""
    print_section("Birthday Bound: Percobaan untuk Menemukan Collision")
    print(Fore.WHITE + f"  │  Formula: ~2^(n/2) percobaan untuk hash n-bit")
    print()
    print(Fore.WHITE + f"  │  {'Hash':^12} {'Bits':^8} {'Birthday Bound':^20} {'Feasible?':^14} {'Status'}")
    print(Fore.WHITE + f"  │  {'─'*12} {'─'*8} {'─'*20} {'─'*14} {'─'*18}")

    hash_info = [
        ("MD5",      128, "SHAttered-gaya",   Fore.RED,    "✘ TIDAK AMAN"),
        ("SHA-1",    160, "SHAttered 2017",   Fore.RED,    "✘ TIDAK AMAN"),
        ("SHA-224",  224, "Sedang berdebat",  Fore.YELLOW, "⚠ HATI-HATI"),
        ("SHA-256",  256, "Mustahil saat ini", Fore.GREEN,  "✔ AMAN"),
        ("SHA-384",  384, "Sangat mustahil",  Fore.GREEN,  "✔ SANGAT AMAN"),
        ("SHA-512",  512, "Jauh mustahil",    Fore.GREEN,  "✔ SANGAT AMAN"),
        ("SHA3-256", 256, "Mustahil saat ini", Fore.GREEN,  "✔ AMAN"),
        ("BLAKE2b",  256, "Mustahil saat ini", Fore.GREEN,  "✔ AMAN"),
    ]

    for name, bits, feasibility, color, status in hash_info:
        bound = 2 ** (bits // 2)
        if bits <= 160:
            bound_str = f"~2^{bits//2} (dilakukan!)"
        elif bits <= 224:
            bound_str = f"~2^{bits//2} (~1.8×10{bits//2*3//10})"
        else:
            bound_str = f"~2^{bits//2}"
        print(color + f"  │  {name:^12} {bits:^8} {bound_str:^20} {feasibility:^14} {status}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_short_hash_collision():
    """Menemukan collision pada hash 16-bit (demo nyata)."""
    print_section("Demo Nyata: Birthday Attack pada Hash 16-bit")
    print(Fore.WHITE + f"  │  Hash 16-bit = 65.536 kemungkinan output")
    print(Fore.WHITE + f"  │  Birthday bound ≈ √65536 ≈ 256 percobaan")
    print(Fore.WHITE + f"  │  Mencari collision...")

    t0 = time.perf_counter()
    result = find_collision_short_hash(bits=16, max_attempts=100_000)
    t1 = time.perf_counter()

    if result["found"]:
        h1 = truncate_hash(result["input1"], 16)
        h2 = truncate_hash(result["input2"], 16)
        print(Fore.GREEN + f"  │  ✔ Collision ditemukan!")
        print(Fore.WHITE + f"  │    Percobaan ke : {result['attempts']}")
        print(Fore.WHITE + f"  │    Waktu        : {(t1-t0)*1000:.1f} ms")
        print(Fore.WHITE + f"  │    Hash sama    : 0x{result['hash']}")
        print(Fore.CYAN  + f"  │    Input 1      : {result['input1'].hex()}")
        print(Fore.CYAN  + f"  │    Input 2      : {result['input2'].hex()}")
        print(Fore.GREEN + f"  │    Hash(input1) = SHA256[:16bit] = 0x{h1}")
        print(Fore.GREEN + f"  │    Hash(input2) = SHA256[:16bit] = 0x{h2}")
        print(Fore.GREEN + f"  │    Sama?        : {'✔ YA' if h1 == h2 else '✘ TIDAK'}")
    else:
        print(Fore.RED + f"  │  ✘ Collision tidak ditemukan dalam {result['attempts']} percobaan")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_partial_md5_collision():
    """Menampilkan partial collision pada MD5."""
    print_section("Demo: Partial MD5 Collision (20-bit prefix)")
    print(Fore.WHITE + f"  │  Mencari 2 input berbeda dengan MD5 yang sama pada 20-bit pertama...")
    print(Fore.WHITE + f"  │  Birthday bound ≈ 2^10 = 1024 percobaan")

    t0 = time.perf_counter()
    result = find_partial_md5_collision(prefix_bits=20, max_tries=2_000_000)
    t1 = time.perf_counter()

    if result["found"]:
        print(Fore.GREEN + f"  │  ✔ Partial collision ditemukan!")
        print(Fore.WHITE + f"  │    Percobaan ke : {result['attempts']}")
        print(Fore.WHITE + f"  │    Waktu        : {(t1-t0):.3f} detik")
        print(Fore.WHITE + f"  │    Prefix sama  : {result['prefix']}")
        print(Fore.CYAN  + f"  │    Input 1      : {result['input1'].hex()}")
        print(Fore.CYAN  + f"  │    Input 2      : {result['input2'].hex()}")
        print(Fore.GREEN + f"  │    MD5(input1)  : {result['hash1']}")
        print(Fore.GREEN + f"  │    MD5(input2)  : {result['hash2']}")
        same_prefix = result['hash1'][:len(result['prefix'])] == result['hash2'][:len(result['prefix'])]
        print(Fore.GREEN + f"  │    Prefix sama? : {'✔ YA' if same_prefix else '✘ TIDAK'}")
    else:
        print(Fore.RED + f"  │  ✘ Partial collision tidak ditemukan dalam percobaan ini")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_attack_timeline():
    """Kronologi serangan hash terkenal."""
    print_section("Kronologi Serangan Hash Terkenal")
    events = [
        (1993, "MD4",    "Collision ditemukan oleh den Boer & Bosselaers"),
        (1996, "MD5",    "Dobbertin menemukan kelemahan kompresi MD5"),
        (2004, "MD5",    "Wang et al.: full collision dalam hitungan jam"),
        (2005, "SHA-1",  "Wang et al.: theoretical break (2^69)"),
        (2008, "MD5",    "Flame malware pakai MD5 collision untuk cert palsu"),
        (2012, "MD5",    "Flame APT menggunakan chosen-prefix collision"),
        (2017, "SHA-1",  "Google SHAttered: first practical SHA-1 collision"),
        (2019, "SHA-1",  "Chosen-prefix attack lebih efisien ditemukan"),
        (2022, "SHA-256","Tidak ada serangan praktis yang diketahui ✔"),
    ]
    for year, algo, desc in events:
        if algo in ("MD4", "MD5"):
            color = Fore.RED
        elif algo == "SHA-1":
            color = Fore.YELLOW
        else:
            color = Fore.GREEN
        print(color + f"  │  [{year}] {algo:<8} → {desc}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_shattered_demo():
    """Demonstrasi konsep SHAttered (SHA-1 collision)."""
    print_section("Konsep SHAttered Attack (SHA-1 Collision 2017)")
    print(Fore.WHITE + """  │
  │  Tim Google berhasil membuat dua PDF berbeda dengan SHA-1 sama:
  │
  │  shattered-1.pdf ──→ SHA-1 = 38762cf7f55934b34d179ae6a4c80cadccbb7f0a
  │  shattered-2.pdf ──→ SHA-1 = 38762cf7f55934b34d179ae6a4c80cadccbb7f0a
  │                              ↑ SAMA PERSIS!
  │
  │  Biaya komputasi: ~6.500 CPU-years + ~100 GPU-years
  │                    (sekitar $110.000 di cloud waktu itu)
  │
  │  Dampak:
  │  - SSL/TLS certificate dengan SHA-1 → TIDAK AMAN
  │  - Git (versi lama) masih pakai SHA-1 (sudah dipatch)
  │  - Semua CA harus beralih ke SHA-2 atau SHA-3
  │
  │  Pelajaran:
  │  → Jangan gunakan SHA-1 untuk tanda tangan digital!
  │  → Gunakan SHA-256 (minimum) atau SHA-3
  │""")
    print(Fore.YELLOW + "  └" + "─" * 54)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print_header()
    show_birthday_paradox()
    show_birthday_bound()
    show_short_hash_collision()
    show_partial_md5_collision()
    show_attack_timeline()
    show_shattered_demo()

    print(Fore.CYAN + Style.BRIGHT + """
  ╔══════════════════════════════════════════════════════╗
  ║  KESIMPULAN                                          ║
  ║  ─────────────────────────────────────────────────  ║
  ║  ✔ Birthday attack: ~2^(n/2) untuk hash n-bit       ║
  ║  ✔ MD5 (128-bit): 2^64 → sudah tidak aman           ║
  ║  ✔ SHA-1 (160-bit): 2^80 → dibuktikan 2017         ║
  ║  ✔ SHA-256 (256-bit): 2^128 → masih sangat aman    ║
  ║  → Selalu gunakan SHA-256 atau SHA-3-256 minimum    ║
  ║  → Untuk signature: hash length ≥ 2× security level║
  ╚══════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
