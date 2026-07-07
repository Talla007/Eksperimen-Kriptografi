#!/usr/bin/env python3
"""
=============================================================
  EKSPERIMEN KRIPTOGRAFI - MATA KULIAH KRIPTOGRAFI
  Semester 4 - Peminatan Cyber Security
=============================================================
  Launcher utama untuk semua eksperimen kriptografi.
  Jalankan: python main.py
=============================================================
"""

import os
import sys
import subprocess
import utils

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = RESET = ""
    class Back:
        BLACK = BLUE = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""


BANNER = r"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║    ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗            ║
║   ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗           ║
║   ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║           ║
║   ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║           ║
║   ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝           ║
║    ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝            ║
║                                                                  ║
║         EKSPERIMEN KRIPTOGRAFI - SEMESTER 4                      ║
║              Peminatan Cyber Security                            ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

MENU_ITEMS = [
    ("01", "Kriptografi Klasik", [
        ("1a", "Caesar Cipher + Brute Force Attack",     "01_classical/caesar_cipher.py"),
        ("1b", "Vigenere Cipher + Kasiski Analysis",     "01_classical/vigenere_cipher.py"),
        ("1c", "Playfair Cipher",                        "01_classical/playfair_cipher.py"),
    ]),
    ("02", "Kriptografi Simetris", [
        ("2a", "AES-256 (CBC & CTR Mode)",               "02_symmetric/aes_demo.py"),
        ("2b", "DES & Triple-DES",                       "02_symmetric/des_demo.py"),
    ]),
    ("03", "Kriptografi Asimetris", [
        ("3a", "RSA-2048 Enkripsi & Dekripsi",           "03_asymmetric/rsa_demo.py"),
        ("3b", "Diffie-Hellman Key Exchange",             "03_asymmetric/diffie_hellman.py"),
    ]),
    ("04", "Fungsi Hash & MAC", [
        ("4a", "MD5, SHA-1, SHA-256, SHA-3",             "04_hashing/hash_demo.py"),
        ("4b", "HMAC - Message Authentication Code",     "04_hashing/hmac_demo.py"),
    ]),
    ("05", "Tanda Tangan Digital", [
        ("5a", "RSA-PSS & DSA Digital Signature",        "05_digital_signature/dsa_rsa_sign.py"),
    ]),
    ("06", "Simulasi Serangan", [
        ("6a", "Frequency Analysis Attack",              "06_attacks/frequency_analysis.py"),
        ("6b", "Birthday Attack Simulation",             "06_attacks/birthday_attack.py"),
    ]),
]


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + BANNER)


def print_menu():
    print(Fore.YELLOW + Style.BRIGHT + "  DAFTAR EKSPERIMEN:\n")
    for group_id, group_name, items in MENU_ITEMS:
        print(Fore.GREEN + Style.BRIGHT + f"  ── [{group_id}] {group_name}")
        for code, label, _ in items:
            print(Fore.WHITE + f"       ({code}) {label}")
        print()
    print(Fore.MAGENTA + "  (all) Jalankan semua eksperimen secara berurutan")
    print(Fore.RED + "   (q)  Keluar\n")


def run_script(path: str):
    script_path = os.path.join(os.path.dirname(__file__), path)
    if not os.path.exists(script_path):
        print(Fore.RED + f"  [ERROR] File tidak ditemukan: {script_path}")
        return
    print(Fore.CYAN + Style.BRIGHT + f"\n  ▶  Menjalankan: {path}\n")
    print("─" * 68)
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            check=False,
        )
        if result.returncode != 0:
            print(Fore.RED + f"\n  [WARN] Script selesai dengan kode: {result.returncode}")
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n  [INFO] Eksperimen dihentikan oleh pengguna.")
    print("─" * 68)
    input(Fore.CYAN + "\n  Tekan ENTER untuk kembali ke menu...")


def build_lookup():
    lookup = {}
    for _, _, items in MENU_ITEMS:
        for code, _, path in items:
            lookup[code.lower()] = path
    return lookup


def main():
    lookup = build_lookup()
    all_paths = [path for _, _, items in MENU_ITEMS for _, _, path in items]

    while True:
        clear_screen()
        print_banner()
        print_menu()

        choice = input(Fore.CYAN + Style.BRIGHT + "  Pilih eksperimen: ").strip().lower()

        if choice in ("q", "quit", "exit"):
            print(Fore.YELLOW + "\n  Sampai jumpa! Selamat belajar kriptografi! 🔐\n")
            sys.exit(0)
        elif choice == "all":
            for path in all_paths:
                run_script(path)
        elif choice in lookup:
            run_script(lookup[choice])
        else:
            print(Fore.RED + f"\n  [ERROR] Pilihan '{choice}' tidak valid.")
            input(Fore.CYAN + "  Tekan ENTER untuk melanjutkan...")


if __name__ == "__main__":
    main()
