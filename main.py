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
║    ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗             ║
║   ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗            ║
║   ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║            ║
║   ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║            ║
║   ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝            ║
║    ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝             ║
║                                                                  ║
║         EKSPERIMEN KRIPTOGRAFI - SEMESTER 4                      ║
║              Peminatan Cyber Security                            ║
║         Anggota Kelompok:                                        ║
║         1. Atalla Ahsan Indrayana - 2410511039                   ║
║         2. Athallah Abrar Duano - 2410511046                     ║
║         3. Sulthon Daffa Arrafi - 2410511061                     ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

MENU_ITEMS = [
    ("1", "Kriptografi Klasik", [
        ("1a", "Caesar Cipher + Brute Force Attack",     "01_classical/caesar_cipher.py"),
        ("1b", "Vigenere Cipher + Kasiski Analysis",     "01_classical/vigenere_cipher.py"),
        ("1c", "Playfair Cipher",                        "01_classical/playfair_cipher.py"),
    ]),
    ("2", "Kriptografi Simetris", [
        ("2a", "AES-256 (CBC & CTR Mode)",               "02_symmetric/aes_demo.py"),
        ("2b", "DES & Triple-DES",                       "02_symmetric/des_demo.py"),
    ]),
    ("3", "Kriptografi Asimetris", [
        ("3a", "RSA-2048 Enkripsi & Dekripsi",           "03_asymmetric/rsa_demo.py"),
        ("3b", "Diffie-Hellman Key Exchange",             "03_asymmetric/diffie_hellman.py"),
    ]),
    ("4", "Fungsi Hash & MAC", [
        ("4a", "MD5, SHA-1, SHA-256, SHA-3",             "04_hashing/hash_demo.py"),
        ("4b", "HMAC - Message Authentication Code",     "04_hashing/hmac_demo.py"),
    ]),
    ("5", "Tanda Tangan Digital", [
        ("5a", "RSA-PSS & DSA Digital Signature",        "05_digital_signature/dsa_rsa_sign.py"),
    ]),
    ("6", "Simulasi Serangan", [
        ("6a", "Frequency Analysis Attack",              "06_attacks/frequency_analysis.py"),
        ("6b", "Birthday Attack Simulation",             "06_attacks/birthday_attack.py"),
    ]),
    ("7", "Aplikasi Praktis", [
        ("7a", "CRUD Catatan Aman (AES-256 + HMAC)",     "07_secure_crud/secure_crud.py"),
    ]),
]


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + BANNER)


def print_main_menu():
    print(Fore.YELLOW + Style.BRIGHT + "  ╔══════════════════════════════════════════════════════════════════╗")
    print(Fore.YELLOW + Style.BRIGHT + "  ║                       MENU KATEGORI UTAMA                        ║")
    print(Fore.YELLOW + Style.BRIGHT + "  ╚══════════════════════════════════════════════════════════════════╝")
    for group_id, group_name, items in MENU_ITEMS:
        sub_count = len(items)
        print(Fore.GREEN + Style.BRIGHT + f"   [{group_id}] " + Fore.WHITE + f"{group_name:<38}" + Fore.CYAN + f"({sub_count} Eksperimen)")
    print(Fore.YELLOW + "  ────────────────────────────────────────────────────────────────────")
    print(Fore.MAGENTA + Style.BRIGHT + "   [A] Jalankan Semua Eksperimen")
    print(Fore.RED + Style.BRIGHT + "   [Q] Keluar dari Program\n")


def print_submenu(group_id: str, group_name: str, items: list):
    print(Fore.YELLOW + Style.BRIGHT + f"  ╔══════════════════════════════════════════════════════════════════╗")
    print(Fore.YELLOW + Style.BRIGHT + f"  ║   KATEGORI [{group_id}]: {group_name.upper():<46} ║")
    print(Fore.YELLOW + Style.BRIGHT + f"  ╚══════════════════════════════════════════════════════════════════╝")
    for code, label, _ in items:
        print(Fore.GREEN + Style.BRIGHT + f"   ({code}) " + Fore.WHITE + f"{label}")
    print(Fore.YELLOW + "  ────────────────────────────────────────────────────────────────────")
    print(Fore.CYAN + Style.BRIGHT + "   [B] Kembali ke Menu Utama")
    print(Fore.RED + Style.BRIGHT + "   [Q] Keluar dari Program\n")


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
    groups = {group_id: (group_name, items) for group_id, group_name, items in MENU_ITEMS}
    all_paths = [path for _, _, items in MENU_ITEMS for _, _, path in items]

    current_group = None

    while True:
        clear_screen()
        print_banner()

        if current_group is None:
            print_main_menu()
            choice = input(Fore.CYAN + Style.BRIGHT + "  Pilih Kategori (1-7) atau opsi lainnya: ").strip().lower()

            if choice in ("q", "quit", "exit"):
                print(Fore.YELLOW + "\n  Terima kasih telah menggunakan program ini. Sampai jumpa!\n")
                sys.exit(0)
            elif choice == "a":
                print(Fore.YELLOW + "\n  Memulai eksekusi semua eksperimen...")
                for path in all_paths:
                    run_script(path)
            elif choice in groups:
                current_group = choice
            else:
                print(Fore.RED + f"\n  [ERROR] Pilihan '{choice}' tidak valid. Silakan pilih 1-7, A, atau Q.")
                input(Fore.CYAN + "  Tekan ENTER untuk melanjutkan...")
        else:
            group_name, items = groups[current_group]
            print_submenu(current_group, group_name, items)
            sub_lookup = {code.lower(): path for code, label, path in items}
            
            choice = input(Fore.CYAN + Style.BRIGHT + f"  Pilih Eksperimen ({items[0][0]}-{items[-1][0]}) atau opsi lainnya: ").strip().lower()

            if choice in ("q", "quit", "exit"):
                print(Fore.YELLOW + "\n  Terima kasih telah menggunakan program ini. Sampai jumpa!\n")
                sys.exit(0)
            elif choice == "b":
                current_group = None
            elif choice in sub_lookup:
                run_script(sub_lookup[choice])
            elif choice in groups:
                # Allow directly switching to another main category
                current_group = choice
            else:
                valid_codes = ", ".join([code for code, _, _ in items])
                print(Fore.RED + f"\n  [ERROR] Pilihan '{choice}' tidak valid. Silakan masukkan {valid_codes}, B, atau Q.")
                input(Fore.CYAN + "  Tekan ENTER untuk melanjutkan...")


if __name__ == "__main__":
    main()
