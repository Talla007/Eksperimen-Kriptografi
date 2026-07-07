#!/usr/bin/env python3
"""
=============================================================
  EKSPERIMEN 7A: SECURE CRUD (Catatan Aman)
  Mata Kuliah Kriptografi - Semester 4 Cyber Security
=============================================================
  Aplikasi CRUD praktis yang mengintegrasikan:
    - KDF (PBKDF2) untuk derivasi kunci dari Master Password
    - AES-256-CBC untuk enkripsi konten catatan
    - HMAC-SHA256 untuk verifikasi integritas data
    - Penyimpanan file terstruktur JSON
=============================================================
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import utils  # noqa: sets up UTF-8

import os
import json
import hmac
import hashlib
from tabulate import tabulate
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""


DB_FILE = os.path.join(os.path.dirname(__file__), "secure_notes.json")
PBKDF2_ITERATIONS = 20_000
KEY_LEN = 32  # 256-bit keys
VALIDATOR_MSG = b"SECURE_DATABASE_VALIDATOR"


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """
    Menurunkan dua kunci dari Master Password menggunakan PBKDF2:
    - 32 byte pertama: Kunci AES-256 untuk Enkripsi
    - 32 byte kedua: Kunci HMAC-SHA256 untuk Integritas
    """
    derived = PBKDF2(password, salt, dkLen=KEY_LEN * 2, count=PBKDF2_ITERATIONS)
    aes_key = derived[:KEY_LEN]
    hmac_key = derived[KEY_LEN:]
    return aes_key, hmac_key


def encrypt_content(content: str, aes_key: bytes) -> tuple[bytes, bytes]:
    """Mengenkripsi teks menggunakan AES-256-CBC dengan PKCS7 padding."""
    iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(content.encode('utf-8'), AES.block_size))
    return ciphertext, iv


def decrypt_content(ciphertext: bytes, aes_key: bytes, iv: bytes) -> str:
    """Mendekripsi teks menggunakan AES-256-CBC dengan PKCS7 padding."""
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')


def calculate_hmac(note_id: str, title: str, ciphertext: bytes, iv: bytes, hmac_key: bytes) -> str:
    """Menghitung HMAC-SHA256 untuk menjamin integritas catatan."""
    h = hmac.new(hmac_key, digestmod=hashlib.sha256)
    h.update(note_id.encode('utf-8'))
    h.update(title.encode('utf-8'))
    h.update(ciphertext)
    h.update(iv)
    return h.hexdigest()


def load_db() -> dict:
    """Memuat database dari berkas JSON."""
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_db(db: dict):
    """Menyimpan database ke berkas JSON."""
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=4)


def setup_new_db() -> tuple[bytes, bytes]:
    """Menginisialisasi database baru dengan Master Password baru."""
    print(Fore.YELLOW + "  Database baru dideteksi. Silakan atur Master Password Anda.")
    while True:
        password = input(Fore.CYAN + "  Masukkan Master Password baru: ").strip()
        if not password:
            print(Fore.RED + "  [ERROR] Password tidak boleh kosong.")
            continue
        confirm = input(Fore.CYAN + "  Konfirmasi Master Password    : ").strip()
        if password != confirm:
            print(Fore.RED + "  [ERROR] Password tidak cocok. Silakan coba lagi.")
            continue
        break

    salt = os.urandom(16)
    aes_key, hmac_key = derive_keys(password, salt)

    # Buat validator HMAC untuk memverifikasi password di kemudian hari
    validator_hmac = hmac.new(hmac_key, VALIDATOR_MSG, hashlib.sha256).hexdigest()

    db = {
        "salt": salt.hex(),
        "validator": validator_hmac,
        "notes": []
    }
    save_db(db)
    print(Fore.GREEN + "  [SUCCESS] Database berhasil dibuat dan dikunci.")
    return aes_key, hmac_key


def authenticate_user() -> tuple[bytes, bytes]:
    """Meminta password pengguna dan memverifikasi terhadap validator database."""
    db = load_db()
    if not db:
        return setup_new_db()

    salt = bytes.fromhex(db["salt"])
    stored_validator = db["validator"]

    print(Fore.YELLOW + "  Database terdeteksi. Masukkan Master Password untuk membuka data.")
    attempts = 3
    while attempts > 0:
        password = input(Fore.CYAN + f"  Master Password ({attempts} kesempatan sisa): ").strip()
        aes_key, hmac_key = derive_keys(password, salt)
        computed_validator = hmac.new(hmac_key, VALIDATOR_MSG, hashlib.sha256).hexdigest()

        if hmac.compare_digest(stored_validator, computed_validator):
            print(Fore.GREEN + "  [SUCCESS] Akses diberikan. Kunci enkripsi berhasil diturunkan.")
            return aes_key, hmac_key
        else:
            print(Fore.RED + "  [ERROR] Master Password salah.")
            attempts -= 1

    print(Fore.RED + "\n  [FATAL] Terlalu banyak percobaan salah. Aplikasi dihentikan.")
    _sys.exit(1)


def create_note(aes_key: bytes, hmac_key: bytes):
    """Menambahkan catatan baru (Create)."""
    print(Fore.YELLOW + Style.BRIGHT + "\n  ┌─ TAMBAH CATATAN BARU")
    title = input(Fore.CYAN + "  │  Judul catatan: ").strip()
    if not title:
        print(Fore.RED + "  │  [ERROR] Judul tidak boleh kosong.")
        print(Fore.YELLOW + "  └" + "─" * 54)
        return

    content = input(Fore.CYAN + "  │  Isi catatan  : ").strip()
    
    # Generate unique ID
    db = load_db()
    if db["notes"]:
        next_id = str(max(int(note["id"]) for note in db["notes"]) + 1)
    else:
        next_id = "1"

    ciphertext, iv = encrypt_content(content, aes_key)
    note_hmac = calculate_hmac(next_id, title, ciphertext, iv, hmac_key)

    new_note = {
        "id": next_id,
        "title": title,
        "ciphertext": ciphertext.hex(),
        "iv": iv.hex(),
        "hmac": note_hmac
    }

    db["notes"].append(new_note)
    save_db(db)
    print(Fore.GREEN + "  │  [SUCCESS] Catatan berhasil dienkripsi dan disimpan.")
    print(Fore.YELLOW + "  └" + "─" * 54)


def list_notes(aes_key: bytes, hmac_key: bytes) -> list:
    """Mendapatkan daftar catatan dengan pemeriksaan integritas (Read)."""
    db = load_db()
    if not db["notes"]:
        print(Fore.YELLOW + "\n  [INFO] Tidak ada catatan yang tersimpan.")
        return []

    table_data = []
    notes_list = []
    
    for note in db["notes"]:
        note_id = note["id"]
        title = note["title"]
        ciphertext = bytes.fromhex(note["ciphertext"])
        iv = bytes.fromhex(note["iv"])
        stored_hmac = note["hmac"]

        # Verifikasi integritas
        computed_hmac = calculate_hmac(note_id, title, ciphertext, iv, hmac_key)
        
        if hmac.compare_digest(stored_hmac, computed_hmac):
            integrity_status = Fore.GREEN + "Valid"
            is_valid = True
        else:
            integrity_status = Fore.RED + "TERGANGGU (Tampered)"
            is_valid = False

        table_data.append([note_id, title, integrity_status])
        notes_list.append((note, is_valid))

    print(Fore.YELLOW + Style.BRIGHT + "\n  DAFTAR CATATAN TERSEDIA:")
    print(tabulate(table_data, headers=["ID", "Judul", "Status Integritas"], tablefmt="fancy_grid"))
    return notes_list


def read_note_content(aes_key: bytes, hmac_key: bytes):
    """Mendekripsi dan menampilkan konten catatan terpilih (Read)."""
    notes = list_notes(aes_key, hmac_key)
    if not notes:
        return

    choice_id = input(Fore.CYAN + "\n  Pilih ID catatan untuk dibaca: ").strip()
    
    selected_note = None
    is_valid = False
    for note, valid in notes:
        if note["id"] == choice_id:
            selected_note = note
            is_valid = valid
            break

    if not selected_note:
        print(Fore.RED + "  [ERROR] ID catatan tidak ditemukan.")
        return

    print(Fore.YELLOW + Style.BRIGHT + f"\n  ┌─ MEMBACA CATATAN ID: {choice_id}")
    print(Fore.WHITE + f"  │  Judul: {selected_note['title']}")
    
    if not is_valid:
        print(Fore.RED + "  │  [WARNING] Deteksi Manipulasi Data!")
        print(Fore.RED + "  │  HMAC tidak valid. Data telah dimodifikasi secara ilegal di luar aplikasi.")
        confirm = input(Fore.YELLOW + "  │  Tetap coba dekripsi data terganggu? (y/n): ").strip().lower()
        if confirm != 'y':
            print(Fore.YELLOW + "  └" + "─" * 54)
            return

    try:
        ciphertext = bytes.fromhex(selected_note["ciphertext"])
        iv = bytes.fromhex(selected_note["iv"])
        decrypted_text = decrypt_content(ciphertext, aes_key, iv)
        print(Fore.GREEN + f"  │  Konten (Terdekripsi): {decrypted_text}")
    except Exception as e:
        print(Fore.RED + f"  │  [ERROR] Gagal mendekripsi catatan. Kemungkinan kunci salah atau data rusak. ({e})")
    
    print(Fore.YELLOW + "  └" + "─" * 54)


def update_note(aes_key: bytes, hmac_key: bytes):
    """Memperbarui judul/konten catatan terpilih (Update)."""
    notes = list_notes(aes_key, hmac_key)
    if not notes:
        return

    choice_id = input(Fore.CYAN + "\n  Pilih ID catatan untuk diubah: ").strip()
    
    selected_note = None
    for note, _ in notes:
        if note["id"] == choice_id:
            selected_note = note
            break

    if not selected_note:
        print(Fore.RED + "  [ERROR] ID catatan tidak ditemukan.")
        return

    print(Fore.YELLOW + Style.BRIGHT + f"\n  ┌─ UBAH CATATAN ID: {choice_id}")
    print(Fore.WHITE + f"  │  Judul lama: {selected_note['title']}")
    
    new_title = input(Fore.CYAN + "  │  Judul baru (kosongkan jika tidak ingin diubah): ").strip()
    if not new_title:
        new_title = selected_note['title']

    new_content = input(Fore.CYAN + "  │  Konten baru (kosongkan jika tidak ingin diubah): ").strip()
    
    db = load_db()
    for note in db["notes"]:
        if note["id"] == choice_id:
            if not new_content:
                # Ambil ciphertext lama namun update judul & hitung ulang HMAC
                ciphertext = bytes.fromhex(note["ciphertext"])
                iv = bytes.fromhex(note["iv"])
            else:
                # Enkripsi konten baru
                ciphertext, iv = encrypt_content(new_content, aes_key)
                note["ciphertext"] = ciphertext.hex()
                note["iv"] = iv.hex()
            
            new_hmac = calculate_hmac(choice_id, new_title, ciphertext, iv, hmac_key)
            note["title"] = new_title
            note["hmac"] = new_hmac
            break

    save_db(db)
    print(Fore.GREEN + "  │  [SUCCESS] Catatan berhasil diperbarui dan dienkripsi ulang.")
    print(Fore.YELLOW + "  └" + "─" * 54)


def delete_note():
    """Menghapus catatan terpilih (Delete)."""
    db = load_db()
    if not db or not db["notes"]:
        print(Fore.YELLOW + "\n  [INFO] Tidak ada catatan untuk dihapus.")
        return

    table_data = [[n["id"], n["title"]] for n in db["notes"]]
    print(Fore.YELLOW + Style.BRIGHT + "\n  DAFTAR CATATAN TERSEDIA:")
    print(tabulate(table_data, headers=["ID", "Judul"], tablefmt="fancy_grid"))

    choice_id = input(Fore.CYAN + "\n  Pilih ID catatan untuk dihapus: ").strip()
    
    found = False
    for i, note in enumerate(db["notes"]):
        if note["id"] == choice_id:
            db["notes"].pop(i)
            found = True
            break

    if not found:
        print(Fore.RED + "  [ERROR] ID catatan tidak ditemukan.")
        return

    save_db(db)
    print(Fore.GREEN + "  [SUCCESS] Catatan berhasil dihapus dari penyimpanan.")


def main():
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════╗
║              EKSPERIMEN 7A: SECURE CRUD              ║
║         Aplikasi Pengelola Catatan Terenkripsi       ║
╚══════════════════════════════════════════════════════╝""")

    # Autentikasi Pengguna & Dapatkan Kunci
    aes_key, hmac_key = authenticate_user()

    while True:
        print(Fore.YELLOW + Style.BRIGHT + "\n  MENU UTAMA CRUD AMAN:\n")
        print(Fore.WHITE + "  (1) Tambah Catatan Baru (Create)")
        print(Fore.WHITE + "  (2) Tampilkan & Baca Catatan (Read)")
        print(Fore.WHITE + "  (3) Edit Catatan (Update)")
        print(Fore.WHITE + "  (4) Hapus Catatan (Delete)")
        print(Fore.RED + "   (q) Kembali ke Menu Launcher Utama\n")

        choice = input(Fore.CYAN + Style.BRIGHT + "  Pilih opsi: ").strip().lower()

        if choice == "1":
            create_note(aes_key, hmac_key)
        elif choice == "2":
            read_note_content(aes_key, hmac_key)
        elif choice == "3":
            update_note(aes_key, hmac_key)
        elif choice == "4":
            delete_note()
        elif choice in ("q", "quit", "exit"):
            print(Fore.YELLOW + "\n  Kembali ke menu launcher utama.")
            break
        else:
            print(Fore.RED + f"\n  [ERROR] Pilihan '{choice}' tidak valid.")
            input(Fore.CYAN + "  Tekan ENTER untuk melanjutkan...")


if __name__ == "__main__":
    main()
