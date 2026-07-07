#!/usr/bin/env python3
"""
=============================================================
  EKSPERIMEN 5A: TANDA TANGAN DIGITAL (Digital Signature)
  Mata Kuliah Kriptografi - Semester 4 Cyber Security

  Topik:
    - RSA-PSS Digital Signature (Probabilistic Signature Scheme)
    - DSA (Digital Signature Algorithm)
    - Verifikasi integritas dan autentikasi pengirim
    - Simulasi skenario dokumen legal digital
    - Certificate chain dan PKI (konsep)

  Tiga Properti Tanda Tangan Digital:
    1. Authenticity   → Membuktikan siapa pengirimnya
    2. Integrity      → Membuktikan isi pesan tidak diubah
    3. Non-repudiation→ Pengirim tidak bisa menyangkal
=============================================================
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import utils  # noqa: sets up UTF-8


import os
import json
import hashlib
import time
import datetime

try:
    from Crypto.PublicKey import RSA, DSA
    from Crypto.Signature import pss, DSS
    from Crypto.Hash import SHA256, SHA384
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
# RSA-PSS SIGNATURE
# ─────────────────────────────────────────────

def rsa_generate_key(bits: int = 2048):
    return RSA.generate(bits)


def rsa_sign_pss(message: bytes, private_key) -> bytes:
    """Membuat tanda tangan RSA-PSS (SHA-256)."""
    h = SHA256.new(message)
    return pss.new(private_key).sign(h)


def rsa_verify_pss(message: bytes, signature: bytes, public_key) -> bool:
    """Memverifikasi tanda tangan RSA-PSS."""
    h = SHA256.new(message)
    try:
        pss.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# ─────────────────────────────────────────────
# DSA SIGNATURE
# ─────────────────────────────────────────────

def dsa_generate_key(bits: int = 2048):
    return DSA.generate(bits)


def dsa_sign(message: bytes, private_key) -> bytes:
    """Membuat tanda tangan DSA."""
    h = SHA256.new(message)
    signer = DSS.new(private_key, 'fips-186-3')
    return signer.sign(h)


def dsa_verify(message: bytes, signature: bytes, public_key) -> bool:
    """Memverifikasi tanda tangan DSA."""
    h = SHA256.new(message)
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False


# ─────────────────────────────────────────────
# SIMULASI DOKUMEN DIGITAL
# ─────────────────────────────────────────────

class DigitalDocument:
    """Simulasi dokumen digital yang ditandatangani."""

    def __init__(self, title: str, content: str, author: str):
        self.title     = title
        self.content   = content
        self.author    = author
        self.timestamp = datetime.datetime.now().isoformat()
        self.signature: bytes | None = None
        self.signer_key = None

    def to_bytes(self) -> bytes:
        """Serialisasi dokumen menjadi bytes."""
        doc = {
            "title":     self.title,
            "content":   self.content,
            "author":    self.author,
            "timestamp": self.timestamp,
        }
        return json.dumps(doc, ensure_ascii=False).encode('utf-8')

    def sign(self, private_key):
        """Menandatangani dokumen."""
        self.signature = rsa_sign_pss(self.to_bytes(), private_key)
        self.signer_key = private_key.publickey()
        return self.signature

    def verify(self) -> bool:
        """Memverifikasi tanda tangan dokumen."""
        if self.signature is None or self.signer_key is None:
            return False
        return rsa_verify_pss(self.to_bytes(), self.signature, self.signer_key)

    def display(self):
        print(Fore.WHITE + f"  │  📄 Judul    : {self.title}")
        print(Fore.WHITE + f"  │  ✍  Penulis  : {self.author}")
        print(Fore.WHITE + f"  │  🕐 Waktu    : {self.timestamp}")
        print(Fore.WHITE + f"  │  📝 Isi      : {self.content[:60]}...")
        if self.signature:
            print(Fore.GREEN + f"  │  🔏 Signature: {self.signature.hex()[:50]}...")
            print(Fore.GREEN + f"  │  📏 Sig Len  : {len(self.signature)} byte")


# ─────────────────────────────────────────────
# VISUALISASI
# ─────────────────────────────────────────────

def print_header():
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════╗
║    EKSPERIMEN 5A: TANDA TANGAN DIGITAL               ║
║    RSA-PSS · DSA · Dokumen Digital · PKI Konsep      ║
╚══════════════════════════════════════════════════════╝""")


def print_section(title: str):
    print(Fore.YELLOW + Style.BRIGHT + f"\n  ┌─ {title}")
    print(Fore.YELLOW + "  │")


def show_signature_workflow():
    """Diagram alur tanda tangan digital."""
    print_section("Alur Tanda Tangan Digital")
    print(Fore.WHITE + """  │
  │  ┌─── PENGIRIM (Alice) ───────────────────────────┐
  │  │                                                 │
  │  │  Dokumen (M)                                    │
  │  │      │                                          │
  │  │      ↓                                          │
  │  │  Hash(M) = h         ← SHA-256                 │
  │  │      │                                          │
  │  │      ↓                                          │
  │  │  S = Sign(h, PrivKey) ← RSA/DSA/ECDSA          │
  │  │                                                 │
  │  └─────────────────────────────────────────────────┘
  │         │
  │  Kirim: (M, S) via jaringan terbuka
  │         │
  │  ┌─── PENERIMA (Bob) ────────────────────────────┐
  │  │                                               │
  │  │  Terima (M, S)                                │
  │  │      │                                        │
  │  │      ├─→ Hash(M) = h'    ← hitung ulang      │
  │  │      │                                        │
  │  │      └─→ Verify(S, h', PubKey)               │
  │  │               │                               │
  │  │          ✔ VALID → M tidak diubah, dari Alice │
  │  │          ✘ INVALID → Tampering / bukan Alice  │
  │  └───────────────────────────────────────────────┘""")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_rsa_signature_demo(priv_key, pub_key):
    """Demo RSA-PSS signature."""
    print_section("Demo RSA-PSS Digital Signature")
    message = b"Saya, Budi Santoso, menyetujui kontrak kerja senilai Rp 50.000.000"

    print(Fore.WHITE + f"  │  Pesan  : {message.decode()}")

    t0 = time.perf_counter()
    sig = rsa_sign_pss(message, priv_key)
    t1 = time.perf_counter()

    print(Fore.GREEN  + f"  │  Signature ({len(sig)} byte): {sig.hex()[:60]}...")
    print(Fore.WHITE  + f"  │  Waktu Sign   : {(t1-t0)*1000:.2f} ms")

    t0 = time.perf_counter()
    v1 = rsa_verify_pss(message, sig, pub_key)
    t1 = time.perf_counter()
    print(Fore.GREEN  + f"  │  Verifikasi Pesan Asli  : {'✔ VALID' if v1 else '✘ INVALID'} ({(t1-t0)*1000:.2f} ms)")

    # Skenario 1: Pesan diubah
    tampered = message + b" (DIUBAH oleh attacker)"
    v2 = rsa_verify_pss(tampered, sig, pub_key)
    print(Fore.RED    + f"  │  Verifikasi Pesan Diubah: {'✔ VALID' if v2 else '✘ INVALID (Tamper Detected!)'}")

    # Skenario 2: Kunci salah
    wrong_key = RSA.generate(2048)
    v3 = rsa_verify_pss(message, sig, wrong_key.publickey())
    print(Fore.RED    + f"  │  Verifikasi Kunci Salah : {'✔ VALID' if v3 else '✘ INVALID (Wrong Key!)'}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_dsa_demo():
    """Demo DSA signature."""
    print_section("Demo DSA (Digital Signature Algorithm)")
    print(Fore.WHITE + f"  │  Generating DSA-2048 key pair...")
    t0 = time.perf_counter()
    dsa_key = dsa_generate_key(2048)
    t1 = time.perf_counter()
    print(Fore.WHITE + f"  │  Key generated in {(t1-t0):.2f}s")
    print(Fore.WHITE + f"  │  DSA Key Size: {dsa_key.p.bit_length()} bit")

    message = b"Laporan Keuangan Q4 2024 - Total: Rp 1.234.567.890"
    print(Fore.WHITE + f"  │  Pesan: {message.decode()}")

    sig = dsa_sign(message, dsa_key)
    print(Fore.GREEN + f"  │  DSA Signature ({len(sig)} byte): {sig.hex()[:50]}...")

    v1 = dsa_verify(message, sig, dsa_key.publickey())
    v2 = dsa_verify(b"Laporan palsu", sig, dsa_key.publickey())

    print(Fore.GREEN + f"  │  Verifikasi Pesan Asli   : {'✔ VALID' if v1 else '✘ INVALID'}")
    print(Fore.RED   + f"  │  Verifikasi Pesan Diubah : {'✔ VALID' if v2 else '✘ INVALID'}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_document_signing(priv_key, pub_key):
    """Demo penandatanganan dokumen digital."""
    print_section("Simulasi Penandatanganan Dokumen Legal Digital")

    doc = DigitalDocument(
        title   = "Perjanjian Kerja Sama Proyek Keamanan Siber",
        content = ("Pihak pertama (PT Maju Bersama) dan pihak kedua (CV Secure Tech) "
                   "sepakat untuk menjalin kerja sama proyek keamanan siber selama 12 bulan "
                   "dengan nilai kontrak sebesar Rp 2.500.000.000 dimulai 1 Januari 2025."),
        author  = "Dr. Budi Santoso, M.Kom"
    )

    print(Fore.WHITE + "  │  Dokumen sebelum ditandatangani:")
    doc.display()
    print()

    # Tandatangani
    doc.sign(priv_key)
    print(Fore.GREEN + "  │  Dokumen setelah ditandatangani:")
    doc.display()

    # Verifikasi
    is_valid = doc.verify()
    print()
    print(Fore.GREEN + f"  │  Status Verifikasi: {'✔ DOKUMEN SAH & TIDAK DIUBAH' if is_valid else '✘ TIDAK SAH'}")

    # Simulasi dokumen dipalsukan
    doc.content = doc.content.replace("2.500.000.000", "250.000.000")  # ubah nominal!
    is_tampered_valid = doc.verify()
    print(Fore.RED + f"  │  Verifikasi setelah isi diubah: {'✔ VALID' if is_tampered_valid else '✘ INVALID (Pemalsuan Terdeteksi!)'}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_rsa_vs_dsa():
    """Perbandingan RSA-PSS vs DSA."""
    print_section("Perbandingan RSA-PSS vs DSA vs ECDSA")
    print(Fore.WHITE + f"  │  {'Aspek':<26} {'RSA-PSS':^18} {'DSA':^18} {'ECDSA':^18}")
    print(Fore.WHITE + f"  │  {'─'*26} {'─'*18} {'─'*18} {'─'*18}")
    rows = [
        ("Dasar Matematika",  "Faktorisasi",   "Discrete Log",  "Elliptic Curve"),
        ("Ukuran Kunci",      "2048-4096 bit", "2048 bit",      "256-521 bit"),
        ("Ukuran Signature",  "256-512 byte",  "~72 byte",      "~64 byte"),
        ("Kecepatan Sign",    "Lambat",         "Sedang",        "Cepat"),
        ("Kecepatan Verify",  "Sangat Cepat",  "Sedang",        "Cepat"),
        ("Keacakan Sign",     "Deterministik",  "Butuh random!", "Butuh random!"),
        ("Standar",           "PKCS#1 v2.1",   "FIPS 186-4",    "FIPS 186-4"),
        ("Digunakan di",      "SSL/TLS, PGP",  "US Gov legacy", "TLS 1.3, JWT"),
    ]
    for aspect, rsa, dsa, ecdsa in rows:
        print(Fore.CYAN + f"  │  {aspect:<26} {rsa:^18} {dsa:^18} {ecdsa:^18}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_pki_concept():
    """Konsep PKI (Public Key Infrastructure)."""
    print_section("Konsep PKI (Public Key Infrastructure)")
    print(Fore.WHITE + """  │
  │  PKI = Sistem manajemen kepercayaan kunci publik
  │
  │  ┌─ Root CA (Certificate Authority) ────────────┐
  │  │  Self-signed, dipercaya semua browser/OS     │
  │  │  (DigiCert, Let's Encrypt, GlobalSign, dll.) │
  │  └──────────────┬────────────────────────────────┘
  │                 │  Signs
  │  ┌──────────────↓────────────────────────────────┐
  │  │  Intermediate CA                              │
  │  │  (Trusted by Root CA)                        │
  │  └──────────────┬────────────────────────────────┘
  │                 │  Signs
  │  ┌──────────────↓────────────────────────────────┐
  │  │  End-Entity Certificate                       │
  │  │  (misal: google.com, kita.ac.id)             │
  │  │  Berisi Public Key + Identity                 │
  │  └───────────────────────────────────────────────┘
  │
  │  Saat HTTPS: Browser verifikasi chain certificate
  │  → Root CA Trust → Intermediate CA → Website cert""")
    print(Fore.YELLOW + "  └" + "─" * 54)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    if not check_library():
        return

    print_header()

    print(Fore.WHITE + "\n  Generating RSA-2048 key pair... (tunggu sebentar)")
    t0 = time.perf_counter()
    priv_key = rsa_generate_key(2048)
    pub_key  = priv_key.publickey()
    t1 = time.perf_counter()
    print(Fore.GREEN + f"  ✔ RSA-2048 key pair ready ({(t1-t0):.2f}s)")

    show_signature_workflow()
    show_rsa_signature_demo(priv_key, pub_key)
    show_dsa_demo()
    show_document_signing(priv_key, pub_key)
    show_rsa_vs_dsa()
    show_pki_concept()

    print(Fore.CYAN + Style.BRIGHT + """
  ╔══════════════════════════════════════════════════════╗
  ║  KESIMPULAN                                          ║
  ║  ─────────────────────────────────────────────────  ║
  ║  ✔ Tanda tangan digital = hash + enkripsi kunci priv║
  ║  ✔ Menjamin Authenticity, Integrity, Non-repudiation║
  ║  ✔ RSA-PSS: verify cepat, cocok untuk sertifikat   ║
  ║  ✔ DSA/ECDSA: signature kecil, cocok untuk mobile  ║
  ║  ✔ PKI = infrastruktur kepercayaan global (CA)      ║
  ║  ⚠ DSA: keacakan buruk = kunci bocor! (Sony PS3)   ║
  ╚══════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
