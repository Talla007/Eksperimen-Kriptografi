#!/usr/bin/env python3
"""
=============================================================
  EKSPERIMEN 4B: HMAC (Hash-based Message Authentication Code)
  Mata Kuliah Kriptografi - Semester 4 Cyber Security

  Topik:
    - HMAC untuk autentikasi pesan (Message Authentication)
    - Perbedaan Hash biasa vs HMAC
    - HMAC-SHA256, HMAC-SHA512
    - Kegunaan HMAC dalam protokol nyata (JWT, API Auth, TLS)
    - Timing attack dan cara mencegahnya

  HMAC Formula:
    HMAC(K, M) = Hash((K ⊕ opad) || Hash((K ⊕ ipad) || M))
    di mana:
      K    = kunci
      M    = pesan
      ipad = 0x36 × blocksize
      opad = 0x5C × blocksize
=============================================================
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import utils  # noqa: sets up UTF-8


import hmac
import hashlib
import os
import time
import json
import base64

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""


# ─────────────────────────────────────────────
# FUNGSI INTI HMAC
# ─────────────────────────────────────────────

def compute_hmac(key: bytes, message: bytes, algo: str = "sha256") -> str:
    """Menghitung HMAC dengan kunci dan pesan."""
    h = hmac.new(key, message, algo)
    return h.hexdigest()


def verify_hmac(key: bytes, message: bytes, mac: str, algo: str = "sha256") -> bool:
    """Memverifikasi HMAC secara aman (constant-time comparison)."""
    expected = hmac.new(key, message, algo).hexdigest()
    return hmac.compare_digest(expected, mac)   # Mencegah timing attack!


def hmac_manual(key: bytes, message: bytes, hash_func=hashlib.sha256) -> bytes:
    """
    Implementasi HMAC manual (untuk pemahaman).
    HMAC(K, M) = Hash((K ⊕ opad) || Hash((K ⊕ ipad) || M))
    """
    block_size = hash_func().block_size

    # Normalisasi kunci
    if len(key) > block_size:
        key = hash_func(key).digest()
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))

    ipad = bytes([k ^ 0x36 for k in key])
    opad = bytes([k ^ 0x5C for k in key])

    inner = hash_func(ipad + message).digest()
    outer = hash_func(opad + inner).digest()
    return outer


# ─────────────────────────────────────────────
# SIMULASI JWT (JSON Web Token)
# ─────────────────────────────────────────────

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + '=' * padding)


def create_jwt(payload: dict, secret: str) -> str:
    """Membuat JWT sederhana dengan HMAC-SHA256."""
    header  = {"alg": "HS256", "typ": "JWT"}
    h_enc   = b64url_encode(json.dumps(header).encode())
    p_enc   = b64url_encode(json.dumps(payload).encode())
    signing_input = f"{h_enc}.{p_enc}".encode()
    sig     = hmac.new(secret.encode(), signing_input, "sha256").digest()
    sig_enc = b64url_encode(sig)
    return f"{h_enc}.{p_enc}.{sig_enc}"


def verify_jwt(token: str, secret: str) -> tuple[bool, dict | None]:
    """Memverifikasi JWT."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False, None
        h_enc, p_enc, sig_enc = parts
        signing_input = f"{h_enc}.{p_enc}".encode()
        expected_sig  = hmac.new(secret.encode(), signing_input, "sha256").digest()
        actual_sig    = b64url_decode(sig_enc)
        if hmac.compare_digest(expected_sig, actual_sig):
            payload = json.loads(b64url_decode(p_enc))
            return True, payload
        return False, None
    except Exception:
        return False, None


# ─────────────────────────────────────────────
# VISUALISASI
# ─────────────────────────────────────────────

def print_header():
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════╗
║     EKSPERIMEN 4B: HMAC - Message Authentication     ║
║       HMAC-SHA256 · JWT · API Key Authentication     ║
╚══════════════════════════════════════════════════════╝""")


def print_section(title: str):
    print(Fore.YELLOW + Style.BRIGHT + f"\n  ┌─ {title}")
    print(Fore.YELLOW + "  │")


def show_hmac_formula():
    """Menampilkan struktur HMAC."""
    print_section("Struktur HMAC (RFC 2104)")
    print(Fore.WHITE + """  │
  │  HMAC(K, M) = Hash((K ⊕ opad) ‖ Hash((K ⊕ ipad) ‖ M))
  │
  │   K (key)  ──── ⊕ ipad (0x36...) ────→ ipad_key
  │                                              │
  │                                          Hash(ipad_key ‖ M) → inner
  │                                              │
  │   K (key)  ──── ⊕ opad (0x5C...) ────→ opad_key
  │                                              │
  │                                          Hash(opad_key ‖ inner) → HMAC
  │
  │  ipad = 0x3636...36  (block_size kali)
  │  opad = 0x5C5C...5C  (block_size kali)""")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_hmac_vs_hash(message: bytes, key: bytes):
    """Perbandingan Hash biasa vs HMAC."""
    print_section("Perbedaan Hash Biasa vs HMAC")
    h_plain = hashlib.sha256(message).hexdigest()
    h_mac   = compute_hmac(key, message)

    print(Fore.WHITE + f"  │  Pesan       : {message.decode()}")
    print(Fore.WHITE + f"  │  Kunci HMAC  : {key.hex()}")
    print()
    print(Fore.WHITE + f"  │  SHA-256 biasa (tanpa kunci):")
    print(Fore.RED   + f"  │    {h_plain}")
    print(Fore.RED   + f"  │    ✘ Siapa saja bisa hitung ini! Tidak ada autentikasi.")
    print()
    print(Fore.WHITE + f"  │  HMAC-SHA256 (dengan kunci):")
    print(Fore.GREEN + f"  │    {h_mac}")
    print(Fore.GREEN + f"  │    ✔ Hanya yang punya kunci bisa verifikasi!")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_hmac_demo(message: bytes, key: bytes):
    """Demonstrasi HMAC lengkap."""
    print_section("Demonstrasi HMAC: Pembuatan & Verifikasi")
    print(Fore.WHITE + f"  │  Pesan   : {message.decode()}")
    print(Fore.WHITE + f"  │  Kunci   : {key.hex()[:40]}...")
    print()

    # HMAC dengan berbagai algoritma
    algos = [("sha256", "HMAC-SHA256", 256), ("sha512", "HMAC-SHA512", 512),
             ("sha3_256", "HMAC-SHA3-256", 256)]
    print(Fore.WHITE + f"  │  {'Algoritma':<16} {'HMAC (hex)':<66} {'Bits'}")
    print(Fore.WHITE + f"  │  {'─'*16} {'─'*66} {'─'*6}")
    for algo, name, bits in algos:
        mac = compute_hmac(key, message, algo)
        print(Fore.CYAN + f"  │  {name:<16} {mac[:64]:<66} {bits}")
    print()

    # Verifikasi HMAC
    mac_sha256 = compute_hmac(key, message, "sha256")
    is_valid   = verify_hmac(key, message, mac_sha256)

    # Pesan dimodifikasi
    tampered = message[:-1] + b'!'
    is_tampered_valid = verify_hmac(key, tampered, mac_sha256)

    print(Fore.WHITE + f"  │  Verifikasi:")
    print(Fore.GREEN + f"  │    Pesan asli   : {'✔ VALID' if is_valid else '✘ INVALID'}")
    print(Fore.RED   + f"  │    Pesan diubah : {'✔ VALID' if is_tampered_valid else '✘ INVALID (Tampering Detected!)'}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_hmac_manual(key: bytes, message: bytes):
    """Demonstrasi HMAC manual vs library."""
    print_section("Implementasi HMAC Manual vs Library")
    manual = hmac_manual(key, message).hex()
    library = compute_hmac(key, message, "sha256")
    match   = manual == library
    print(Fore.WHITE + f"  │  Kunci   : {key.hex()}")
    print(Fore.WHITE + f"  │  Pesan   : {message.decode()}")
    print(Fore.CYAN  + f"  │  Manual  : {manual}")
    print(Fore.GREEN + f"  │  Library : {library}")
    print(Fore.GREEN + f"  │  Sama?   : {'✔ YA (implementasi benar!)' if match else '✘ BERBEDA'}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_jwt_demo():
    """Demo JWT dengan HMAC."""
    print_section("Simulasi JWT (JSON Web Token) dengan HMAC-SHA256")
    secret  = "kunci_rahasia_server_2024"
    payload = {
        "sub":  "mahasiswa001",
        "name": "Budi Santoso",
        "role": "student",
        "iat":  1720000000,
        "exp":  1720086400,
    }

    token = create_jwt(payload, secret)
    parts = token.split(".")

    print(Fore.WHITE + f"  │  Secret  : '{secret}'")
    print(Fore.WHITE + f"  │  Payload : {json.dumps(payload, indent=None)}")
    print()
    print(Fore.WHITE + f"  │  JWT Token:")
    print(Fore.RED   + f"  │    Header   : {parts[0]}")
    print(Fore.CYAN  + f"  │    Payload  : {parts[1]}")
    print(Fore.GREEN + f"  │    Signature: {parts[2]}")
    print(Fore.WHITE + f"\n  │  Full JWT:")
    print(Fore.YELLOW + Style.BRIGHT + f"  │  {token[:80]}...")

    # Verifikasi
    valid, decoded = verify_jwt(token, secret)
    print(Fore.GREEN + f"\n  │  Verifikasi dengan secret benar: {'✔ VALID' if valid else '✘ INVALID'}")
    if decoded:
        print(Fore.CYAN + f"  │  Payload decoded: {decoded}")

    # Coba verifikasi dengan secret salah
    valid2, _ = verify_jwt(token, "kunci_salah")
    print(Fore.RED + f"  │  Verifikasi dengan secret salah: {'✔ VALID' if valid2 else '✘ INVALID'}")

    # Coba tamper payload
    tampered_token = token[:token.rfind('.')] + ".hacked_signature_xyz"
    valid3, _ = verify_jwt(tampered_token, secret)
    print(Fore.RED + f"  │  Verifikasi token di-tamper     : {'✔ VALID' if valid3 else '✘ INVALID (Tamper Detected!)'}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_timing_attack():
    """Menampilkan bahaya timing attack dan cara mencegah."""
    print_section("Timing Attack & Constant-Time Comparison")
    key     = os.urandom(32)
    message = b"Pesan Rahasia"
    correct_mac = compute_hmac(key, message)
    wrong_mac   = "a" * len(correct_mac)  # MAC yang salah

    # Normal comparison (vulnerable!)
    def naive_compare(a: str, b: str) -> bool:
        if len(a) != len(b):
            return False
        for ca, cb in zip(a, b):
            if ca != cb:
                return False  # Early exit = timing leak!
        return True

    # Ukur waktu
    n = 10000
    t0 = time.perf_counter()
    for _ in range(n):
        naive_compare(correct_mac, wrong_mac)
    t_naive = (time.perf_counter() - t0) / n * 1e6

    t0 = time.perf_counter()
    for _ in range(n):
        hmac.compare_digest(correct_mac, wrong_mac)
    t_safe = (time.perf_counter() - t0) / n * 1e6

    print(Fore.WHITE + f"  │  Perbandingan (avg {n} kali):")
    print(Fore.RED   + f"  │    Naive comparison (== atau loop)  : {t_naive:.3f} μs  [RENTAN!]")
    print(Fore.GREEN + f"  │    hmac.compare_digest()            : {t_safe:.3f} μs  [AMAN]")
    print(Fore.WHITE + f"\n  │  Mengapa aman?")
    print(Fore.WHITE + f"  │  → compare_digest() selalu memakan waktu SAMA")
    print(Fore.WHITE + f"    meski karakter pertama sudah berbeda (no early exit).")
    print(Fore.WHITE + f"  │  → Attacker tidak bisa menyimpulkan posisi mana yang cocok.")
    print(Fore.YELLOW + "  └" + "─" * 54)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print_header()

    key     = os.urandom(32)
    message = b"Pesan API Request: GET /api/data?user=admin&timestamp=1720000000"

    show_hmac_formula()
    show_hmac_vs_hash(message, key)
    show_hmac_demo(message, key)
    show_hmac_manual(key[:32], b"Hello HMAC World")
    show_jwt_demo()
    show_timing_attack()

    print(Fore.CYAN + Style.BRIGHT + """
  ╔══════════════════════════════════════════════════════╗
  ║  KESIMPULAN                                          ║
  ║  ─────────────────────────────────────────────────  ║
  ║  ✔ HMAC menjamin integritas DAN autentikasi pesan   ║
  ║  ✔ Berbeda dari hash biasa: butuh kunci rahasia      ║
  ║  ✔ Digunakan di JWT, OAuth, API signature, TLS      ║
  ║  ⚠ Selalu gunakan hmac.compare_digest() (anti-timing)║
  ║  ⚠ Kunci HMAC harus benar-benar acak dan rahasia    ║
  ╚══════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
