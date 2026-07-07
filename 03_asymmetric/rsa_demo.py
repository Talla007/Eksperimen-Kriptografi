#!/usr/bin/env python3
"""
=============================================================
  EKSPERIMEN 3A: RSA (Rivest-Shamir-Adleman)
  Mata Kuliah Kriptografi - Semester 4 Cyber Security

  Topik:
    - RSA Key Generation (public key & private key)
    - Enkripsi dengan kunci publik (OAEP padding)
    - Dekripsi dengan kunci privat
    - Matematika di balik RSA
    - RSA untuk tanda tangan digital

  Matematika RSA:
    1. Pilih dua prima besar p, q
    2. n = p × q   (modulus)
    3. φ(n) = (p-1)(q-1)
    4. Pilih e: gcd(e, φ(n)) = 1
    5. d = e⁻¹ mod φ(n)
    6. Public key: (n, e)  |  Private key: (n, d)
    7. Encrypt: C = M^e mod n
    8. Decrypt: M = C^d mod n
=============================================================
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import utils  # noqa: sets up UTF-8


import os
import time

try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Signature import pss
    from Crypto.Hash import SHA256
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
# RSA MANUAL (SMALL NUMBERS) - untuk visualisasi
# ─────────────────────────────────────────────

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean Algorithm: ax + by = gcd(a,b)."""
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def modinv(a: int, m: int) -> int:
    """Modular inverse: a^-1 mod m."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError("Tidak ada modular inverse!")
    return x % m


def rsa_manual_demo(p: int = 61, q: int = 53):
    """Demonstrasi RSA dengan angka kecil untuk visualisasi."""
    n     = p * q
    phi_n = (p - 1) * (q - 1)
    e     = 17  # public exponent (coprime dengan phi_n)
    d     = modinv(e, phi_n)

    return {
        "p": p, "q": q, "n": n, "phi_n": phi_n,
        "e": e, "d": d,
        "public_key":  (n, e),
        "private_key": (n, d),
    }


def rsa_manual_encrypt(m: int, e: int, n: int) -> int:
    """Enkripsi manual: C = M^e mod n."""
    return pow(m, e, n)


def rsa_manual_decrypt(c: int, d: int, n: int) -> int:
    """Dekripsi manual: M = C^d mod n."""
    return pow(c, d, n)


# ─────────────────────────────────────────────
# RSA NYATA (pycryptodome) - 2048-bit
# ─────────────────────────────────────────────

def generate_rsa_keypair(bits: int = 2048):
    """Generate RSA key pair."""
    key = RSA.generate(bits)
    return key, key.publickey()


def rsa_encrypt(message: bytes, public_key) -> bytes:
    """Enkripsi dengan RSA-OAEP."""
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message)


def rsa_decrypt(ciphertext: bytes, private_key) -> bytes:
    """Dekripsi dengan RSA-OAEP."""
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


def rsa_sign(message: bytes, private_key) -> bytes:
    """Membuat tanda tangan digital RSA-PSS."""
    h = SHA256.new(message)
    return pss.new(private_key).sign(h)


def rsa_verify(message: bytes, signature: bytes, public_key) -> bool:
    """Memverifikasi tanda tangan digital RSA-PSS."""
    h = SHA256.new(message)
    try:
        pss.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# ─────────────────────────────────────────────
# VISUALISASI
# ─────────────────────────────────────────────

def print_header():
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════╗
║         EKSPERIMEN 3A: RSA-2048                      ║
║   Public Key Cryptography + Digital Signature        ║
╚══════════════════════════════════════════════════════╝""")


def print_section(title: str):
    print(Fore.YELLOW + Style.BRIGHT + f"\n  ┌─ {title}")
    print(Fore.YELLOW + "  │")


def show_rsa_math(params: dict):
    """Menampilkan matematika RSA dengan angka kecil."""
    print_section("Matematika RSA (Contoh Angka Kecil untuk Visualisasi)")
    p, q = params["p"], params["q"]
    n, phi_n = params["n"], params["phi_n"]
    e, d = params["e"], params["d"]

    print(Fore.WHITE  + f"  │  Langkah 1: Pilih 2 prima  → p = {p},  q = {q}")
    print(Fore.WHITE  + f"  │  Langkah 2: Hitung n       → n = p×q = {p}×{q} = {n}")
    print(Fore.WHITE  + f"  │  Langkah 3: Hitung φ(n)    → φ(n) = (p-1)(q-1) = {p-1}×{q-1} = {phi_n}")
    print(Fore.WHITE  + f"  │  Langkah 4: Pilih e        → e = {e}  (gcd({e}, {phi_n}) = 1)")
    print(Fore.WHITE  + f"  │  Langkah 5: Hitung d       → d = e⁻¹ mod φ(n) = {d}")
    print(Fore.GREEN  + f"  │  Public Key  (n, e) = ({n}, {e})")
    print(Fore.CYAN   + f"  │  Private Key (n, d) = ({n}, {d})")

    # Demonstrasi enkripsi/dekripsi manual
    message = 42
    ciphertext = rsa_manual_encrypt(message, e, n)
    decrypted  = rsa_manual_decrypt(ciphertext, d, n)

    print(Fore.WHITE  + f"\n  │  Enkripsi Manual:")
    print(Fore.WHITE  + f"  │    Pesan (M)    = {message}")
    print(Fore.GREEN  + f"  │    C = M^e mod n = {message}^{e} mod {n} = {ciphertext}")
    print(Fore.WHITE  + f"\n  │  Dekripsi Manual:")
    print(Fore.CYAN   + f"  │    M = C^d mod n = {ciphertext}^{d} mod {n} = {decrypted}")
    print(Fore.GREEN  + f"  │  Verifikasi: {decrypted} == {message} → {'✔ BENAR' if decrypted == message else '✘ SALAH'}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_keygen(bits: int):
    """Menampilkan proses key generation RSA."""
    print_section(f"RSA-{bits} Key Generation")
    print(Fore.WHITE + f"  │  Sedang generate {bits}-bit RSA key pair...")

    t0 = time.perf_counter()
    private_key, public_key = generate_rsa_keypair(bits)
    t1 = time.perf_counter()

    n = private_key.n
    e = private_key.e
    d = private_key.d

    print(Fore.WHITE  + f"  │  Waktu Generate : {(t1-t0):.3f} detik")
    print(Fore.WHITE  + f"  │  Key Size       : {bits} bit")
    print(Fore.GREEN  + f"  │  Public  e      : {e}")
    print(Fore.GREEN  + f"  │  Modulus n      : {str(n)[:60]}...")
    print(Fore.CYAN   + f"  │  Private d      : {str(d)[:60]}...")

    # Ekspor PEM
    pem_pub  = public_key.export_key('PEM').decode()
    pem_priv = private_key.export_key('PEM').decode()
    print(Fore.WHITE + f"\n  │  Public Key (PEM):")
    for line in pem_pub.splitlines()[:5]:
        print(Fore.GREEN + f"  │    {line}")
    print(Fore.GREEN + f"  │    ...")
    print(Fore.WHITE + f"\n  │  Private Key (PEM):")
    for line in pem_priv.splitlines()[:5]:
        print(Fore.CYAN + f"  │    {line}")
    print(Fore.CYAN + f"  │    ...")
    print(Fore.YELLOW + "  └" + "─" * 54)
    return private_key, public_key


def show_encrypt_decrypt(message: bytes, private_key, public_key):
    """Demonstrasi enkripsi/dekripsi RSA."""
    print_section("RSA-OAEP Enkripsi & Dekripsi")
    print(Fore.WHITE + f"  │  Plaintext  : {message.decode()}")
    print(Fore.WHITE + f"  │  Panjang    : {len(message)} byte")
    print(Fore.WHITE + f"  │  Padding    : OAEP (Optimal Asymmetric Encryption Padding)")

    t0 = time.perf_counter()
    ciphertext = rsa_encrypt(message, public_key)
    t1 = time.perf_counter()

    decrypted = rsa_decrypt(ciphertext, private_key)
    t2 = time.perf_counter()

    print(Fore.GREEN  + f"  │  Ciphertext : {ciphertext.hex()[:60]}...")
    print(Fore.WHITE  + f"  │  CT Length  : {len(ciphertext)} byte")
    print(Fore.CYAN   + f"  │  Decrypted  : {decrypted.decode()}")
    print(Fore.WHITE  + f"  │  Enc Time   : {(t1-t0)*1000:.2f} ms")
    print(Fore.WHITE  + f"  │  Dec Time   : {(t2-t1)*1000:.2f} ms")
    print(Fore.GREEN  + f"  │  Verifikasi : {'✔ SAMA' if decrypted == message else '✘ BERBEDA!'}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_digital_signature(message: bytes, private_key, public_key):
    """Demonstrasi digital signature RSA-PSS."""
    print_section("RSA-PSS Digital Signature")
    print(Fore.WHITE + f"  │  Pesan    : {message.decode()}")

    t0 = time.perf_counter()
    signature = rsa_sign(message, private_key)
    t1 = time.perf_counter()

    is_valid = rsa_verify(message, signature, public_key)

    # Pesan yang dimodifikasi
    tampered = message[:-1] + (b'!' if message[-1:] != b'!' else b'?')
    is_tampered_valid = rsa_verify(tampered, signature, public_key)

    print(Fore.CYAN   + f"  │  Signature: {signature.hex()[:60]}...")
    print(Fore.WHITE  + f"  │  Sig Len  : {len(signature)} byte")
    print(Fore.WHITE  + f"  │  Sign Time: {(t1-t0)*1000:.2f} ms")
    print(Fore.GREEN  + f"  │  Verifikasi Pesan Asli    : {'✔ VALID' if is_valid else '✘ INVALID'}")
    print(Fore.RED    + f"  │  Verifikasi Pesan Diubah  : {'✔ VALID' if is_tampered_valid else '✘ INVALID (Tamper Detected!)'}")
    print(Fore.YELLOW + "  └" + "─" * 54)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    if not check_library():
        return

    print_header()

    # Demonstrasi matematika RSA
    params = rsa_manual_demo(p=61, q=53)
    show_rsa_math(params)

    # RSA nyata 2048-bit
    private_key, public_key = show_keygen(2048)

    message = b"Pesan rahasia ini dienkripsi dengan RSA-2048 OAEP"
    show_encrypt_decrypt(message, private_key, public_key)
    show_digital_signature(message, private_key, public_key)

    print(Fore.CYAN + Style.BRIGHT + """
  ╔══════════════════════════════════════════════════════╗
  ║  KESIMPULAN                                          ║
  ║  ─────────────────────────────────────────────────  ║
  ║  ✔ RSA berdasarkan sulitnya faktorisasi bilangan    ║
  ║  ✔ Kunci publik = enkripsi / verifikasi signature   ║
  ║  ✔ Kunci privat = dekripsi / pembuatan signature    ║
  ║  ⚠ RSA LAMBAT → biasa digunakan hybrid (RSA+AES)   ║
  ║  ⚠ RSA-1024 sudah TIDAK AMAN, gunakan minimal 2048  ║
  ║  → Masa depan: Quantum-safe (lattice-based, etc.)   ║
  ╚══════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
