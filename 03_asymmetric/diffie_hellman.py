#!/usr/bin/env python3
"""
=============================================================
  EKSPERIMEN 3B: DIFFIE-HELLMAN KEY EXCHANGE
  Mata Kuliah Kriptografi - Semester 4 Cyber Security

  Topik:
    - Protokol pertukaran kunci Diffie-Hellman (1976)
    - Parameter publik: p (prima besar) dan g (generator)
    - Private key: a (Alice), b (Bob) - rahasia!
    - Public key: A = g^a mod p,  B = g^b mod p
    - Shared secret: s = B^a mod p = A^b mod p
    - Aplikasi: HTTPS/TLS, SSH, Signal Protocol

  DH tidak mengenkripsi data, hanya menukar kunci!
  Kunci bersama kemudian digunakan oleh AES/ChaCha20.
=============================================================
"""
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import utils  # noqa: sets up UTF-8


import os
import hashlib
import secrets

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""


# ─────────────────────────────────────────────
# PARAMETER PUBLIK DH
# ─────────────────────────────────────────────

# RFC 3526 Group 14 (2048-bit MODP Group)
DH_P_2048 = int(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF".replace(" ", ""), 16
)
DH_G = 2  # Standard generator


# Parameter kecil untuk visualisasi
DH_P_SMALL = 23    # Prima kecil (hanya untuk demo!)
DH_G_SMALL = 5     # Generator primitif mod 23


# ─────────────────────────────────────────────
# FUNGSI INTI DH
# ─────────────────────────────────────────────

class DHParty:
    """Merepresentasikan satu pihak dalam DH key exchange."""

    def __init__(self, name: str, p: int, g: int):
        self.name   = name
        self.p      = p
        self.g      = g
        self.private_key = secrets.randbelow(p - 2) + 2  # [2, p-1]
        self.public_key  = pow(g, self.private_key, p)
        self.shared_secret: int | None = None

    def compute_shared_secret(self, other_public: int):
        """Menghitung shared secret dari public key pihak lain."""
        self.shared_secret = pow(other_public, self.private_key, self.p)
        return self.shared_secret

    def derive_aes_key(self) -> bytes:
        """Menurunkan kunci AES-256 dari shared secret."""
        if self.shared_secret is None:
            raise ValueError("Shared secret belum dihitung!")
        secret_bytes = self.shared_secret.to_bytes(
            (self.shared_secret.bit_length() + 7) // 8, 'big'
        )
        return hashlib.sha256(secret_bytes).digest()


# ─────────────────────────────────────────────
# VISUALISASI
# ─────────────────────────────────────────────

def print_header():
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════╗
║      EKSPERIMEN 3B: DIFFIE-HELLMAN KEY EXCHANGE      ║
║    Pertukaran Kunci Aman melalui Saluran Terbuka     ║
╚══════════════════════════════════════════════════════╝""")


def print_section(title: str):
    print(Fore.YELLOW + Style.BRIGHT + f"\n  ┌─ {title}")
    print(Fore.YELLOW + "  │")


def show_dh_protocol_diagram():
    """Menampilkan diagram protokol DH."""
    print_section("Diagram Protokol Diffie-Hellman")
    print(Fore.WHITE + """  │
  │         ALICE                        BOB
  │     (Private: a)                (Private: b)
  │           │                           │
  │           │ ← Sepakati p dan g (publik)│
  │           │                           │
  │  A = g^a mod p                B = g^b mod p
  │           │                           │
  │           │ ─────── kirim A ─────────→ │
  │           │ ←────── kirim B ─────────  │
  │           │                           │
  │  s = B^a mod p              s = A^b mod p
  │           │                           │
  │     (Sama! = g^(ab) mod p)            │
  │           │                           │
  │  Derive AES Key = SHA256(s)           │
  │           │                           │
  │  [AMAN: Eve melihat A,B,p,g tapi TIDAK bisa hitung s]
  │""")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_small_example():
    """Demo DH dengan angka kecil."""
    print_section(f"Demo DH dengan Angka Kecil (p={DH_P_SMALL}, g={DH_G_SMALL})")

    p, g = DH_P_SMALL, DH_G_SMALL

    # Hardcode untuk demo yang terlihat jelas
    a_priv = 6   # private key Alice
    b_priv = 15  # private key Bob
    A = pow(g, a_priv, p)
    B = pow(g, b_priv, p)
    s_alice = pow(B, a_priv, p)
    s_bob   = pow(A, b_priv, p)

    print(Fore.WHITE + f"  │  Parameter Publik:")
    print(Fore.CYAN  + f"  │    p (prima)   = {p}")
    print(Fore.CYAN  + f"  │    g (generator) = {g}")
    print(Fore.WHITE + f"\n  │  Alice:")
    print(Fore.WHITE + f"  │    Private key  a = {a_priv}  (RAHASIA!)")
    print(Fore.GREEN + f"  │    Public key   A = g^a mod p = {g}^{a_priv} mod {p} = {A}  (kirim ke Bob)")
    print(Fore.WHITE + f"\n  │  Bob:")
    print(Fore.WHITE + f"  │    Private key  b = {b_priv}  (RAHASIA!)")
    print(Fore.GREEN + f"  │    Public key   B = g^b mod p = {g}^{b_priv} mod {p} = {B}  (kirim ke Alice)")
    print(Fore.WHITE + f"\n  │  Perhitungan Shared Secret:")
    print(Fore.CYAN  + f"  │    Alice: s = B^a mod p = {B}^{a_priv} mod {p} = {s_alice}")
    print(Fore.CYAN  + f"  │    Bob  : s = A^b mod p = {A}^{b_priv} mod {p} = {s_bob}")
    agree = s_alice == s_bob
    color = Fore.GREEN if agree else Fore.RED
    print(color + f"  │  → Shared secret {'SAMA ✔' if agree else 'BERBEDA ✘'}: {s_alice}")

    # Serangan Eve
    print(Fore.WHITE + f"\n  │  Eve (penyadap) melihat: p={p}, g={g}, A={A}, B={B}")
    print(Fore.RED   + f"  │  Eve mencoba brute force private key Alice:")
    for guess in range(1, p):
        if pow(g, guess, p) == A:
            print(Fore.RED + f"  │    a = {guess} ditemukan! (p kecil = TIDAK AMAN)")
            break
    print(Fore.GREEN + f"  │  → Dengan p 2048-bit, brute force MUSTAHIL secara komputasi")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_real_dh():
    """Demo DH dengan parameter 2048-bit nyata."""
    print_section("Demo DH Nyata (RFC 3526 - 2048-bit MODP Group)")
    print(Fore.WHITE + f"  │  Parameter: RFC 3526 Group 14 (2048-bit prime)")
    print(Fore.WHITE + f"  │  Generator g = {DH_G}")
    print(Fore.WHITE + f"  │  Prime p (hex, 2048-bit): {hex(DH_P_2048)[:40]}...")
    print()
    print(Fore.WHITE + f"  │  Mensimulasikan pertukaran kunci Alice ↔ Bob...")

    alice = DHParty("Alice", DH_P_2048, DH_G)
    bob   = DHParty("Bob",   DH_P_2048, DH_G)

    # Tukar public key
    alice_secret = alice.compute_shared_secret(bob.public_key)
    bob_secret   = bob.compute_shared_secret(alice.public_key)

    agree = alice_secret == bob_secret

    print(Fore.GREEN  + f"  │  Alice Public Key (A): {str(alice.public_key)[:40]}...")
    print(Fore.CYAN   + f"  │  Bob   Public Key (B): {str(bob.public_key)[:40]}...")
    print(Fore.WHITE  + f"\n  │  Shared Secret Agreement: {'✔ BERHASIL!' if agree else '✘ GAGAL'}")
    print(Fore.WHITE  + f"  │  Shared Secret (bits): {alice_secret.bit_length()} bit")

    alice_aes = alice.derive_aes_key()
    bob_aes   = bob.derive_aes_key()

    print(Fore.WHITE  + f"\n  │  Derivasi AES-256 Key (SHA256 dari shared secret):")
    print(Fore.GREEN  + f"  │    Alice AES Key: {alice_aes.hex()}")
    print(Fore.CYAN   + f"  │    Bob   AES Key: {bob_aes.hex()}")
    key_match = alice_aes == bob_aes
    print(Fore.GREEN  + f"  │    Kunci Sama?  : {'✔ YA - Siap untuk enkripsi!' if key_match else '✘ TIDAK'}")
    print(Fore.YELLOW + "  └" + "─" * 54)


def show_ecdh_comparison():
    """Perbandingan DH vs ECDH."""
    print_section("Perbandingan: DH vs ECDH (Elliptic Curve DH)")
    print(Fore.WHITE + f"  │  {'Aspek':<28} {'DH (Classic)':^20} {'ECDH':^20}")
    print(Fore.WHITE + f"  │  {'─'*28} {'─'*20} {'─'*20}")
    rows = [
        ("Dasar Matematika",    "Discrete Log",    "Elliptic Curve DL"),
        ("Ukuran Kunci (128b)", "3072-bit",        "256-bit"),
        ("Ukuran Kunci (256b)", "15360-bit",       "521-bit"),
        ("Kecepatan",           "Lebih lambat",    "Lebih cepat"),
        ("Ukuran Pesan",        "Besar",           "Kecil (efisien)"),
        ("Penggunaan",          "TLS legacy",      "TLS 1.3, Signal"),
        ("Status",              "Masih aman",      "Lebih disarankan"),
    ]
    for aspect, dh, ecdh in rows:
        print(Fore.CYAN + f"  │  {aspect:<28} {dh:^20} {ecdh:^20}")
    print(Fore.YELLOW + "  └" + "─" * 54)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print_header()
    show_dh_protocol_diagram()
    show_small_example()
    show_real_dh()
    show_ecdh_comparison()

    print(Fore.CYAN + Style.BRIGHT + """
  ╔══════════════════════════════════════════════════════╗
  ║  KESIMPULAN                                          ║
  ║  ─────────────────────────────────────────────────  ║
  ║  ✔ DH memungkinkan pertukaran kunci via saluran pu- ║
  ║    blik tanpa mengirim kunci itu sendiri             ║
  ║  ✔ Keamanan berdasarkan Discrete Logarithm Problem  ║
  ║  ✔ Digunakan di HTTPS/TLS, SSH, VPN                 ║
  ║  ⚠ DH klasik rentan Man-in-the-Middle (MITM)        ║
  ║    → Perlu autentikasi tambahan (sertifikat, dll)   ║
  ║  ✔ ECDH lebih efisien, digunakan TLS 1.3 & Signal   ║
  ╚══════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
