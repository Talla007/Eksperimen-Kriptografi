# 🔐 Eksperimen Kriptografi — Semester 4 Peminatan Cyber Security

> Kumpulan eksperimen kriptografi berbasis Python yang mencakup topik-topik fundamental dan lanjutan mata kuliah Kriptografi semester 4.

---

## 📁 Struktur Proyek

```
crypto_experiments/
├── main.py                          ← Launcher utama (menu interaktif)
├── requirements.txt
│
├── 01_classical/                    ← Kriptografi Klasik
│   ├── caesar_cipher.py             → Caesar + Brute Force
│   ├── vigenere_cipher.py           → Vigenere + Kasiski + IoC
│   └── playfair_cipher.py           → Playfair (5×5 matrix, digraph)
│
├── 02_symmetric/                    ← Enkripsi Simetris
│   ├── aes_demo.py                  → AES-256 CBC & CTR, PKCS7, IV
│   └── des_demo.py                  → DES, 3DES, perbandingan keamanan
│
├── 03_asymmetric/                   ← Enkripsi Asimetris
│   ├── rsa_demo.py                  → RSA-2048, OAEP, PSS Signature
│   └── diffie_hellman.py            → DH 2048-bit, shared secret, AES derivasi
│
├── 04_hashing/                      ← Fungsi Hash
│   ├── hash_demo.py                 → MD5/SHA-1/SHA-256/SHA3/BLAKE2b
│   └── hmac_demo.py                 → HMAC, JWT, Timing Attack
│
├── 05_digital_signature/            ← Tanda Tangan Digital
│   └── dsa_rsa_sign.py              → RSA-PSS, DSA, Dokumen Digital, PKI
│
└── 06_attacks/                      ← Simulasi Serangan
    ├── frequency_analysis.py        → Frequency Attack, IoC, Substitution
    └── birthday_attack.py           → Birthday Paradox, Hash Collision
```

---

## 🚀 Cara Menjalankan

### 1. Install Dependensi
```bash
pip install -r requirements.txt
```

### 2. Jalankan Menu Utama
```bash
python main.py
```

### 3. Jalankan Eksperimen Tertentu
```bash
python 01_classical/caesar_cipher.py
python 01_classical/vigenere_cipher.py
python 01_classical/playfair_cipher.py
python 02_symmetric/aes_demo.py
python 02_symmetric/des_demo.py
python 03_asymmetric/rsa_demo.py
python 03_asymmetric/diffie_hellman.py
python 04_hashing/hash_demo.py
python 04_hashing/hmac_demo.py
python 05_digital_signature/dsa_rsa_sign.py
python 06_attacks/frequency_analysis.py
python 06_attacks/birthday_attack.py
```

---

## 📚 Topik yang Dipelajari

### Eksperimen 1A — Caesar Cipher
- Enkripsi & Dekripsi dengan Caesar Cipher (`E(x) = (x + k) mod 26`)
- Visualisasi tabel pergeseran alfabet
- Brute Force Attack (exhaustive key search)
- English frequency scoring untuk auto-crack

### Eksperimen 1B — Vigenere Cipher
- Enkripsi poly-alphabetic dengan kunci berulang
- Tableau Vigenere (tabula recta)
- Index of Coincidence (IoC) analysis
- Kasiski Test untuk estimasi panjang kunci

### Eksperimen 1C — Playfair Cipher
- Pembentukan Key Matrix 5×5
- Aturan enkripsi digraph (baris, kolom, rectangle)
- Persiapan plaintext (null insertion, I=J)

### Eksperimen 2A — AES-256
- Mode CBC (Cipher Block Chaining) & CTR (Counter Mode)
- PKCS7 Padding
- Pentingnya IV (Initialization Vector)
- Perbandingan CBC vs CTR

### Eksperimen 2B — DES & 3DES
- Struktur Feistel Network DES (16 ronde)
- Triple-DES (EDE mode: Enc-Dec-Enc)
- Perbandingan keamanan: DES → 3DES → AES
- Analisis key space & brute force

### Eksperimen 3A — RSA-2048
- Matematika RSA dari dasar (p, q, n, φ(n), e, d)
- RSA-2048 key generation (PEM format)
- Enkripsi/Dekripsi dengan OAEP padding
- Digital Signature RSA-PSS

### Eksperimen 3B — Diffie-Hellman
- Diagram protokol DH (Alice ↔ Bob)
- Demo angka kecil + serangan Eve
- DH 2048-bit (RFC 3526 Group 14)
- Derivasi kunci AES dari shared secret

### Eksperimen 4A — Fungsi Hash
- MD5, SHA-1, SHA-256, SHA-512, SHA-3, BLAKE2b
- Sifat: deterministik, one-way, avalanche effect
- Benchmark performa (MB/s)
- Aplikasi nyata hash

### Eksperimen 4B — HMAC
- Implementasi HMAC manual (RFC 2104)
- Perbandingan Hash biasa vs HMAC
- Simulasi JWT (JSON Web Token)
- Timing attack & `hmac.compare_digest()`

### Eksperimen 5A — Tanda Tangan Digital
- RSA-PSS signing & verification
- DSA (Digital Signature Algorithm)
- Simulasi dokumen legal digital
- Konsep PKI (Certificate Authority chain)

### Eksperimen 6A — Frequency Analysis Attack
- Distribusi frekuensi bahasa Inggris (ASCII bar chart)
- Menyerang Caesar Cipher dengan frequency scoring
- Index of Coincidence untuk klasifikasi cipher
- Partial substitution attack

### Eksperimen 6B — Birthday Attack
- Birthday Paradox (tabel probabilitas)
- Birthday bound: `2^(n/2)` untuk hash n-bit
- Demo collision nyata pada hash 16-bit
- Partial MD5 collision (proof of concept)
- Kronologi serangan: MD5 → SHA-1 SHAttered

---

## 📦 Dependensi

| Package | Versi | Kegunaan |
|---------|-------|----------|
| `pycryptodome` | ≥ 3.20 | AES, DES, RSA, DSA, HMAC |
| `colorama` | ≥ 0.4.6 | Warna terminal (cross-platform) |
| `tabulate` | ≥ 0.9 | Format tabel |

---

## 🔬 Referensi

- **NIST FIPS 197** — AES Standard
- **NIST FIPS 186-4** — DSA Standard  
- **RFC 3526** — DH Groups (2048-bit MODP)
- **RFC 2104** — HMAC
- **RFC 8017** — RSA OAEP & PSS
- **SHAttered (2017)** — SHA-1 Collision Attack
- **Christof Paar** — *Understanding Cryptography*
- **Bruce Schneier** — *Applied Cryptography*

---

## ⚠️ Disclaimer

Eksperimen ini **hanya untuk tujuan pendidikan**. Kode yang mendemonstrasikan serangan (brute force, frequency analysis, birthday attack) dibuat untuk memahami kelemahan algoritma lama dan **tidak boleh digunakan untuk tujuan ilegal**.

---

*Mata Kuliah Kriptografi — Semester 4 — Peminatan Cyber Security*
