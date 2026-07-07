# Eksperimen Kriptografi - Semester 4 Peminatan Cyber Security

Repositori ini berisi kumpulan implementasi praktis dan simulasi laboratorium untuk mata kuliah Kriptografi di Semester 4 Peminatan Cyber Security. Seluruh kode ditulis menggunakan Python dengan fokus pada pemahaman konsep teoretis, visualisasi proses, serta demonstrasi kekuatan dan kelemahan masing-masing algoritma.

---

## Struktur Proyek

Proyek ini terbagi menjadi beberapa modul utama yang mencakup kategori kriptografi klasik hingga modern, serta simulasi serangan (kriptanalisis):

```
crypto_experiments/
├── main.py                          ← Launcher utama (menu interaktif)
├── requirements.txt                 ← Daftar pustaka eksternal
├── utils.py                         ← Konfigurasi sistem dan encoding terminal
│
├── 01_classical/                    ← Kriptografi Klasik
│   ├── caesar_cipher.py             → Caesar Cipher dan Brute Force Attack
│   ├── vigenere_cipher.py           → Vigenere Cipher, Kasiski Test, dan Index of Coincidence
│   └── playfair_cipher.py           → Playfair Cipher (Matriks Kunci 5x5, Digraph)
│
├── 02_symmetric/                    ← Kriptografi Simetris
│   ├── aes_demo.py                  → AES-256 (Mode CBC dan CTR), PKCS7 Padding, dan Analisis IV
│   └── des_demo.py                  → DES, Triple-DES (3DES), dan Analisis Kinerja
│
├── 03_asymmetric/                   ← Kriptografi Asimetris
│   ├── rsa_demo.py                  → Pembangkitan Kunci RSA-2048, OAEP Padding, dan Signature PSS
│   └── diffie_hellman.py            → Protokol Pertukaran Kunci Diffie-Hellman 2048-bit
│
├── 04_hashing/                      ← Fungsi Hash Kriptografi
│   ├── hash_demo.py                 → MD5, SHA-1, SHA-2, SHA-3, BLAKE2b, dan Avalanche Effect
│   └── hmac_demo.py                 → HMAC, Token JWT, dan Simulasi Timing Attack
│
├── 05_digital_signature/            ← Tanda Tangan Digital
│   └── dsa_rsa_sign.py              → Skema RSA-PSS dan DSA, serta Integritas Dokumen Legal
│
├── 06_attacks/                      ← Simulasi Kriptanalisis dan Serangan
│   ├── frequency_analysis.py        → Analisis Frekuensi Huruf dan Klasifikasi Cipher
│   └── birthday_attack.py           → Simulasi Birthday Paradox dan Pencarian Collision
│
└── 07_secure_crud/                  ← Aplikasi Praktis
    └── secure_crud.py               → CRUD Catatan Aman (AES-256 + HMAC)
```

---

## Panduan Penggunaan

### 1. Prasyarat Sistem
Pastikan Anda telah menginstal Python 3.10 atau versi yang lebih baru di sistem Anda.

### 2. Instalasi Pustaka
Instal seluruh dependensi yang diperlukan dengan menjalankan perintah berikut:
```bash
pip install -r requirements.txt
```

### 3. Menjalankan Launcher Utama
Untuk mengakses seluruh eksperimen melalui menu interaktif yang terintegrasi, jalankan:
```bash
python main.py
```

### 4. Menjalankan Eksperimen Secara Terpisah
Setiap file demonstrasi dirancang agar dapat dijalankan secara mandiri. Contoh:
```bash
python 01_classical/caesar_cipher.py
python 02_symmetric/aes_demo.py
python 03_asymmetric/rsa_demo.py
```

---

## Ringkasan Materi Eksperimen

### Modul 1: Kriptografi Klasik
*   **Caesar Cipher:** Enkripsi dan dekripsi menggunakan pergeseran huruf tunggal alfabet. Dilengkapi visualisasi tabel pergeseran, implementasi Brute Force Attack, serta pencarian kunci otomatis berbasis skor frekuensi bahasa Inggris (*frequency scoring*).
*   **Vigenere Cipher:** Enkripsi substitusi poli-alfabetis dengan kunci berulang. Mempelajari *Index of Coincidence* (IoC) untuk mengukur tingkat keacakan teks serta Kasiski Test untuk mengestimasi panjang kunci secara statistik.
*   **Playfair Cipher:** Enkripsi berbasis digraph (pasangan huruf). Menunjukkan proses pembentukan matriks kunci 5x5 (dengan penyatuan huruf I dan J) serta aturan pergeseran baris, kolom, dan persegi panjang (*rectangle*).

### Modul 2: Kriptografi Simetris
*   **AES-256:** Implementasi Advanced Encryption Standard dengan panjang kunci 256-bit. Membandingkan Cipher Block Chaining (CBC) yang menggunakan PKCS7 Padding dengan Counter (CTR) mode yang bertindak sebagai stream cipher. Menunjukkan pentingnya IV (Initialization Vector) yang unik di setiap sesi.
*   **DES dan Triple-DES:** Demonstrasi skema enkripsi standar lama berbasis Feistel Network 16 ronde (DES) dan perkembangannya menjadi Triple-DES (EDE mode: Encrypt-Decrypt-Encrypt). Menyertakan analisis kinerja komputasi dan ketahanan terhadap *brute force*.

### Modul 3: Kriptografi Asimetris
*   **RSA-2048:** Proses pembangkitan pasangan kunci (*key generation*) secara matematis dari dua bilangan prima besar. Simulasi enkripsi aman dengan skema padding OAEP serta pembuatan tanda tangan digital menggunakan skema PSS.
*   **Diffie-Hellman Key Exchange:** Protokol pertukaran kunci secara aman melalui saluran komunikasi publik yang tidak terpercaya. Menggunakan grup MODP 2048-bit (RFC 3526 Group 14) untuk menghasilkan kunci bersama (*shared secret*) yang kemudian diturunkan menjadi kunci enkripsi AES-256.

### Modul 4: Fungsi Hash dan Message Authentication Code
*   **Fungsi Hash:** Pengujian komparatif dari MD5, SHA-1, SHA-256, SHA-512, SHA3-256, SHA3-512, dan BLAKE2b. Menunjukkan sifat-sifat utama hash seperti *determinism*, *one-way* (pre-image resistance), *fixed-length output*, serta *avalanche effect* (perubahan 1 bit input mengubah ~50% bit output).
*   **HMAC (Hash-based MAC):** Mekanisme autentikasi pesan menggunakan kunci simetris berbasis formula manual RFC 2104. Mengandung simulasi struktur data JSON Web Token (JWT) serta penanganan *Timing Attack* menggunakan komparasi waktu konstan (`hmac.compare_digest`).

### Modul 5: Tanda Tangan Digital
*   **RSA-PSS dan DSA:** Penerapan algoritma tanda tangan digital untuk menjamin *authenticity* (keabsahan pengirim), *integrity* (integritas data), dan *non-repudiation* (anti-penyangkalan). Dilengkapi simulasi verifikasi dokumen kerja sama legal digital serta pemahaman konsep rantai sertifikat (*certificate chain*).

### Modul 6: Simulasi Serangan (Kriptanalisis)
*   **Frequency Analysis Attack:** Serangan terhadap cipher substitusi klasik dengan menganalisis kecenderungan kemunculan huruf pada bahasa tertentu (disajikan dalam bentuk visualisasi ASCII bar chart).
*   **Birthday Attack Simulation:** Eksperimen praktis untuk mendemonstrasikan kelemahan fungsi hash terhadap tumbukan (*collision*). Menunjukkan cara kerja Birthday Paradox untuk mencari collision pada hash pendek 16-bit dan partial collision MD5 20-bit.

### Modul 7: Aplikasi Praktis
*   **Secure CRUD Catatan Aman:** Implementasi integratif pengelola catatan terenkripsi. Menggunakan KDF (PBKDF2) untuk derivasi kunci enkripsi dan integritas dari Master Password, enkripsi simetris AES-256-CBC untuk menyembunyikan isi data catatan, dan HMAC-SHA256 untuk menjamin integritas berkas database JSON terhadap manipulasi di luar aplikasi.

---

## Kebutuhan Sistem dan Pustaka

| Nama Pustaka | Versi Minimal | Deskripsi Peran |
| :--- | :--- | :--- |
| `pycryptodome` | 3.20.0 | Operasi kriptografi modern (AES, DES, RSA, DSA, Padding) |
| `colorama` | 0.4.6 | Pewarnaan dan pemformatan output pada terminal lintas platform |
| `tabulate` | 0.9.0 | Pemformatan tabular data perbandingan pada konsol |

---

## Referensi Ilmiah

*   **NIST FIPS 197** — Advanced Encryption Standard (AES) Standard
*   **NIST FIPS 186-4** — Digital Signature Standard (DSS)
*   **RFC 3526** — More Modular Exponential (MODP) Diffie-Hellman Groups for Internet Key Exchange (IKE)
*   **RFC 2104** — HMAC: Keyed-Hashing for Message Authentication
*   **RFC 8017** — PKCS #1: RSA Cryptography Specifications Version 2.2
*   **SHAttered (2017)** — The first practical collision attack against SHA-1
*   *Understanding Cryptography* — Christof Paar & Jan Pelzl
*   *Applied Cryptography* — Bruce Schneier

---

## Batasan Tanggung Jawab (Disclaimer)

Eksperimen yang terdapat dalam proyek ini disediakan murni untuk keperluan akademis, pendidikan, dan pembelajaran mandiri. Kode demonstrasi penyerangan (seperti brute force, analisis frekuensi, dan birthday attack) ditujukan untuk memahami kelemahan algoritma lama dan tidak boleh digunakan untuk aktivitas ilegal atau merugikan pihak lain.

---
*Mata Kuliah Kriptografi - Semester 4 - Peminatan Cyber Security*
