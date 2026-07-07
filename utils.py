"""
utils.py — Utilitas bersama untuk eksperimen kriptografi.
Pastikan terminal mendukung UTF-8 di Windows.
"""
import sys
import os


def setup_encoding():
    """Mengatur encoding stdout ke UTF-8 agar box characters tampil benar."""
    if sys.platform == "win32":
        # Atur code page ke UTF-8
        os.system("chcp 65001 > nul 2>&1")
        # Reconfigure stdout/stderr ke UTF-8
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
        except AttributeError:
            pass  # Python versi lama tidak mendukung reconfigure


# Panggil saat diimport
setup_encoding()
