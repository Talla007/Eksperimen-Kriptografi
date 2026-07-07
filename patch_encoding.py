"""Patch script to fix UTF-8 encoding on all experiment files."""
import os

INJECT = (
    'import sys as _sys, os as _os\n'
    '_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))\n'
    'import utils  # noqa: sets up UTF-8\n'
)

FILES = [
    '01_classical/caesar_cipher.py',
    '01_classical/vigenere_cipher.py',
    '01_classical/playfair_cipher.py',
    '02_symmetric/aes_demo.py',
    '02_symmetric/des_demo.py',
    '03_asymmetric/rsa_demo.py',
    '03_asymmetric/diffie_hellman.py',
    '04_hashing/hash_demo.py',
    '04_hashing/hmac_demo.py',
    '05_digital_signature/dsa_rsa_sign.py',
    '06_attacks/frequency_analysis.py',
    '06_attacks/birthday_attack.py',
]

MARKER = '=' * 61 + '\n"""'

for filepath in FILES:
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    if 'import utils' in content:
        print(f'[SKIP] {filepath}')
        continue
    if MARKER in content:
        content = content.replace(MARKER, MARKER + '\n' + INJECT, 1)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f'[PATCHED] {filepath}')
    else:
        # Try to inject at top after shebang/docstring end
        lines = content.split('\n')
        insert_at = 0
        in_docstring = False
        for i, line in enumerate(lines):
            if line.strip().startswith('"""') and not in_docstring:
                in_docstring = True
            elif '"""' in line and in_docstring:
                insert_at = i + 1
                break
        if insert_at > 0:
            lines.insert(insert_at, INJECT)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            print(f'[PATCHED-ALT] {filepath}')
        else:
            print(f'[FAILED] {filepath}')

print('\nDone.')
