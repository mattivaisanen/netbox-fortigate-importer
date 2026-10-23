"""Helpers shared by the tests."""
import gzip
import hashlib
import os
from pathlib import Path

FIXTURES = Path(__file__).parent / 'fixtures'
THIRD_PARTY = FIXTURES / 'third_party'

HQ = FIXTURES / 'fg100f_hq_multivdom.conf'
BRANCH = FIXTURES / 'fg60f_branch1.conf'
AZURE_100D = THIRD_PARTY / 'azure_fg100d_5.4.conf'
XUTILS_MULTI_VDOM = THIRD_PARTY / 'fortios_xutils_vm_6.2_multivdom.txt'
BATFISH = THIRD_PARTY / 'batfish'

ALL_FULL_CONFIGS = (HQ, BRANCH, AZURE_100D, XUTILS_MULTI_VDOM)


def read(path):
    return Path(path).read_bytes()


def encrypt_backup(text, password, model='FGT60F', major=7, minor=2, build=1639, fmt=4):
    """
    Make an encrypted backup the way FortiOS does. fmt=4 is the old layout
    (SHA-256 key, no salt, up to 7.4.3). fmt=6 is the new one (a 16-byte
    salt and PBKDF2-HMAC-SHA256, 4096 rounds; 7.2.9+, 7.4.4+, 7.6+).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if fmt == 6:
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 4096, 32)
    else:
        salt = b''
        key = hashlib.sha256(password.encode()).digest()
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, gzip.compress(text.encode()), None)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    header = f'#FGBK|{fmt}|{model}|{major}|{minor:02d}|{build}|\n'.encode()
    return header + salt + nonce + tag + ciphertext
