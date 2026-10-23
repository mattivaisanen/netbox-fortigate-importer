"""
Turning uploaded bytes into configuration text.

Handles plain text backups, gzip-compressed ones and password-encrypted
backups. Everything happens in memory: nothing here writes a file.

Encrypted backups carry a version in the header line's second field. Two
layouts are known, both AES-256-GCM over gzip-compressed configuration
text, both checked against real FortiGate backups:

    "format 4" (FortiOS up to 7.4.3 / 7.2.8):

        #FGBK|4|FGVM64|7|04|2360|\\n      header line
        12 bytes                            AES-GCM nonce (IV)
        16 bytes                            AES-GCM tag
        rest                                ciphertext

    The key is SHA-256 of the password, with no salt.

    "format 6" (FortiOS 7.2.9+, 7.4.4+ and 7.6+):

        #FGBK|6|FG120G|7|04|2933|\\n       header line
        16 bytes                            PBKDF2 salt
        12 bytes                            AES-GCM nonce (IV)
        16 bytes                            AES-GCM tag
        rest                                ciphertext

    The key is PBKDF2-HMAC-SHA256 of the password over that salt, 4096
    rounds. This is the FG-IR-23-423 / CVE-2024-21754 fix: a per-backup
    salt and a slow KDF instead of the old bare SHA-256.

Both layouts are tried (the header's format field decides the order), and
AES-GCM's tag tells a right key from a wrong one, so there is never a false
match. A header whose format field is newer than any we know, when neither
layout decrypts it, is reported as an unsupported newer format rather than
as a wrong password.
"""
import hashlib
import zlib

ENCRYPTED_MAGIC = b'#FGBK|'
#: Largest decompressed configuration read by default. A real backup is a
#: few megabytes; a small "zip bomb" must not fill the web worker's memory.
MAX_TEXT_BYTES = 500 * 1024 * 1024
GZIP_MAGIC = b'\x1f\x8b'

#: AES-GCM nonce and tag lengths, shared by both layouts.
NONCE_LEN = 12
TAG_LEN = 16
#: The "format 6" layout: a PBKDF2 salt in front, then nonce + tag.
SALT_LEN = 16
PBKDF2_ROUNDS = 4096
#: Newest header "format" field this module knows how to decrypt.
NEWEST_KNOWN_FORMAT = 6


class ConfigFileError(ValueError):
    """Base class: the file can't be turned into configuration text."""


class PasswordRequired(ConfigFileError):
    def __init__(self, header=None):
        self.header = header or {}
        super().__init__('This configuration file is encrypted. Enter the password it was saved with.')


class DecryptionError(ConfigFileError):
    pass


class UnsupportedFormat(ConfigFileError):
    pass


class UnsupportedEncryption(UnsupportedFormat):
    """An encrypted backup in a newer format than this module can read."""


def is_encrypted(data):
    return data.startswith(ENCRYPTED_MAGIC)


def encrypted_header(data):
    """
    Fields of an encrypted backup's header line, e.g.
    {'format': '4', 'model': 'FGVM64', 'major': 7, 'minor': 4, 'build': 2360}.
    Unknown or malformed fields are left out.
    """
    end = data.find(b'\n')
    if end == -1 or end > 256:
        return {}
    parts = data[:end].decode('ascii', 'replace').split('|')
    info = {}
    keys = ('magic', 'format', 'model', 'major', 'minor', 'build')
    for key, value in zip(keys, parts):
        if key == 'magic':
            continue
        if key in ('major', 'minor', 'build'):
            try:
                info[key] = int(value)
            except ValueError:
                continue
        else:
            info[key] = value
    return info


def _format_number(header):
    """The header's format field as an int, or None if it isn't a number."""
    try:
        return int(header.get('format'))
    except (TypeError, ValueError):
        return None


def _version_label(header):
    if 'major' not in header or 'minor' not in header:
        return 'a newer FortiOS release'
    label = f"FortiOS {header['major']}.{header['minor']}"
    if header.get('build') is not None:
        label += f" (build {header['build']})"
    return label


def _key_v4(password, body):
    """Old layout: SHA-256 of the password, no salt. Returns (key, nonce, tag, ct)."""
    key = hashlib.sha256(password.encode('utf-8')).digest()
    nonce = body[:NONCE_LEN]
    tag = body[NONCE_LEN:NONCE_LEN + TAG_LEN]
    ciphertext = body[NONCE_LEN + TAG_LEN:]
    return key, nonce, tag, ciphertext


def _key_v6(password, body):
    """New layout: a 16-byte salt, then PBKDF2-HMAC-SHA256 (4096 rounds)."""
    salt = body[:SALT_LEN]
    rest = body[SALT_LEN:]
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ROUNDS, 32)
    nonce = rest[:NONCE_LEN]
    tag = rest[NONCE_LEN:NONCE_LEN + TAG_LEN]
    ciphertext = rest[NONCE_LEN + TAG_LEN:]
    return key, nonce, tag, ciphertext


#: Shortest body each layout can possibly have (one byte of ciphertext).
_MIN_BODY = {_key_v4: NONCE_LEN + TAG_LEN + 1, _key_v6: SALT_LEN + NONCE_LEN + TAG_LEN + 1}


def decrypt_backup(data, password, max_size=MAX_TEXT_BYTES):
    """Decrypt an encrypted backup. Returns the decompressed bytes."""
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - NetBox ships cryptography
        raise UnsupportedFormat('Decrypting needs the "cryptography" Python package.') from exc

    end = data.find(b'\n')
    if end == -1:
        raise UnsupportedFormat('The encrypted file has no header line.')
    body = data[end + 1:]

    header = encrypted_header(data)
    fmt = _format_number(header)
    # Try the layout the header points at first, then the other; the GCM tag
    # rules out a false match, so the order only saves a wasted PBKDF2.
    layouts = [_key_v4, _key_v6] if fmt is not None and fmt < 6 else [_key_v6, _key_v4]
    tried = False
    for derive in layouts:
        if len(body) < _MIN_BODY[derive]:
            continue
        tried = True
        key, nonce, tag, ciphertext = derive(password, body)
        try:
            plain = AESGCM(key).decrypt(nonce, ciphertext + tag, None)
        except InvalidTag:
            continue
        return _maybe_decompress(plain, max_size)

    if not tried:
        raise UnsupportedFormat('The encrypted file is too short; it may be truncated.')
    if fmt is not None and fmt > NEWEST_KNOWN_FORMAT:
        raise UnsupportedEncryption(
            f'This backup is in a newer encrypted format (version {fmt}) than the importer knows, '
            f'saved by {_version_label(header)}. If the password is right, back up the configuration '
            'again without a password and upload that file; the importer drops passwords and keys '
            'from it.'
        )
    raise DecryptionError('Wrong password, or the file is damaged.')


def _maybe_decompress(data, max_size=MAX_TEXT_BYTES):
    if not data.startswith(GZIP_MAGIC):
        return data
    # Stream it, so a tiny file that inflates to gigabytes stops at max_size.
    out = bytearray()
    try:
        while data:
            inflater = zlib.decompressobj(wbits=31)  # gzip; one per gzip member
            while data:
                out += inflater.decompress(data, max_size + 1 - len(out))
                if len(out) > max_size:
                    raise UnsupportedFormat(
                        f'The configuration is larger than {max_size // (1024 * 1024)} MB once '
                        'uncompressed; it is not read.')
                data = inflater.unconsumed_tail
                if inflater.eof:
                    break
            if not inflater.eof:
                raise EOFError('the compressed data ends early')
            data = inflater.unused_data
            if data and not data.startswith(GZIP_MAGIC):
                break  # trailing padding after the last member
    except (OSError, EOFError, zlib.error) as exc:
        raise UnsupportedFormat(f'The compressed configuration is damaged: {exc}') from exc
    return bytes(out)


def _decode(data):
    for encoding in ('utf-8-sig', 'cp1252', 'latin-1'):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise UnsupportedFormat('The file is not text.')  # pragma: no cover - latin-1 never fails


def read_config_bytes(data, password=None, max_size=MAX_TEXT_BYTES):
    """
    Turn uploaded bytes into configuration text.

    Raises PasswordRequired when the file is encrypted and no password was
    given, DecryptionError for a wrong password, UnsupportedFormat for files
    that aren't FortiGate configurations.
    """
    if not data:
        raise UnsupportedFormat('The file is empty.')
    if is_encrypted(data):
        if not password:
            raise PasswordRequired(encrypted_header(data))
        data = decrypt_backup(data, password, max_size)
    else:
        data = _maybe_decompress(data, max_size)
    sample = data[:4096]
    if b'\x00' in sample:
        raise UnsupportedFormat('The file is binary, not a FortiGate configuration.')
    return _decode(data)
