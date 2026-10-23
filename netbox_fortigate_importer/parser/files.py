"""
Turning uploaded bytes into configuration text.

Handles plain text backups, gzip-compressed ones and password-encrypted
backups. Everything happens in memory: nothing here writes a file.

Encrypted backups (FortiOS up to 7.4.3) look like this, checked against a
real FortiOS 7.4 backup:

    #FGBK|4|FGVM64|7|04|2360|\\n      header line
    12 bytes                            AES-GCM nonce (IV)
    16 bytes                            AES-GCM tag
    rest                                ciphertext

The key is SHA-256 of the password and the plaintext is gzip-compressed
configuration text.

FortiOS 7.4.4 and 7.2.9 changed the key derivation (FG-IR-23-423,
CVE-2024-21754), and 7.6 and later use the new one too. The new format is
not described anywhere public and we have no sample, so it is not guessed:
the old method is still tried, and when it fails on a backup whose header
says it comes from one of those versions, the error says the encryption is
not supported instead of blaming the password. The header has no patch
number, only the build, so the version is told apart by build number.
"""
import hashlib
import zlib

ENCRYPTED_MAGIC = b'#FGBK|'
#: Largest decompressed configuration read by default. A real backup is a
#: few megabytes; a small "zip bomb" must not fill the web worker's memory.
MAX_TEXT_BYTES = 500 * 1024 * 1024
GZIP_MAGIC = b'\x1f\x8b'

#: (major, minor) -> first build with the new backup encryption:
#: 7.2.9 is build 1688, 7.4.4 is build 2662. 6.x and 7.0 never got the fix.
NEW_FORMAT_BUILDS = {(7, 2): 1688, (7, 4): 2662}
#: Every release from this (major, minor) on uses the new encryption.
NEW_FORMAT_FROM = (7, 6)


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
    """An encrypted backup from FortiOS 7.2.9+, 7.4.4+ or 7.6+."""


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


def uses_new_encryption(header):
    """
    True when the header says FortiOS 7.2.9+, 7.4.4+ or 7.6+, False when
    it says an older release, None when it doesn't say enough to tell.
    """
    major, minor = header.get('major'), header.get('minor')
    if major is None or minor is None:
        return None
    if (major, minor) >= NEW_FORMAT_FROM:
        return True
    first_build = NEW_FORMAT_BUILDS.get((major, minor))
    if first_build is None:
        return False
    build = header.get('build')
    if build is None:
        return None
    return build >= first_build


def _version_label(header):
    label = f"FortiOS {header['major']}.{header['minor']}"
    if header.get('build') is not None:
        label += f" (build {header['build']})"
    return label


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
    if len(body) < 12 + 16 + 1:
        raise UnsupportedFormat('The encrypted file is too short; it may be truncated.')
    nonce, tag, ciphertext = body[:12], body[12:28], body[28:]
    key = hashlib.sha256(password.encode('utf-8')).digest()
    try:
        plain = AESGCM(key).decrypt(nonce, ciphertext + tag, None)
    except InvalidTag:
        header = encrypted_header(data)
        new = uses_new_encryption(header)
        if new:
            raise UnsupportedEncryption(
                f'This backup was saved by {_version_label(header)}. FortiOS 7.2.9, 7.4.4 and later '
                'encrypt backups in a way the importer can\'t read yet, so the password can\'t be '
                'checked either. Back up the configuration again without a password and upload '
                'that file; the importer drops passwords and keys from it.'
            ) from None
        hint = ''
        if new is None:
            hint = (
                ' If the password is right, the backup may come from FortiOS 7.2.9, 7.4.4 or later, '
                'whose encryption is not supported yet.'
            )
        raise DecryptionError(f'Wrong password, or the file is damaged.{hint}') from None
    return _maybe_decompress(plain, max_size)


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
