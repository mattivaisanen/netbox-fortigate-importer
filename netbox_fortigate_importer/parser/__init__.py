"""Reading FortiGate configuration files: decryption, parsing, secret removal."""
from .cli import ParseError, ParseResult, Section, parse
from .files import (
    DecryptionError, PasswordRequired, UnsupportedEncryption, UnsupportedFormat, read_config_bytes,
)

__all__ = [
    'DecryptionError', 'ParseError', 'ParseResult', 'PasswordRequired', 'Section',
    'UnsupportedEncryption', 'UnsupportedFormat', 'parse', 'read_config_bytes',
]
