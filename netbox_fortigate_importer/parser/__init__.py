"""Reading FortiGate configuration files: decryption, parsing, secret removal."""
from .cli import ParseError, ParseResult, Section, parse
from .files import DecryptionError, PasswordRequired, UnsupportedFormat, read_config_bytes

__all__ = [
    'DecryptionError', 'ParseError', 'ParseResult', 'PasswordRequired', 'Section',
    'UnsupportedFormat', 'parse', 'read_config_bytes',
]
