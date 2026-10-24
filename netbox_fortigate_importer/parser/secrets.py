"""
Which `set` values are secrets.

The parser calls is_secret() for every value and drops the ones it flags, so
secrets never reach the parse tree, the saved import data, logs or NetBox.
It errs on the side of dropping: the importer needs no secret for anything.
"""
import re

#: Keys whose value is always a secret, wherever they appear.
SECRET_KEYS = frozenset({
    'password', 'passwd', 'psksecret', 'psksecret-remote', 'ppk-secret',
    'private-key', 'passphrase', 'secret', 'key', 'auth-pwd', 'priv-pwd',
    'auth-password', 'md5-key', 'md5-keys', 'auth-key', 'api-key',
    'pre-shared-key', 'sae-password', 'wpa-psk', 'ldap-password',
    'sso-password', 'ddns-password', 'ddns-key', 'tacacs-key',
    'radius-secret', 'secondary-secret', 'tertiary-secret', 'server-secret',
    'shared-secret', 'eap-password', 'mpsk', 'ha-password', 'group-password',
    'enc-key', 'authentication-key', 'keyword', 'privkey', 'password2',
    'pin', 'otp', 'two-factor-password', 'fortitoken-cloud-password',
    'auth-code', 'psk', 'login-passwd', 'n-mhae-key', 'inter-controller-key',
    'certificate-key', 'client-secret', 'oauth-client-secret', 'token-secret',
    'mpsk-key', 'ipsec-psk', 'remote-auth-key', 'keytab', 'auth-string', 'access-key',
    'key-string', 'token', 'secret-key', 'auth-token',
})

#: Key fragments that mark a secret ("admin-password", "snmp-auth-pwd", ...).
_SECRET_FRAGMENTS = re.compile(
    r'(passw|passwd|secret|psk|passphrase|private-key|privkey|-pwd$|^pwd$|md5-key|auth-key|api-key)'
)

#: Tables whose entries are secrets as a whole (SNMP communities are
#: passwords; local certificates carry private keys).
SECRET_TABLES = (
    'vpn certificate local', 'vpn certificate ca', 'vpn certificate remote',
    'vpn certificate crl', 'vpn certificate ocsp-server',
    'certificate local', 'certificate ca', 'certificate remote', 'certificate crl',
    'system snmp community', 'system snmp user',
)

#: Keys that are secrets in one table: automation webhooks carry tokens in
#: their URL, body and headers, and scripts can hold anything.
SECRET_KEYS_IN = {
    'system automation-action': frozenset({'uri', 'http-body', 'headers', 'script'}),
    'system auto-script': frozenset({'script'}),
    'http-headers': frozenset({'key', 'value'}),  # automation-action's own header table
}

#: Keys of SNMP community entries that may stay (they name things, not secrets).
_SNMP_SAFE = frozenset({'status', 'events', 'query-v1-status', 'query-v2c-status',
                        'trap-v1-status', 'trap-v2c-status'})


def is_secret(key, values, table_path=''):
    """True if `set key values...` inside `table_path` must not be kept."""
    lowered = key.lower()
    if values and values[0] == 'ENC':
        return True
    if lowered in SECRET_KEYS or _SECRET_FRAGMENTS.search(lowered):
        return True
    if lowered in SECRET_KEYS_IN.get(table_path, ()):
        return True
    for value in values:
        if 'PRIVATE KEY' in value or 'BEGIN CERTIFICATE' in value or 'BEGIN ENCRYPTED' in value:
            return True
    if table_path in SECRET_TABLES:
        if table_path.endswith('snmp community'):
            return lowered not in _SNMP_SAFE  # the community name is the password
        return True
    return False
