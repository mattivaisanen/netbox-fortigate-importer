# Changelog

## Unreleased

New:

- Read FortiGate configuration files: plain, gzip-compressed and
  password-encrypted backups (FortiOS up to 7.4.3), single and multi-VDOM.
  Secrets (passwords, pre-shared keys, private keys, SNMP communities) are
  dropped while reading and never stored.
