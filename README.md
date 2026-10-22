# netbox-fortigate-importer

A NetBox plugin that imports FortiGate firewall configurations into NetBox.
Upload a configuration file (drag and drop, or through the REST API), review
what would change, try it with a dry run, apply it, and roll it back if
needed. Later imports of the same firewall are delta syncs: changed and
deleted objects wait for a person to decide.

> Work in progress. The plan is in the project's planning document; this
> README grows with each feature.

## What it reads

- Plain-text backups and `show full-configuration` output, gzip-compressed
  files, and password-encrypted backups (FortiOS up to 7.4.3). FortiOS
  7.4.4 changed the backup encryption; those files aren't supported yet.
- Single-VDOM and multi-VDOM configurations, from hardware and VM models,
  FortiOS 5.4 to 7.4.

## What it never keeps

The configuration file is read in memory and never saved. Passwords,
pre-shared keys, private keys, certificates and SNMP communities are
dropped while reading, before anything is stored. Only the data the
importer needs is saved on the import run.

## Requirements

- NetBox **4.7** or later. Tested with NetBox 4.7.0 and 4.7.3.
- No other plugins required. When installed, these are used too:
  netbox-security (firewall objects), netbox-routing (static routes, BGP,
  OSPF, route filters) and netbox-change-approval (imports go through
  approval for users without bypass).

## Installation

Not on PyPI; install from GitHub into NetBox's Python environment:

```bash
pip install git+https://github.com/mattivaisanen/netbox-fortigate-importer.git
```

Add it to `configuration.py` and run the migrations:

```python
PLUGINS = ['netbox_fortigate_importer']
```

```bash
cd /opt/netbox/netbox && python manage.py migrate
```

Settings: [docs/configuration.md](docs/configuration.md).

## License

Apache-2.0. Test configurations from other projects are listed with their
licences in `netbox_fortigate_importer/tests/fixtures/third_party/README.md`.
