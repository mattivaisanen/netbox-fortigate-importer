# netbox-fortigate-importer

A NetBox plugin that imports FortiGate firewall configurations into NetBox.
Upload a configuration file (drag and drop, or through the REST API), review
what would change, try it with a dry run, apply it, and roll it back if
needed. Later imports of the same firewall are delta syncs: changed and
deleted objects wait for a person to decide.

## How an import works

1. **Upload** under *FortiGate → New Import*: drop the file on the page.
   An encrypted backup asks for its password.
2. **Match**: the firewall is found by its serial number, or by its
   hostname when exactly one FortiGate has it and no serial number says
   otherwise. A FortiOS default hostname (the model, such as
   `FortiGate-VM64` or `FGT60F`) or a serial number used as hostname never
   picks a FortiGate on its own. When several FortiGates share the
   hostname, or it is a default one, you choose (the matches are
   suggested). The
   first time, you choose its NetBox device, or ask for a new one. A new
   device is not created yet: it is one of the changes in the plan, written
   on apply and removed again by a rollback.
3. **Review** the plan: every object that would be created, changed,
   adopted (an existing NetBox object the importer starts managing) or
   removed, field by field. New objects start approved; changes, removals
   and conflicts wait for you. Approve, skip, or keep NetBox's value.
4. **Dry run** to check that everything would save, then **Apply**. Every
   apply is one entry in NetBox's change log and can be **rolled back**.

Later imports of the same firewall compare three things: the firewall's
configuration, NetBox now, and what the last import wrote. A value someone
edited in NetBox is kept as long as the firewall didn't change it; when
both changed, it's a conflict for you to decide. An object that is no
longer on the firewall is offered for deletion (or kept, see settings).
Before writing, every object is checked again: if someone changed it after
the plan was made, nothing is applied until you plan again.

Uploading a configuration that was imported before (the same file, or the
same configuration saved again, encrypted or not) says so: nothing changed
on the firewall, and the plan only shows what changed in NetBox since.

## Following a firewall over time

- **Firewall Changes** (a tab on every import): what changed in the
  FortiGate's own configuration since its previous import, whatever NetBox
  has: policies, addresses, routes, VPNs, settings added, changed or
  removed, field by field. Compare with any other import of the same
  firewall.
- **Journal**: every apply and rollback adds an entry to the device's
  journal (who, when, what changed, a link to the import). Turn it off with
  `journal_entries`.
- **Managed by FortiGate**: every NetBox object the importer manages shows
  a panel with its FortiGate, the fields the importer owns, the last import
  that synced it, and which owned fields were edited in NetBox since (the
  next import asks what to keep). On the FortiGate's own device page this
  is part of the single "FortiGate" panel, next to its firmware, last import
  and the Import configuration button.

## What it reads

- Plain-text backups and `show full-configuration` output, gzip-compressed
  files, and password-encrypted backups from every FortiOS version,
  including the newer encryption of FortiOS 7.2.9, 7.4.4, 7.6 and later. You
  are asked for the password when the backup is encrypted.
- Single-VDOM and multi-VDOM configurations, from hardware and VM models,
  FortiOS 5.4 to 7.4. Backups of single VDOMs (without the global part)
  are refused: back up the full configuration instead.

## What it creates in NetBox

- The device's platform (FortiOS), serial number, primary IP and a
  `fortigate` key in its config context (firmware, HA, DNS, NTP, SNMP,
  syslog, FortiAnalyzer/FortiManager).
- HA clusters as virtual chassis (import both units; the first one becomes
  the master), VDOMs as virtual device contexts, and a
  VRF per VDOM.
- Interfaces (physical, aggregate, hard/soft switch, VLAN, tunnel,
  loopback, VDOM link) with their VLANs, IP addresses and connected
  prefixes.
- VRRP groups, DHCP ranges and reservations, BGP AS numbers.
- IPsec VPNs: IKE and IPsec proposals and policies, profiles, tunnels and
  terminations. A tunnel between two imported FortiGates is one tunnel
  with both ends.

With [netbox-security](https://github.com/andy-shady-org/netbox-security)
installed, also the firewall's rules:

- Addresses (subnets, ranges, FQDNs), address groups, VIPs and VIP groups
  as addresses and address sets, scoped to the firewall (and VDOM) with
  netbox-security's identifier, so two FortiGates can both have "all".
- Custom services and service groups as applications and application sets.
- Zones, and interfaces that policies name directly, as security zones on
  their interfaces.
- Policies as security zone policies, in the firewall's order: one per
  source and destination interface pair.
- IP pools as NAT pools, VIPs as destination NAT rules, central SNAT or
  policy NAT as source NAT rules, on the device (or its VDOM).

With [netbox-routing](https://github.com/DanSheps/netbox-routing)
installed, also its routing:

- Static routes on the device, in the VDOM's VRF (blackhole and SD-WAN
  routes too).
- Prefix lists and access lists (as prefix lists), AS path lists,
  community lists and route maps, linked to each other as on the firewall.
  Their names start with the firewall (and VDOM), since netbox-routing
  names are unique across NetBox.
- BGP: a router per AS on the device, a scope per VDOM, the neighbors with
  their route maps and prefix lists, and neighbor groups as peer templates.
  Neighbor addresses are found in IPAM or created there.
- OSPF: an instance per VDOM, its areas and the interfaces its networks
  cover.

BGP network statements, BGP BFD and OSPF costs have no netbox-routing
field and are listed in the plan's notes. Passwords and keys are never
imported.

Country, MAC and dynamic addresses, excluded group members, negated
fields, users and schedules have no netbox-security form: they are left
out or written into the description, and the plan's notes list them.

Every object it creates gets the tag `fortigate-import`.

## What it never keeps

The configuration file is read in memory and never saved. Passwords,
pre-shared keys, private keys, certificates and SNMP communities are
dropped while reading, before anything is stored. Only the data the
importer needs is saved on the import run.

## Requirements

- NetBox **4.7** or later. Tested with NetBox 4.7.0 and 4.7.3.
- No other plugins required. When installed, these are used too:

  | Plugin | Used for | Tested version |
  | --- | --- | --- |
  | netbox-security | Firewall objects | 1.6.8 |
  | netbox-routing | Static routes, BGP, OSPF, route filters | 0.5.1 |
  | netbox-change-approval | Imports go through approval for users without bypass | 0.5.4 |

  The importer writes into these plugins' models, so other versions may
  fail or miss fields. NetBox logs a warning at startup when an installed
  version differs from the tested one in its first two numbers.

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

Settings and permissions: [docs/configuration.md](docs/configuration.md).

Dry runs, applies and rollbacks run as NetBox background jobs, so NetBox's
worker (`manage.py rqworker`) must be running. The worker also deletes old
import runs once a day (`run_retention_days`).

## REST API

`/api/plugins/fortigate-importer/`: `fortigates/`, `runs/` (with
`POST runs/upload/` for a multipart file, and `runs/<id>/plan/`,
`dry-run/`, `apply/`, `rollback/`) and `changes/` (`PATCH` a decision).

## Upgrading

```bash
pip install --upgrade git+https://github.com/mattivaisanen/netbox-fortigate-importer.git
cd /opt/netbox/netbox && python manage.py migrate
```

Then restart NetBox and its worker.

## Uninstalling

The importer's own records (FortiGates, import runs) have change log,
journal and tag rows in NetBox's tables. Remove those first, while the
plugin is still installed, then its tables:

```bash
cd /opt/netbox/netbox
python manage.py prepare_fortigate_uninstall
python manage.py migrate netbox_fortigate_importer zero
```

Then take `netbox_fortigate_importer` out of `PLUGINS`, restart NetBox and
`pip uninstall netbox-fortigate-importer`. Everything the imports created
(devices, interfaces, IP addresses, security and routing objects, the
`fortigate` config context key and the import tag) is ordinary NetBox data
and stays. `prepare_fortigate_uninstall --dry-run` shows what it would
remove.

## License

Apache License 2.0, see [LICENSE](LICENSE). Test configurations from other
projects are listed with their licenses in
`netbox_fortigate_importer/tests/fixtures/third_party/README.md`.
