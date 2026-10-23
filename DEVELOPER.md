# Developer guide

How the importer works and why, for anyone changing it.

## Pipeline

1. **Bytes to text** (`parser/files.py`): plain, gzip or encrypted
   (`#FGBK|` header, AES-256-GCM, key = SHA-256 of the password, gzip
   inside). In memory only.
2. **Text to tree** (`parser/cli.py`): a shell-like tokenizer (quoted and
   bare parts join, backslash escapes, multi-line quoted values) and a
   stack machine for `config` / `edit` / `set` / `next` / `end`, plus the
   script commands `rename`, `move`, `clone`, `delete`, `purge`, `append`,
   `select`, `unselect`. A stray quote is closed at the end of its line when
   the next line is a CLI command, so one typo can't swallow the file.
3. **Secrets out** (`parser/secrets.py`): checked for every `set` while
   parsing; flagged values never enter the tree. Only a count is kept.
4. **Layout** (`parser/layout.py`): header facts (model, firmware, VDOM
   mode, serial from the default `alias`) and the global / per-VDOM split.
5. **Extract** (`extract/`): the importer's own JSON document, the only
   thing saved (`ImportRun.data`).

## Optional plugins

`integrations/__init__.py` decides what is installed. Code that imports
another plugin lives in modules that are only imported when it is.
The plugin must work the same without them; CI runs the tests with none
and with all of them installed.

## From data to NetBox

6. **Mappers** (`mappers/`): turn the document into `Desired` objects
   (`mappers/base.py`): one NetBox object each, with a stable key
   (`interface/vlan10`, `vpn/root/to-hq/ike-policy`), the fields the
   importer *owns*, how to find an existing object (`lookup`), values set
   only on create, and references to other desired objects (`Ref(key)`).
   `native.py` and `vpn.py` cover core NetBox; `security.py` and
   `routing.py` the optional plugins. A reference to something the
   configuration doesn't have is dropped with a note instead of failing.
7. **Plan** (`planner.py`): every desired object is found first (managed
   by this FortiGate, else by its lookup = adopt, else create), then each
   owned field is compared three ways: firewall now, NetBox now, and what
   the importer wrote last time (`ManagedObject.fields`). See the table at
   the top of `planner.py`. Objects the importer managed that are gone
   from the configuration become delete / deprecate / unmanage. The result
   is `PlannedChange` rows; nothing is written to NetBox.
8. **Review**: creates start approved (setting), everything else waits.
   "Keep NetBox" on a conflict writes the firewall's other fields but keeps
   NetBox's value; the baseline still moves to the firewall's value so the
   next import of the same file doesn't ask again.
9. **Apply** (`applier.py`): one NetBox request ID, run as the user who
   pressed Apply through `apply_request_processors()` (change log,
   webhooks, approval plugins), removals first in reverse order, then
   writes in plan order, then the "deferred" fields (primary IP, virtual
   chassis master) once everything exists. Each item has its own savepoint
   and goes through `full_clean()` + `save()`. Before an object is written
   it is compared with the plan; a difference fails the item ("plan
   again"). By default one failure rolls the whole apply back. Events
   queued by a failed item are taken out of NetBox's event queue so no
   webhook fires for something that was rolled back. A dry run is the
   same with a rollback at the end.
10. **Rollback** (`rollback.py`): the change log entries of the apply's
    request ID, newest first: creates deleted, updates and deletes
    restored from `prechange_data` with `deserialize_object()`. Refused
    when any of those objects has a later change log entry. The import tag
    and change-approval's own records are left alone.

## Ownership rules

- **Owned fields** are the only ones compared and written. Everything else
  on an object (tenant, comments, custom fields, cables...) is the user's.
- **Physical interface type** is set on create only, so a user can pick
  the exact optic type.
- **Shared** objects (prefixes, VRRP addresses, a tunnel between two
  imported FortiGates) can be managed by several FortiGates; removing one
  while another still manages it only releases it.
- **Release-only** objects (platform, manufacturer, RIR, ASNs, IKE and
  IPsec proposals) are found or created by name and never deleted.
- **Partial** objects (the bound device) are never created or deleted;
  the importer owns only its platform, serial, config context key
  `fortigate`, virtual chassis fields and primary IPv4.

## NetBox objects

| FortiGate | NetBox |
| --- | --- |
| The firewall | its Device: platform FortiOS, serial, `local_context_data.fortigate`, primary IPv4 (management interface) |
| HA cluster | VirtualChassis named after the HA group, this device as master |
| VDOM | VirtualDeviceContext; with `vrf_per_vdom`, a VRF per VDOM |
| FortiOS VRF number | VRF `<name> <vdom> vrf<n>` |
| interface | Interface (physical, `lag`, `bridge` for hard/soft switches, `virtual` for VLAN, tunnel, loopback, VDOM link) with parent, LAG, bridge, VDCs, VRF, MTU, speed |
| VLAN interface | VLAN in a VLAN group per FortiGate (scoped to the device's site); untagged on the VLAN interface, tagged on its parent |
| interface IPs | IPAddress (secondary role for secondaries, loopback role on loopbacks) |
| connected networks | Prefix (shared) |
| VRRP | FHRPGroup + assignment + VRRP virtual IP |
| DHCP server | IPRange per range; reservations as IPAddress status DHCP |
| BGP AS | ASN (RIR from the FortiGate, or "Private" for private AS numbers) |
| IPsec phase 1 / 2 | IKEProposal, IKEPolicy, IPSecProposal, IPSecPolicy, IPSecProfile, Tunnel, TunnelTermination on the tunnel interface with the outside IP |

A tunnel between two FortiGates that are both imported is one Tunnel:
its name is built from both public addresses, sorted, so the second
firewall finds and joins the tunnel the first created.

## Uploads

`views.InMemoryUploadHandler` replaces Django's upload handlers for the
upload view (and the API's upload action) so a file of any size up to
`max_upload_mb` stays in memory; Django would otherwise spill uploads over
2.5 MB to a temporary file. The view is `csrf_exempt` with `csrf_protect`
inside, because the handlers must be replaced before anything reads the
request body. The page posts with `fetch()` so an encrypted backup can be
sent again with its password without choosing the file again.

## Working with netbox-change-approval

`integrations/change_approval.py`. The importer's own models are not
NetBoxModel, so recording a run never needs approval. The apply runs as
the user, so change-approval decides like for any edit:

- A change set "FortiGate import: <run>" is opened; requests join it and
  it is submitted at the end (removed when empty).
- Items run under change-approval's `BatchCollector` (RAISE mode), like a
  bulk edit: a gated update or delete raises `ChangeApprovalRequired`; the
  importer rolls back that item's savepoint, saves the request and marks
  the item "waiting for approval". A gated delete that change-approval's
  `wrap_model_delete` isolated itself is seen by the growing queue. A
  create is written and marked pending by change-approval itself.
- An object with a pending request is "blocked".
- A post_save receiver on ChangeRequest follows decisions: approved marks
  the item applied and confirms the record; rejected or withdrawn marks it
  rejected and restores the record, so the next import proposes it again.
- Rollback withdraws the run's pending requests.
- Dry runs don't go through change-approval.

## Tests

`tests/test_parser.py` (no database), `tests/test_apply.py` (plan, apply,
delta, conflicts, drift, rollback, two firewalls), `tests/test_views.py`
(upload, password prompt, memory-only upload, review, API, jobs) and
`tests/test_change_approval.py` (skipped unless installed).
