# Developer guide

How the importer works and why, for anyone changing it.

## Pipeline

1. **Bytes to text** (`parser/files.py`): plain, gzip or encrypted. Two
   encrypted layouts, both AES-256-GCM over gzip, both `#FGBK|` headers:
   "format 4" (FortiOS up to 7.4.3 / 7.2.8) uses key = SHA-256 of the
   password with no salt; "format 6" (FortiOS 7.2.9+, 7.4.4+, 7.6+, the
   FG-IR-23-423 / CVE-2024-21754 fix) prepends a 16-byte salt and derives
   the key with PBKDF2-HMAC-SHA256, 4096 rounds. Both are tried (the
   header's format field picks the order) and the GCM tag rules out a false
   match; a format field newer than `NEWEST_KNOWN_FORMAT` that neither
   layout reads raises `UnsupportedEncryption`. In memory only. Decompression streams and stops at
   `max_size` (ten times `max_upload_mb`), so a small "zip bomb" can't
   exhaust memory. `services.ingest` is `@sensitive_variables()` and the
   upload views mark `password` sensitive, so Django's error reports never
   show the file, its text or the password.
2. **Text to tree** (`parser/cli.py`): a shell-like tokenizer (quoted and
   bare parts join, backslash escapes, multi-line quoted values) and a
   stack machine for `config` / `edit` / `set` / `next` / `end`, plus the
   script commands `rename`, `move`, `clone`, `delete`, `purge`, `append`,
   `select`, `unselect`. A quote left open at a line end starts a multi-line
   value only if a later quote closes it at the end of its line (scripts,
   certificates); otherwise it is a typo and is closed at the end of its own
   line, so one stray quote can't swallow the file and script lines are
   never read as configuration.
3. **Secrets out** (`parser/secrets.py`): checked for every `set` while
   parsing; flagged values never enter the tree. Only a count is kept.
   Some keys are secrets only in one table (`SECRET_KEYS_IN`): scripts,
   and automation webhooks' URL, body and headers.
4. **Layout** (`parser/layout.py`): header facts (model, firmware, VDOM
   mode, serial from the default `alias`) and the global / per-VDOM split.
   A backup of VDOMs without `config global` (a VDOM administrator's) is
   refused: without its interfaces everything firewall-wide would look
   deleted.
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
   webhooks, approval plugins), with that user's permissions (`may()` /
   `require()`: model permission before, constraints before and after each
   write, like NetBox's views; NetBox itself only checks in views and the
   API). The run and its FortiGate are locked (`select_for_update`) for
   the whole apply, so a re-plan, a decision or another apply or rollback
   of the same FortiGate waits and then refuses; the job carries the plan
   time the user saw and refuses a plan made again. Plan, decisions and
   discard refuse while a job of the run is queued or running
   (`jobs.busy()`). Removals first in reverse order, then
   writes in plan order, then the "deferred" fields (primary IP, virtual
   chassis master) once everything exists. Each item has its own savepoint
   and goes through `full_clean()` + `save()`. Before an object is written
   it is compared with the plan; a difference fails the item ("plan
   again"). By default one failure rolls the whole apply back. Events
   queued by a failed item are taken out of NetBox's event queue so no
   webhook fires for something that was rolled back. A dry run is the
   same with a rollback at the end. A delete fails when Django's
   `Collector` finds that it would also delete something the same apply
   does not delete (an IP someone added to an imported interface).
10. **Rollback** (`rollback.py`): the change log entries of the apply's
    request ID, newest first: creates deleted, updates and deletes
    restored from `prechange_data` with `deserialize_object()`. Refused
    when any of those objects has a later change log entry, or when
    deleting a created object would cascade to anything the import did not
    create, or would clear a reference on someone else's object such as a
    switch port's untagged VLAN (`cascade_victims()`, which also reads the
    collector's SET_NULL updates), or when the change log no longer has the
    entries of the objects the apply created (retention). Changes approved
    later by their approver are not undone, so their records stay. The import tag
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
- **Not taken over:** an existing object assigned to another device or VM
  (an IP on another firewall's interface), or one another FortiGate
  manages, is never adopted; it is left out with a note
  (`Planner.assigned_elsewhere()`). Creating a duplicate would fail
  NetBox's `ENFORCE_GLOBAL_UNIQUE`.
- **Adopted objects are only released:** `@meta.adopted` marks objects
  that existed before the importer took them over; a removal stops
  managing them instead of deleting.
- **Nothing removed from an incomplete file:** when the parser reports a
  truncated file (`ParseResult.truncated`, saved as `data['truncated']`), or a VDOM of a managed object is missing, the plan holds
  those removals back with a note.
- **Moved objects keep their record:** when a wanted key finds an object
  that a key the configuration no longer has managed (an IP address moved
  to another interface), the plan updates it under the new key and only
  drops the old record (`Planner.rekeyed`, `plan_rekey()`), instead of
  deleting and adopting the same object.
- **Fields written last that fail** (primary IP, chassis master) leave the
  object "applied", with what was not written in its error; with
  change-approval, rejecting only those fields keeps the object managed.
- **Decisions survive re-planning** for rows whose action, values and diff
  are unchanged (`carry_decisions()`).
- **Text is text:** configuration strings that look like reference tokens
  (`$ref:...`) are escaped with an extra `$` in the plan and unescaped when
  written (`escape_literals()`).

## NetBox objects

| FortiGate | NetBox |
| --- | --- |
| The firewall | its Device: platform FortiOS, serial, `local_context_data.fortigate`, primary IPv4 (management interface) |
| A firewall NetBox does not have | a new Device (name, site, role from the device choice; a Fortinet DeviceType named after the model unless one was chosen) |
| HA cluster | VirtualChassis named after the HA group (shared by both units), the first unit imported as master, each unit at the first free position |
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

With netbox-security (`mappers/security.py`; its docstring has the full
mapping):

| FortiGate | netbox-security |
| --- | --- |
| address (subnet), VIP | Address on a CustomPrefix (not an IPAM prefix: firewall objects would fill IPAM with host routes); a VIP is its mapped address |
| address (FQDN) | Address with a DNS name |
| address (range) | AddressSet of the subnets covering the range exactly |
| address group, VIP group | AddressSet (nested groups in `address_sets`) |
| custom service, group | Application (protocols, single ports; wide ranges only described), ApplicationSet |
| zone, interface named in a policy | SecurityZone + SecurityZoneAssignment per interface |
| policy | SecurityZonePolicy per source x destination interface, `index` = position |
| IP pool | NatPool + NatPoolMember (IPAM prefix, or IP range) |
| VIP | destination NatRule (+ a NatPool for the mapped address) |
| central SNAT / policy NAT | source NatRule; rule sets assigned to the device or VDC |

Why some choices:

- Names are scoped with `identifier` (`<FortiGate>` or `<FortiGate> <vdom>`);
  NatPool and NatRuleSet have no identifier, so it starts their names.
- Policies use one AddressList per address and side
  (`all (source)`, `all (destination)`): netbox-security refuses a policy
  whose source and destination share a list, which "all" to "all" would.
- A zone used on both sides of a policy gets `allow_intra_zone`, which
  netbox-security requires for such policies.
- NAT rules point at IPAM objects (netbox-security's model). The mapper
  reuses the core mapper's connected prefix under the same key, otherwise
  finds or creates one, release-only. A range that overlaps another
  NetBox range (NetBox refuses overlaps) is left out with a note.
- A group inside a group gets a slightly higher write order so its members
  exist first (the plan sorts by order, then key).

With netbox-routing (`mappers/routing.py`; its docstring has the full
mapping):

| FortiGate | netbox-routing |
| --- | --- |
| static route | StaticRoute (device, VRF, next hop, interface next hop, distance as metric) |
| prefix list, access list | PrefixList + PrefixListEntry on a netbox-routing CustomPrefix ("any" has none) |
| AS path list | ASPath + ASPathEntry |
| community list | CommunityList + CommunityListEntry; Community found or created (global) |
| route map | RouteMap + RouteMapEntry; matches on lists link to them, other matches and sets go in the JSON fields |
| BGP | BGPRouter per AS (on the device), BGPScope per VDOM VRF, BGPAddressFamily per IP version, BGPPeer + BGPPeerAddressFamily per neighbor, BGPPeerTemplate per neighbor group |
| OSPF | OSPFInstance per VDOM, OSPFArea (global, found or created), OSPFInterface per interface a network covers |

Why some choices:

- PrefixList, RouteMap, ASPath and CommunityList names are unique across
  NetBox, so their names start with `<FortiGate> [<vdom>]`.
- Access lists become prefix lists: netbox-routing has no access lists,
  and route maps match them by name. A non-exact rule gets `le 32`/`le 128`.
- netbox-routing refuses an `le` not longer than the prefix (FortiGate's
  `le 0` exact match: dropped) and, in the tested version, `ge` and `le`
  together: `le` is left out with a note.
- A BGP neighbor's address must be an IPAM IPAddress. The mapper reuses
  an interface address the core mapper plans, otherwise finds or creates
  one (release-only, shared: the other firewall's import may own it).
  Remote AS numbers become ASNs with the same rules as the local one.
- Planner: a many-to-many name in `lookup` (StaticRoute `devices`) only
  filters; the `m2m` values set it on create.

A tunnel between two FortiGates that are both imported is one Tunnel:
its name is built from both public addresses, sorted, so the second
firewall finds and joins the tunnel the first created.

## Matching a configuration to its FortiGate

`services.find_binding()`: the binding with the configuration's serial
number, else the only binding with its hostname whose serial doesn't
contradict it. `is_generic_hostname()` keeps FortiOS default hostnames (the
model name or code: `FortiGate-VM64`, `FGT60F`, `FGVM64`, `FortiWiFi-60F`)
and serial numbers out of that: they never match on their own, and the
device choice page suggests them (`candidate_devices()`) for the user to
confirm.

## A new device

Choosing "a new device" writes nothing to NetBox. The FortiGate (binding)
is saved without a device and with `new_device` (name, site, role, device
type pks). While `binding.device` is empty, `Context.device` is
`Ref('device')`, so every object that hangs on the device (interfaces,
VDCs, routes) refers to the planned device like to any other planned
object, and lookups that need it find nothing (they are creates).
`NativeMapper.device()` then plans the device as a normal create (lookup
name + site, so a device made in the meantime is adopted) and, without a
chosen type, a release-only `device-type/<slug>`.

The applier links the binding to the device as soon as it is created, in
the same savepoint, so a dry run or a failed apply leaves the binding as it
was. Rollback leaves the binding out of the change log replay (it is the
importer's record; refreshing its firmware would otherwise block every
rollback) and unlinks the device in `detach_device()` before deleting it;
`new_device` stays, so the next import plans the device again. With an
approval plugin the device may be created later than the apply:
`planner.attach_created_device()` links it on the next plan.

NetBox's `Device.save()` creates the components of the device type
(interface templates and so on). They did not exist when the plan was
made, so their planned interfaces are creates. A planned create stores the
names of its lookup fields (`proposed['lookup']`, only when the lookup is
made of plain fields that `create` repeats). When this apply created the
device, the applier's `made_by_netbox()` repeats the lookup of every
planned create that hangs on that device (`device` = `Ref('device')`)
before creating it. A match is updated instead
(written like a create, logged as a change, tagged, and marked adopted so
a later removal only stops managing it). Rollback deletes the device and
with it those interfaces.

## Reviewing with dependencies

Every planned change stores the keys it refers to (`depends_on`, from the
`Ref`s in its desired values). `dependencies.py` follows them: approving a
change whose prerequisites are creates that stay unapproved shows
`importrun_dependencies.html` ("approve them too" or "only my selection"),
and skipping one warns about approved changes that need it. A prerequisite
that already exists in NetBox (adopt, update, conflict, no change) needs no
approval: the applier resolves it by its pk. When an item is skipped at
apply time because a prerequisite is missing, `Applier.unresolved_text`
names that change and why it was not written.

Dry-run results live in `ImportRun.dry_run['items']` (by key), not on the
changes, so the change list reads them through the `dry_run` filter and
the table's `dry_run` column.

## Job progress

While a job of the run is queued or running, the run page shows a spinner
and polls `runs/<pk>/job-status/` (JSON: `active`, the job's `status`, the
run's `run_status`; needs view permission on the run). The poll starts at
1.5 s and slows to at most 10 s; once no job is active it reloads the page,
which then shows the results.

## Job errors

`jobs.enqueue()` turns any failure to queue a job (database, Redis) into
`QueueError`, shown as a message (503 in the API). `jobs.workers_running()`
asks Redis whether an RQ worker runs, so the run page can warn while a job
waits for a worker that isn't there. A job that raises writes
"<Action> did not run: <error>" to `ImportRun.error`.

## Uploads

`views.InMemoryUploadHandler` replaces Django's upload handlers for the
upload view (and the API's upload action) so a file of any size up to
`max_upload_mb` stays in memory; Django would otherwise spill uploads over
2.5 MB to a temporary file. The view is `csrf_exempt` with `csrf_protect`
inside, because the handlers must be replaced before anything reads the
request body. The page posts with `fetch()` so an encrypted backup can be
sent again with its password without choosing the file again.

## History

`compare.py` works on `ImportRun.data` only, never on NetBox:

- `content_hash()` hashes the extracted data (without `stats`, `warnings`
  and other bookkeeping) into `ImportRun.data_sha256`. The same
  configuration gives the same hash whether it came plain or as an
  encrypted backup (whose file hash differs every time). `same_as()` finds
  an earlier run with the same file or data hash; the upload view and the
  run page warn about it. The plan is still made: NetBox may have changed.
- `compare()` lists firewall changes between two runs' data. List items are
  matched by `id` (policies, DHCP servers), `seq` (static routes) or
  `name`, with the address family; single blocks (BGP, OSPF, HA, settings)
  are compared key by key. Shown on the run's "Firewall Changes" tab.

`journal.py` writes one `JournalEntry` per apply and rollback, after the
transaction commits and outside its request, so it is not part of the
import's change log and a rollback leaves it alone. It goes on the device,
or on the FortiGate while it has none. Failures are logged, never raised.
Rolling back an import that created the device deletes the importer's own
entries on it (`journal.own_entries()`) instead of refusing as for other
newer work.

`template_content.ManagedByFortiGatePanel` has `models = None` (every
detail page) and shows the `ManagedObject` rows of the object: owned
fields from `ManagedObject.fields`, each compared with the object now
(`read_field`/`read_m2m`, as the planner does) to mark NetBox edits.
It skips a device that has a binding: there `DeviceFortiGatePanel` shows
the same rows (`inc/managed_rows.html`) inside the one "FortiGate" panel,
so the device page has a single panel.

## Working with netbox-change-approval

`integrations/change_approval.py`. The importer's own models are not
NetBoxModel, so recording a run never needs approval. The apply runs as
the user, so change-approval decides like for any edit:

- A change set "FortiGate import: <run>" is opened; requests join it and
  it is submitted at the end (removed when empty).
- Items run under change-approval's `BatchCollector` (RAISE mode), like a
  bulk edit: a gated update or delete raises `ChangeApprovalRequired`; the
  importer rolls back that item's savepoint, saves the request and marks
  the item "Pending". A gated delete that change-approval's
  `wrap_model_delete` isolated itself is seen by the growing queue. A
  create is written and marked pending by change-approval itself.
- An object with a pending request is "blocked".
- A post_save receiver on ChangeRequest follows decisions: approved marks
  the item applied and confirms the record; rejected or withdrawn marks it
  rejected and restores the record, so the next import proposes it again.
- Rollback withdraws the run's pending requests.
- Dry runs go through the gate too, so they show what would wait for
  approval; the change set is not submitted and everything rolls back
  (change-approval only notifies after commit).

## Tests

`tests/test_parser.py` (no database), `tests/test_apply.py` (plan, apply,
delta, conflicts, drift, rollback, two firewalls), `tests/test_views.py`
(upload, password prompt, memory-only upload, review, API, jobs),
`tests/test_safety.py` (permissions, cascades, locking, matching),
`tests/test_review.py` (dependency prompts, dry-run results, job errors),
`tests/test_history.py` (same-file warning, journal, managed panel,
firewall changes) and
`tests/test_change_approval.py`, `tests/test_security.py` and
`tests/test_routing.py` (skipped unless the plugin is installed).

Fixtures in `tests/fixtures/` are not part of the wheel, so run the tests
from a checkout (`pip install -e`). CI runs on pull requests and on manual
runs (`workflow_dispatch`), not on pushes to `main`.
