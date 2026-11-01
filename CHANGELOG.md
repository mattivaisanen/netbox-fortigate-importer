# Changelog

## 0.10.0 (2026-10-26)

Changed:

- Apply and Roll back ask for confirmation in a NetBox dialog instead of
  the browser's pop-up.
- Menu items, card titles and the import tab use Title Case like NetBox
  itself ("New Import", "Import Runs", "Firewall Changes").
- The status "Waiting for approval" is now "Pending", the same word
  netbox-change-approval uses.

Removed:

- Test configurations are no longer installed with the plugin.

## 0.9.0 (2026-10-25)

Fixed:

- A FortiGate's device page showed two panels, "FortiGate" and "Managed by
  FortiGate", with overlapping information. They are now one "FortiGate"
  panel: imported as, firmware, last import, the fields the importer owns on
  the device (and which were edited in NetBox), last synced, and the Import
  configuration button.

## 0.8.0 (2026-10-24)

New:

- Uploading a configuration that was imported before says so ("Same
  configuration as import #12"), also when the same configuration comes as
  a new encrypted backup. Nothing changed on the firewall; the plan only
  shows what changed in NetBox since.
- A "Firewall changes" tab on every import shows what changed in the
  FortiGate's own configuration since its previous import: policies,
  addresses, routes, VPNs and settings added, changed or removed, field by
  field. You can compare with any other import of the same firewall.
- Every apply and rollback adds an entry to the device's journal: who,
  when, what changed, and a link to the import. Turn it off with the new
  `journal_entries` setting.
- Every NetBox object the importer manages shows a "Managed by FortiGate"
  panel: the FortiGate, the fields the importer owns, the last import that
  synced it, and which of those fields were edited in NetBox since, so you
  know which edits the next import will ask about.

## 0.7.0 (2026-10-24)

Fixed:

- A backup of single VDOMs (made by a VDOM administrator, without the
  global part) is refused with an explanation. Before, it was read as an
  empty configuration, and the plan proposed deleting the root VDOM, the
  interfaces and everything else firewall-wide.
- An IP address that moves to another interface on the firewall is moved
  in NetBox. Before, the plan both deleted and adopted it, and the apply
  failed.
- The second unit of an HA pair joins the first unit's virtual chassis at
  the next free position, and the first unit stays its master. Before, the
  second unit's device was not updated at all.
- Deleting or rolling back an imported object is refused when it would
  clear a reference on someone else's object, such as a switch port's
  untagged VLAN or another device's primary IP. Before, NetBox cleared it
  silently.
- A device whose primary IP was skipped (or failed with "keep going past
  failed items") shows as applied, with what was not written, instead of
  "skipped" or "failed".
- With netbox-change-approval: rejecting only a device's primary IP or a
  chassis master keeps the device managed by the importer. A failed apply
  no longer shows changes as "waiting for approval".
- Scripts and automation webhooks' URLs, bodies and headers (which carry
  tokens) are dropped like passwords.
- Choosing a device whose FortiGate has another serial number warns.
  An import already linked to a FortiGate can no longer be moved to
  another one.
- "A new device" with a name NetBox already has (at that site) is linked
  to the FortiGate when the import is applied.
- The job log of a dry run shows the counts of that dry run, not the
  previous one.

## 0.6.0 (2026-10-23)

New:

- While a dry run, apply or rollback runs, the import page shows a loader
  and refreshes by itself when the job is done.

Fixed:

- Importing into a new device whose device type has interfaces no longer
  fails with "Interface with this Device and Name already exists". NetBox
  adds the device type's interfaces when it creates the device; the import
  now matches them by name and fills them in from the configuration,
  instead of trying to create them a second time. Interfaces of the device
  type that the configuration does not have are left as they are. Plans
  made with an earlier version: press Plan again before the dry run.
- The job log of a dry run shows its counts ("40 applied, 2 failed")
  instead of "Dry run: %s".

## 0.5.0 (2026-10-23)

New:

- Password-encrypted backups from FortiOS 7.2.9, 7.4.4, 7.6 and later now
  import. These versions changed how the backup is encrypted (the
  CVE-2024-21754 fix): a per-backup salt and a slower key derivation. The
  importer reads both the old and the new layout, so you can upload an
  encrypted backup from any version and are simply asked for its password.
  0.3.0 had recognised these files and asked for an unencrypted export
  instead; that is no longer needed.

## 0.4.0 (2026-10-23)

Fixed:

- A configuration whose hostname is a FortiOS default (the model name or
  code, such as `FortiGate-VM64`, `FGT60F`, `FGVM64`, `FortiWiFi-60F`) or a
  serial number is no longer matched to a FortiGate by that hostname, even
  when only one FortiGate has it: many firewalls share these names. The
  device choice page suggests the matches instead. Own hostnames still
  match as before.

## 0.3.0 (2026-10-23)

Fixed:

- Uploading a password-encrypted backup from FortiOS 7.2.9, 7.4.4 or later
  no longer says "wrong password". Those versions encrypt backups in a way
  the importer can't read yet, and the message now says so, names the
  version, and asks for a backup saved without a password instead of
  asking for the password again. Backups from 7.2.0 to 7.2.8 and 7.4.0 to
  7.4.3 no longer get a misleading hint about the new encryption.

## 0.2.0 (2026-10-23)

New:

- Approving a change that needs other changes (an IP address needs its
  interface, a route its VRF) asks whether to approve those too. Skipping a
  change warns about approved changes that need it. A change's page lists
  what it needs by name, with their decisions.
- A skipped item says which change it needed and why that one was not
  written ("not reviewed yet", "skipped", or its error).
- The last dry run's result shows on every change, and "Failed in dry run"
  lists the changes that would fail.
- The plan notes interfaces the device has but the configuration doesn't,
  for example from a device type that names its ports differently.

Fixed:

- "See failing items" after a dry run showed every change instead of the
  failing ones.
- When NetBox cannot queue a dry run, apply or rollback (database or Redis
  trouble), the page says so instead of showing a server error, and it
  warns when no background worker is running to start the job. A job that
  crashes leaves its error on the import's page.
- The "Not imported" list is folded into one line of the configuration box.
- The new or existing device choice shows proper radio buttons.

- Scripts stored in a configuration (`system auto-script`, automation
  actions) are kept as text. Before, their lines were read as configuration,
  so a script that adds an address made the import propose that address.
- A small compressed file that unpacks to a huge one is refused (limit:
  ten times `max_upload_mb`) instead of filling the server's memory.
- If reading a configuration fails unexpectedly, Django's error page and
  error e-mails no longer show the file's text or the backup password.
- Kerberos keytabs, RIP authentication strings, access keys and tokens are
  dropped as secrets like passwords.
- Uploads through the REST API with a browser session stay in memory too.
- REST API plan, dry run, apply and rollback work for users who may apply or
  roll back but not upload.
- Apply and rollback respect the user's NetBox permissions. Before, a user
  who could apply imports could create, change and delete any object
  through an import, also on sites their permissions exclude. The device
  choice only offers devices, sites and roles the user may see.
- A configuration is no longer matched to another FortiGate by hostname
  when their serial numbers differ. A hostname matches only when exactly
  one FortiGate has it; otherwise the device choice page suggests the
  matches and you choose.
- Rollback refuses when deleting an imported object would also delete
  later work, such as an IP address someone added to an imported interface.
- Deleting an object the firewall no longer has fails, with a list, when it
  would also delete objects the import does not delete; choose "stop
  managing" or move them first.
- While a dry run, apply or rollback is queued or running, the run cannot be
  planned again, decided or discarded, and two imports of the same
  FortiGate no longer apply at the same time.
- Changing decisions clears the last dry run, which no longer matches.
- The review page only returns to addresses on this NetBox after a decision.
- A configuration that looks truncated (also when it has many other
  warnings), or lacks VDOMs that earlier imports had, no longer proposes deleting what is missing; the plan says why.
- IP addresses on another device, and DHCP ranges, reservations and VRRP
  addresses another FortiGate manages, are no longer taken over (branches
  that reuse the same subnets). They are left out with a note suggesting a
  VRF per firewall.
- An object that existed in NetBox before an import adopted it is kept
  (only no longer managed) when the firewall drops it, instead of deleted.
- Planning again keeps the review decisions of items that did not change.
- Dry runs show what would wait for approval with netbox-change-approval.
- Fields written last (primary IP, virtual chassis master) that were not
  written, because the change waits for approval or failed with "keep going
  past failed items", are proposed again by the next import instead of
  being forgotten; the object itself stays managed.
- Rollback refuses when NetBox's change log no longer has the import's
  entries, instead of only forgetting the objects.
- Rollback keeps tracking changes that were approved and applied later by
  their approver (netbox-change-approval), and says so.
- An approved "deprecate" stops managing the object, like a direct apply.
- A prefix or access list rule whose prefix cannot be read no longer
  matches everything: a permit is left out, a deny becomes "deny any".
- Text in a configuration that starts with "$ref:" is written as text.
- Changes to many-to-many fields alone (tagged VLANs, members) go through
  full_clean() and carry the import's change log message.

## 0.1.0 (2026-10-23)

New:

- Read FortiGate configuration files: plain, gzip-compressed and
  password-encrypted backups (FortiOS up to 7.4.3), single and multi-VDOM.
  Secrets (passwords, pre-shared keys, private keys, SNMP communities) are
  dropped while reading and never stored.
- Upload a configuration by dragging it onto the page (or through the REST
  API). Encrypted backups ask for their password, which is never saved.
  The file stays in memory and is never written to disk.
- The firewall is matched to its NetBox device by serial number or
  hostname, or you choose the device. A new device (and its device type)
  is a change in the plan like any other: nothing is written before you
  apply, and a rollback removes it again.
- Review a plan of every change before anything is written: creates,
  updates, adoptions of existing objects, conflicts and removals, field by
  field. The list has pages; select single changes or everything listed to
  approve, skip or keep NetBox's value.
- Imports the device's platform, serial number, primary IP and settings
  (config context), HA clusters (virtual chassis), VDOMs (virtual device
  contexts and VRFs), interfaces, VLANs, IP addresses, connected prefixes,
  VRRP groups, DHCP ranges and reservations, BGP AS numbers and IPsec VPNs.
- Later imports are delta syncs: NetBox edits are kept unless the firewall
  changed the same value, conflicts are shown, removed objects are offered
  for deletion.
- Dry run, apply (all or nothing, re-checked against NetBox first) and
  rollback of an apply, all from NetBox's change log.
- With netbox-security, imports the firewall's addresses, address groups,
  VIPs, services, service groups, zones, policies, IP pools and NAT rules.
- With netbox-routing, imports the firewall's static routes, prefix and
  access lists, AS path and community lists, route maps, BGP (routers,
  neighbors with their filters, neighbor groups) and OSPF (instances,
  areas, interfaces).
- With netbox-change-approval, imports by users without bypass go through
  approval as one change set, and the import follows the decisions.
