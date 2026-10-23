# Changelog

## Unreleased

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
