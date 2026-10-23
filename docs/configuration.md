# Configuration

Settings go in NetBox's `configuration.py`:

```python
PLUGINS_CONFIG = {
    'netbox_fortigate_importer': {
        'max_upload_mb': 50,
    },
}
```

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `max_upload_mb` | int | `50` | Largest configuration file accepted, in megabytes. Files are held in memory only. A compressed file may unpack to at most ten times this. |
| `auto_approve_creates` | bool | `True` | New objects start approved in the review. Changes and deletes always wait for a person. |
| `vrf_per_vdom` | bool | `True` | In multi-VDOM configurations, put each VDOM in its own VRF, named `<FortiGate> <vdom>`. VDOMs often reuse the same subnets, which NetBox's global uniqueness check refuses without VRFs. FortiOS VRF numbers inside a VDOM always get their own VRF. |
| `create_connected_prefixes` | bool | `True` | Create prefixes for the networks on the firewall's interfaces. |
| `config_context` | bool | `True` | Write the firewall's settings (DNS, NTP, SNMP, syslog, ...) into the device's local config context under the `fortigate` key. |
| `import_tag` | str | `"fortigate-import"` | Tag added to every object the importer creates. |
| `default_delete_action` | str | `"delete"` | What a firewall object that disappeared proposes for its NetBox object: `delete`, `unmanage` (keep it, stop syncing) or `deprecate` (status "deprecated" where the model has one, otherwise delete). Deletes always wait for review. |
| `continue_on_error` | bool | `False` | When applying, keep going past items that fail (each in its own savepoint) instead of rolling the whole run back. |

Per-firewall overrides of `auto_approve_creates`, `vrf_per_vdom`,
`create_connected_prefixes`, `config_context`, `continue_on_error` and
`default_delete_action` are set on the FortiGate's edit page (stored in the
FortiGate's `options`), as is the RIR used for new ASNs.

## Permissions

| Permission | Allows |
| --- | --- |
| `netbox_fortigate_importer.add_importrun` | Uploading configurations |
| `netbox_fortigate_importer.change_importrun` | Planning again, discarding runs |
| `netbox_fortigate_importer.change_plannedchange` | Reviewing (approve, skip, keep NetBox) |
| `netbox_fortigate_importer.apply_importrun` | Dry runs and applying |
| `netbox_fortigate_importer.rollback_importrun` | Rolling back |
| `netbox_fortigate_importer.add_fortigatebinding` | Linking a configuration to a device, or to a new device (which the apply creates) |

Applying writes NetBox objects as the user who applied the run, with that
user's NetBox permissions: each object needs the add, change or delete
permission on its model, and permission constraints (for example "only
these sites") are checked before and after the write, like a form. An item
the user may not write fails with a message. Rollback checks the rolling
back user the same way. With netbox-change-approval installed, its approval
rules apply to those writes too.
