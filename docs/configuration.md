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
| `max_upload_mb` | int | `50` | Largest configuration file accepted, in megabytes. Files are held in memory only. |
| `auto_approve_creates` | bool | `True` | New objects start approved in the review. Changes and deletes always wait for a person. |
| `vrf_per_vdom` | bool | `False` | Put each VDOM (and each FortiOS VRF inside a VDOM) in its own VRF, named `<hostname>-<vdom>`. |
| `create_connected_prefixes` | bool | `True` | Create prefixes for the networks on the firewall's interfaces. |
| `config_context` | bool | `True` | Write the firewall's settings (DNS, NTP, SNMP, syslog, ...) into the device's local config context under the `fortigate` key. |
| `import_tag` | str | `"fortigate-import"` | Tag added to every object the importer creates. |
| `default_delete_action` | str | `"delete"` | What a firewall object that disappeared proposes for its NetBox object: `delete`, `unmanage` (keep it, stop syncing) or `deprecate` (status "deprecated" where the model has one, otherwise delete). Deletes always wait for review. |
| `continue_on_error` | bool | `False` | When applying, keep going past items that fail (each in its own savepoint) instead of rolling the whole run back. |

Per-firewall overrides of `vrf_per_vdom`, `create_connected_prefixes`,
`config_context` and `default_delete_action` are set on the FortiGate's
edit page.
