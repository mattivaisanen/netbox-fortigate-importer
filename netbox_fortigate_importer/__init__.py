"""
Import FortiGate configurations into NetBox.

An uploaded configuration is read in memory, stripped of secrets and turned
into the importer's own data (see extract/). The importer then plans the
changes against NetBox, people review them, and the approved ones are
applied in one transaction that can be dry-run and rolled back. The file
itself is never stored. See DEVELOPER.md.
"""
from netbox.plugins import PluginConfig


class FortiGateImporterConfig(PluginConfig):
    name = 'netbox_fortigate_importer'
    verbose_name = 'FortiGate Importer'
    description = 'Import FortiGate configurations with delta sync, review, dry run and rollback.'
    version = '0.1.0'
    author = 'Matti'
    base_url = 'fortigate-importer'
    # Only claim what CI tests (.github/workflows/test.yml).
    min_version = '4.7.0'

    default_settings = {
        # Largest upload accepted, in megabytes. The file is held in memory only.
        'max_upload_mb': 50,
        # New objects start approved; changes and deletes always wait for review.
        'auto_approve_creates': True,
        # One VRF per VDOM (and per FortiOS VRF inside a VDOM).
        'vrf_per_vdom': True,
        # Create prefixes for the networks on the firewall's interfaces.
        'create_connected_prefixes': True,
        # Write the firewall's settings (DNS, NTP, syslog, ...) into the
        # device's local config context, under the "fortigate" key.
        'config_context': True,
        # Tag put on every object the importer creates.
        'import_tag': 'fortigate-import',
        # What a deleted firewall object proposes for its NetBox object:
        # 'delete', 'unmanage' (keep it, stop syncing) or 'deprecate'
        # (status "deprecated" where the model has one, else delete).
        'default_delete_action': 'delete',
        # Apply: keep going past failing items (each in its own savepoint)
        # instead of rolling the whole run back.
        'continue_on_error': False,
    }

    menu = 'navigation.menu'
    template_extensions = 'template_content.template_extensions'

    def ready(self):
        super().ready()
        from . import integrations

        integrations.connect()


config = FortiGateImporterConfig
