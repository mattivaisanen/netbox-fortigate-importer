"""Plugin settings: PLUGINS_CONFIG['netbox_fortigate_importer'], with defaults
from FortiGateImporterConfig.default_settings."""
from netbox.plugins.utils import get_plugin_config

PLUGIN = 'netbox_fortigate_importer'


def get_setting(key):
    return get_plugin_config(PLUGIN, key)
