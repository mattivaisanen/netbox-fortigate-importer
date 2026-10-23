from django.utils.translation import gettext_lazy as _

from netbox.plugins import PluginMenu, PluginMenuButton, PluginMenuItem

menu = PluginMenu(
    label=_('FortiGate'),
    icon_class='mdi mdi-wall-fire',
    groups=(
        (_('Import'), (
            PluginMenuItem(
                link='plugins:netbox_fortigate_importer:importrun_upload',
                link_text=_('New import'),
                permissions=['netbox_fortigate_importer.add_importrun'],
            ),
            PluginMenuItem(
                link='plugins:netbox_fortigate_importer:importrun_list',
                link_text=_('Import runs'),
                permissions=['netbox_fortigate_importer.view_importrun'],
            ),
        )),
        (_('Firewalls'), (
            PluginMenuItem(
                link='plugins:netbox_fortigate_importer:fortigatebinding_list',
                link_text=_('FortiGates'),
                permissions=['netbox_fortigate_importer.view_fortigatebinding'],
                buttons=(
                    PluginMenuButton(
                        link='plugins:netbox_fortigate_importer:fortigatebinding_add',
                        title=_('Add'),
                        icon_class='mdi mdi-plus-thick',
                        permissions=['netbox_fortigate_importer.add_fortigatebinding'],
                    ),
                ),
            ),
        )),
    ),
)
