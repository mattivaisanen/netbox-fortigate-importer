"""
Optional integrations with other plugins. Each one is used only when its
plugin is installed; nothing here imports another plugin at module level.
"""
from django.apps import apps

SECURITY = 'netbox_security'
ROUTING = 'netbox_routing'
CHANGE_APPROVAL = 'netbox_change_approval'


def installed(app_label):
    return apps.is_installed(app_label)


def has_security():
    return installed(SECURITY)


def has_routing():
    return installed(ROUTING)


def has_change_approval():
    return installed(CHANGE_APPROVAL)


def connect():
    """Called from ready(): hook into installed plugins. No database queries."""
    if has_change_approval():
        from . import change_approval

        change_approval.connect()
