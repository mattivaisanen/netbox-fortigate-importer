"""
Optional integrations with other plugins. Each one is used only when its
plugin is installed; nothing here imports another plugin at module level.
"""
import logging
from importlib import metadata

from django.apps import apps

logger = logging.getLogger('netbox_fortigate_importer')

SECURITY = 'netbox_security'
ROUTING = 'netbox_routing'
CHANGE_APPROVAL = 'netbox_change_approval'

#: The versions CI tests with (.github/workflows/test.yml), by app label:
#: (distribution name, version). The mappers write into these plugins'
#: models, so a different minor version may have renamed fields.
TESTED = {
    SECURITY: ('netbox-security', '1.6.8'),
    ROUTING: ('netbox-routing', '0.5.1'),
    CHANGE_APPROVAL: ('netbox-change-approval', '0.5.4'),
}


def installed(app_label):
    return apps.is_installed(app_label)


def has_security():
    return installed(SECURITY)


def has_routing():
    return installed(ROUTING)


def has_change_approval():
    return installed(CHANGE_APPROVAL)


def _minor(version):
    """'1.6.8' -> (1, 6). Anything unreadable compares as itself."""
    parts = version.split('.')
    return tuple(parts[:2])


def untested_versions():
    """Installed optional plugins outside the tested minor version: [(name, installed, tested)]."""
    found = []
    for app_label, (dist, tested) in TESTED.items():
        if not installed(app_label):
            continue
        try:
            version = metadata.version(dist)
        except metadata.PackageNotFoundError:
            continue  # installed from a checkout without metadata: nothing to compare
        if _minor(version) != _minor(tested):
            found.append((dist, version, tested))
    return found


def check_versions():
    for dist, version, tested in untested_versions():
        logger.warning('%s %s is installed; the FortiGate importer is tested with %s. '
                       'Imports into it may fail or miss fields.', dist, version, tested)


def connect():
    """Called from ready(): hook into installed plugins. No database queries."""
    check_versions()
    if has_change_approval():
        from . import change_approval

        change_approval.connect()
