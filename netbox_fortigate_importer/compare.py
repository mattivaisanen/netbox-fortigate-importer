"""
What changed on the firewall itself between two imports of it.

Works only on the importer's saved data (ImportRun.data), never on NetBox:
"policy 14 added, address srv-web changed, route removed". Also finds an
earlier import of the very same configuration.
"""
from __future__ import annotations

import hashlib
import json

from django.utils.translation import gettext_lazy as _

from .models import ImportRun, RunStatusChoices

#: Parts of the data that say nothing about the firewall's configuration.
IGNORED = frozenset({'schema', 'stats', 'warnings', 'truncated', 'connected'})

SECTION_LABELS = {
    'info': _('System'),
    'ha': _('HA'),
    'settings': _('Settings'),
    'interfaces': _('Interfaces'),
    'opmode': _('Operation mode'),
    'zones': _('Zones'),
    'dhcp_servers': _('DHCP servers'),
    'addresses': _('Addresses'),
    'address_groups': _('Address groups'),
    'services': _('Services'),
    'service_groups': _('Service groups'),
    'policies': _('Firewall policies'),
    'vips': _('Virtual IPs'),
    'vip_groups': _('Virtual IP groups'),
    'ip_pools': _('IP pools'),
    'central_snat': _('Central SNAT'),
    'static_routes': _('Static routes'),
    'bgp': _('BGP'),
    'ospf': _('OSPF'),
    'prefix_lists': _('Prefix lists'),
    'access_lists': _('Access lists'),
    'route_maps': _('Route maps'),
    'aspath_lists': _('AS path lists'),
    'community_lists': _('Community lists'),
    'ipsec_phase1': _('IPsec phase 1'),
    'ipsec_phase2': _('IPsec phase 2'),
}

ADDED, REMOVED, CHANGED = 'added', 'removed', 'changed'


def content_hash(data):
    """SHA-256 of the extracted configuration: equal for the same configuration,
    whether it came as a plain file or an encrypted backup."""
    relevant = {k: v for k, v in (data or {}).items() if k not in IGNORED}
    text = json.dumps(relevant, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(text.encode()).hexdigest()


def same_as(run):
    """The latest earlier import of exactly this configuration, if any."""
    earlier = ImportRun.objects.filter(pk__lt=run.pk).exclude(status=RunStatusChoices.DISCARDED)
    match = earlier.filter(file_sha256=run.file_sha256) if run.file_sha256 else earlier.none()
    if run.data_sha256:
        match = match | earlier.filter(data_sha256=run.data_sha256)
    return match.select_related('binding').defer('data').order_by('-pk').first()


def previous_run(run):
    """The import of the same FortiGate before this one (discarded ones left out)."""
    if run.binding_id is None:
        return None
    return run.binding.runs.filter(pk__lt=run.pk).exclude(status=RunStatusChoices.DISCARDED) \
        .order_by('-pk').first()


def identity(item):
    """(key, label) of one list item: policies by ID, routes by sequence, the rest by name."""
    family = item.get('family')
    suffix = ' (IPv6)' if family == 6 else ''
    for field in ('id', 'seq', 'name'):
        if item.get(field) not in (None, ''):
            value = item[field]
            label = f'{value}' if field == 'name' else f'#{value}'
            if field == 'id' and item.get('name'):
                label = f'#{value} {item["name"]}'
            if field == 'seq' and item.get('dst'):
                label = f'#{value} {item["dst"]}'
            return (family, field, str(value)), label + suffix
    text = json.dumps(item, sort_keys=True, default=str)
    return (family, 'item', text), text[:80]


def show(value):
    """A field value as short text."""
    if value is None or value == '' or value == []:
        return '—'
    if isinstance(value, bool):
        return 'yes' if value else 'no'
    if isinstance(value, list) and all(not isinstance(v, (dict, list)) for v in value):
        return ', '.join(str(v) for v in value)
    if isinstance(value, (dict, list)):
        text = json.dumps(value, separators=(', ', ': '), default=str)
        return text if len(text) <= 300 else text[:299] + '…'
    return str(value)


def field_changes(old, new):
    return [
        {'field': name, 'old': show(old.get(name)), 'new': show(new.get(name))}
        for name in dict.fromkeys(list(old) + list(new))
        if old.get(name) != new.get(name)
    ]


def compare_section(name, old, new):
    """Entries for one section: a list of items, or one block of settings."""
    if isinstance(old, list) or isinstance(new, list):
        old_items = {identity(item)[0]: item for item in old or [] if isinstance(item, dict)}
        new_items = {identity(item)[0]: item for item in new or [] if isinstance(item, dict)}
        entries = []
        for key, item in new_items.items():
            if key not in old_items:
                entries.append({'action': ADDED, 'label': identity(item)[1], 'fields': []})
            elif old_items[key] != item:
                entries.append({'action': CHANGED, 'label': identity(item)[1],
                                'fields': field_changes(old_items[key], item)})
        for key, item in old_items.items():
            if key not in new_items:
                entries.append({'action': REMOVED, 'label': identity(item)[1], 'fields': []})
        return entries
    if old == new:
        return []
    if not isinstance(old, dict) or not isinstance(new, dict):
        return [{'action': CHANGED, 'label': str(SECTION_LABELS.get(name, name)),
                 'fields': [{'field': name, 'old': show(old), 'new': show(new)}]}]
    action = ADDED if not old else REMOVED if not new else CHANGED
    return [{'action': action, 'label': str(SECTION_LABELS.get(name, name)),
             'fields': field_changes(old, new) if action == CHANGED else []}]


def compare(old_data, new_data):
    """
    Firewall changes from one import's data to another's:
    [{'section', 'vdom', 'entries': [{'action', 'label', 'fields': [{'field', 'old', 'new'}]}]}].
    """
    old_data, new_data = old_data or {}, new_data or {}
    result = []

    def add(name, vdom, old, new):
        entries = compare_section(name, old, new)
        if entries:
            result.append({'section': str(SECTION_LABELS.get(name, name)), 'vdom': vdom, 'entries': entries})

    for name in dict.fromkeys(list(old_data) + list(new_data)):
        if name in IGNORED or name == 'vdoms':
            continue
        add(name, '', old_data.get(name), new_data.get(name))
    old_vdoms, new_vdoms = old_data.get('vdoms') or {}, new_data.get('vdoms') or {}
    for vdom in dict.fromkeys(list(old_vdoms) + list(new_vdoms)):
        if vdom not in old_vdoms or vdom not in new_vdoms:
            action = ADDED if vdom in new_vdoms else REMOVED
            result.append({'section': str(_('VDOMs')), 'vdom': '',
                           'entries': [{'action': action, 'label': vdom, 'fields': []}]})
            continue
        old, new = old_vdoms[vdom], new_vdoms[vdom]
        for name in dict.fromkeys(list(old) + list(new)):
            if name != 'name':
                add(name, vdom, old.get(name), new.get(name))
    return result


def counts(sections):
    found = {ADDED: 0, CHANGED: 0, REMOVED: 0}
    for section in sections:
        for entry in section['entries']:
            found[entry['action']] += 1
    return found
