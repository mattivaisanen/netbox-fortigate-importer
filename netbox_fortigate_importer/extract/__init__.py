"""
From a parsed configuration to the importer's own data: the "necessary
info" that is saved on an import run. Only what the mappers use is kept; the
parse tree and the file itself are dropped after this runs.

The document is plain JSON (lists and dicts of strings, numbers, booleans),
so it can be stored in a JSONField and compared between imports.
"""
from ..parser import ParseResult, parse, read_config_bytes
from ..parser.layout import layout
from . import firewall, routing, system, vpn

SCHEMA_VERSION = 1

#: Top-level tables the importer reads. Everything else in a configuration is
#: counted in the summary as "not imported".
USED_TABLES = frozenset({
    'system global', 'system interface', 'system virtual-switch', 'system switch-interface',
    'system ha', 'system zone', 'system dhcp server', 'system dns', 'system ntp',
    'system snmp sysinfo', 'system settings', 'system central-management',
    'log syslogd setting', 'log syslogd2 setting', 'log syslogd3 setting', 'log syslogd4 setting',
    'log fortianalyzer setting', 'log fortianalyzer2 setting', 'log fortianalyzer3 setting',
    'firewall address', 'firewall address6', 'firewall addrgrp', 'firewall addrgrp6',
    'firewall service custom', 'firewall service group', 'firewall policy', 'firewall vip',
    'firewall vipgrp', 'firewall ippool', 'firewall central-snat-map',
    'router static', 'router static6', 'router bgp', 'router ospf', 'router prefix-list',
    'router prefix-list6', 'router access-list', 'router access-list6', 'router route-map',
    'router aspath-list', 'router community-list',
    'vpn ipsec phase1-interface', 'vpn ipsec phase2-interface', 'vpn ipsec phase1', 'vpn ipsec phase2',
    'vdom', 'global',
})


def extract_vdom(name, section):
    return {
        'name': name,
        'opmode': section.table('system settings').get('opmode', 'nat') or 'nat',
        'zones': system.zones(section),
        'dhcp_servers': system.dhcp_servers(section),
        'addresses': firewall.addresses(section, 4) + firewall.addresses(section, 6),
        'address_groups': firewall.address_groups(section, 4) + firewall.address_groups(section, 6),
        'services': firewall.services(section),
        'service_groups': firewall.service_groups(section),
        'policies': firewall.policies(section),
        'vips': firewall.vips(section),
        'vip_groups': firewall.vip_groups(section),
        'ip_pools': firewall.ip_pools(section),
        'central_snat': firewall.central_snat(section),
        'static_routes': routing.static_routes(section, 4) + routing.static_routes(section, 6),
        'bgp': routing.bgp(section),
        'ospf': routing.ospf(section),
        'prefix_lists': routing.prefix_lists(section, 4) + routing.prefix_lists(section, 6),
        'access_lists': routing.access_lists(section, 4) + routing.access_lists(section, 6),
        'route_maps': routing.route_maps(section),
        'aspath_lists': routing.aspath_lists(section),
        'community_lists': routing.community_lists(section),
        'ipsec_phase1': vpn.phase1(section),
        'ipsec_phase2': vpn.phase2(section),
    }


def _unused_tables(result, config_layout):
    """Names of top-level tables present but not imported (for the summary)."""
    names = set()
    sections = [config_layout.global_section] + list(config_layout.vdoms.values())
    for section in sections:
        for table_name in section.tables:
            if table_name not in USED_TABLES:
                names.add(table_name)
    return sorted(names)


def extract(result: ParseResult):
    """Build the importer document from a ParseResult."""
    config_layout = layout(result)
    warnings = list(result.warnings)
    interfaces = system.interfaces(config_layout.global_section, warnings)
    vdom_names = list(config_layout.vdoms)
    for item in interfaces:
        if item['vdom'] and item['vdom'] not in vdom_names:
            warnings.append(f'interface {item["name"]} is in unknown VDOM "{item["vdom"]}"')
    return {
        'schema': SCHEMA_VERSION,
        'info': config_layout.info.as_dict(),
        'ha': system.ha(config_layout.global_section),
        'settings': system.device_settings(config_layout.global_section, config_layout.vdoms),
        'interfaces': interfaces,
        'connected': system.connected_networks(interfaces),
        'vdoms': {name: extract_vdom(name, section) for name, section in config_layout.vdoms.items()},
        'stats': {
            'lines': result.lines,
            'secrets_removed': result.secrets_removed,
            'not_imported': _unused_tables(result, config_layout),
        },
        'warnings': warnings,
    }


def load(data, password=None):
    """
    Bytes of an uploaded file to the importer document, in one step. Raises
    the parser's errors (PasswordRequired, DecryptionError, UnsupportedFormat,
    ParseError) unchanged. The text and the parse tree are dropped when this
    returns.
    """
    text = read_config_bytes(data, password)
    try:
        return extract(parse(text))
    finally:
        del text
