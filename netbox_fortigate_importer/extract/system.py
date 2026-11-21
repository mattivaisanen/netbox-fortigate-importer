"""System-level facts: interfaces, HA, zones, DHCP servers, device settings."""
from .util import int_or_none, network_of, to_interface_ip, to_ip

#: FortiOS interface types and what they are.
INTERFACE_KINDS = {
    'physical': 'physical',
    'vlan': 'vlan',
    'aggregate': 'lag',
    'redundant': 'lag',
    'hard-switch': 'bridge',
    'switch': 'bridge',
    'vap-switch': 'wireless',
    'wl-mesh': 'wireless',
    'tunnel': 'tunnel',
    'loopback': 'loopback',
    'vdom-link': 'virtual',
    'vxlan': 'tunnel',
    'geneve': 'tunnel',
    'gre': 'tunnel',
    'emac-vlan': 'vlan',
    'fext-wan': 'physical',
    'lan-extension': 'virtual',
    'ssl': 'tunnel',
}

#: Interfaces FortiOS creates on its own (SSL VPN, NAT64, L2TP, ...). They
#: carry no configuration worth having in NetBox.
SYSTEM_INTERFACE_PREFIXES = ('ssl.', 'naf.', 'l2t.', 'npu', 'modem')


def is_system_interface(name, section):
    if section.get('type') == 'tunnel' and name.startswith(SYSTEM_INTERFACE_PREFIXES):
        return True
    if name == 'modem' and section.get('mode') == 'pppoe' and not section.get('ip'):
        return True
    return False


def interfaces(global_section, warnings):
    """Interfaces from `system interface`, `system virtual-switch` and
    `system switch-interface`."""
    result = []
    members_of = {}  # interface name -> bridge name

    for switch_name, switch in global_section.table('system virtual-switch'):
        for port_name, _ in switch.table('port'):
            members_of[port_name] = switch_name
    for switch_name, switch in global_section.table('system switch-interface'):
        for member in switch.get_list('member'):
            members_of[member] = switch_name

    seen = set()
    for name, section in global_section.table('system interface'):
        if is_system_interface(name, section):
            continue
        seen.add(name)
        # `show` leaves out default values, and a VLAN's type is implied by
        # its parent interface and VLAN ID.
        default_type = 'vlan' if section.get('vlanid') and section.get('interface') else 'physical'
        fortios_type = section.get('type', default_type)
        kind = INTERFACE_KINDS.get(fortios_type, 'virtual')
        if fortios_type == 'tunnel' and section.get('interface'):
            kind = 'tunnel'

        ip = None
        ip_tokens = section.get_list('ip')
        if ip_tokens:
            ip = to_interface_ip(*ip_tokens[:2]) if len(ip_tokens) >= 2 else to_interface_ip(ip_tokens[0])
            if ip is None and ip_tokens[0] not in ('0.0.0.0', '0.0.0.0/0'):
                warnings.append(f'interface {name}: could not read address "{" ".join(ip_tokens)}"')
            # Tunnel interfaces carry a /32 and give the subnet on remote-ip.
            remote = section.get_list('remote-ip')
            if ip and ip.endswith('/32') and len(remote) >= 2 and to_interface_ip(remote[0], remote[1]):
                ip = to_interface_ip(ip_tokens[0], remote[1]) or ip

        secondary = []
        if section.is_enabled('secondary-IP'):
            for _, sec in section.table('secondaryip'):
                tokens = sec.get_list('ip')
                if len(tokens) >= 2:
                    value = to_interface_ip(*tokens[:2])
                else:
                    value = to_interface_ip(tokens[0] if tokens else None)
                if value:
                    secondary.append(value)

        ipv6 = []
        v6 = section.table('ipv6')
        v6_address = v6.get('ip6-address')
        if v6_address and to_interface_ip(v6_address):
            ipv6.append(to_interface_ip(v6_address))
        for _, extra in v6.table('ip6-extra-addr'):
            if to_interface_ip(extra.name):
                ipv6.append(to_interface_ip(extra.name))

        vrrp = []
        for vrid, entry in section.table('vrrp'):
            address = to_ip(entry.get('vrip'))
            if address is None:
                continue
            vrrp.append({
                'vrid': int_or_none(vrid) or int_or_none(entry.get('vrid')),
                'version': 3 if section.get('vrrp-virtual-mac') == 'v3' or entry.get('version') == '3' else 2,
                'address': address,
                'priority': int_or_none(entry.get('priority')),
                'status': entry.get('status', 'enable'),
            })

        mac = section.get('macaddr')
        if mac in ('00:00:00:00:00:00',):
            mac = None

        speed = section.get('speed')
        result.append({
            'name': name,
            'vdom': section.get('vdom', 'root'),
            'fortios_type': fortios_type,
            'kind': kind,
            'alias': section.get('alias', '') or '',
            'description': section.get('description', '') or '',
            'enabled': section.get('status', 'up') != 'down',
            'mode': section.get('mode', 'static'),
            # Addresses learnt by DHCP/PPPoE aren't configuration.
            'ip': ip if section.get('mode', 'static') == 'static' else None,
            'secondary_ips': secondary,
            'ipv6': ipv6,
            'mtu': int_or_none(section.get('mtu')) if section.is_enabled('mtu-override') else None,
            'speed': speed if speed and speed != 'auto' else None,
            'mac': mac,
            'vlan_id': int_or_none(section.get('vlanid')),
            'parent': section.get('interface') if fortios_type in ('vlan', 'emac-vlan', 'tunnel') else None,
            'members': section.get_list('member') if kind == 'lag' else [],
            'lacp_mode': section.get('lacp-mode') if fortios_type == 'aggregate' else None,
            'bridge': members_of.get(name),
            'role': section.get('role', '') if section.get('role') not in (None, 'undefined') else '',
            'vrf': int_or_none(section.get('vrf')),
            'allowaccess': section.get_list('allowaccess'),
            'vrrp': vrrp,
        })

    # Ports that exist only as members of a hardware/software switch.
    for port, bridge in members_of.items():
        if port in seen:
            continue
        result.append({
            'name': port, 'vdom': None, 'fortios_type': 'physical', 'kind': 'physical',
            'alias': '', 'description': '', 'enabled': True, 'mode': 'static', 'ip': None,
            'secondary_ips': [], 'ipv6': [], 'mtu': None, 'speed': None, 'mac': None,
            'vlan_id': None, 'parent': None, 'members': [], 'lacp_mode': None,
            'bridge': bridge, 'role': '', 'vrf': None, 'allowaccess': [], 'vrrp': [],
        })
    by_name = {i['name']: i for i in result}
    for item in result:
        if item['vdom'] is None and item['bridge'] in by_name:
            item['vdom'] = by_name[item['bridge']]['vdom']
    return result


def connected_networks(interface_list):
    """(network, interface name, vdom, vrf) for every interface address."""
    found = []
    for item in interface_list:
        for address in ([item['ip']] if item['ip'] else []) + item['secondary_ips'] + item['ipv6']:
            network = network_of(address)
            if network and not network.endswith(('/32', '/128')):
                found.append({'prefix': network, 'interface': item['name'], 'vdom': item['vdom'], 'vrf': item['vrf']})
    return found


def ha(global_section):
    section = global_section.table('system ha')
    mode = section.get('mode', 'standalone')
    if mode in (None, 'standalone'):
        return None
    return {
        'mode': mode,
        'group_name': section.get('group-name', '') or '',
        'group_id': int_or_none(section.get('group-id')),
        'priority': int_or_none(section.get('priority')),
        'override': section.is_enabled('override'),
        'hbdev': list(dict.fromkeys(t for t in section.get_list('hbdev') if not t.isdigit())),
        'monitor': section.get_list('monitor'),
        'session_pickup': section.is_enabled('session-pickup'),
        'mgmt_interfaces': [
            entry.get('interface') for _, entry in section.table('ha-mgmt-interfaces') if entry.get('interface')
        ],
    }


def zones(vdom_section):
    result = []
    for name, entry in vdom_section.table('system zone'):
        result.append({
            'name': name,
            'interfaces': entry.get_list('interface'),
            'intrazone': entry.get('intrazone', 'deny'),
            'description': entry.get('description', '') or '',
        })
    return result


def dhcp_servers(vdom_section):
    result = []
    for server_id, entry in vdom_section.table('system dhcp server'):
        ranges = []
        for _, ip_range in entry.table('ip-range'):
            start, end = to_ip(ip_range.get('start-ip')), to_ip(ip_range.get('end-ip'))
            if start and end:
                ranges.append({'start': start, 'end': end})
        if not ranges and entry.get('start-ip'):  # FortiOS 5.0 style
            start, end = to_ip(entry.get('start-ip')), to_ip(entry.get('end-ip'))
            if start and end:
                ranges.append({'start': start, 'end': end})
        reserved = []
        for _, item in entry.table('reserved-address'):
            ip = to_ip(item.get('ip'))
            if ip:
                reserved.append({
                    'ip': ip,
                    'mac': item.get('mac'),
                    'description': item.get('description', '') or '',
                    'action': item.get('action', 'reserved'),
                })
        dns = [to_ip(entry.get(f'dns-server{i}')) for i in (1, 2, 3, 4)]
        result.append({
            'id': server_id,
            'interface': entry.get('interface'),
            'enabled': entry.get('status', 'enable') != 'disable',
            'netmask': entry.get('netmask'),
            'gateway': to_ip(entry.get('default-gateway')),
            'dns': [d for d in dns if d],
            'lease_time': int_or_none(entry.get('lease-time')),
            'ranges': ranges,
            'reserved': reserved,
        })
    return result


def device_settings(global_section, vdom_sections):
    """Settings for the device's config context: no secrets, no bulk."""
    glob = global_section.table('system global')
    dns = global_section.table('system dns')
    ntp = global_section.table('system ntp')
    servers = [to_ip(dns.get('primary')), to_ip(dns.get('secondary'))]
    ntp_servers = [entry.get('server') for _, entry in ntp.table('ntpserver') if entry.get('server')]
    syslog = []
    for path in ('log syslogd setting', 'log syslogd2 setting', 'log syslogd3 setting', 'log syslogd4 setting'):
        section = global_section.table(path)
        if section.is_enabled('status') and section.get('server'):
            syslog.append({'server': section.get('server'), 'port': int_or_none(section.get('port'))})
    faz = []
    for path in ('log fortianalyzer setting', 'log fortianalyzer2 setting', 'log fortianalyzer3 setting'):
        section = global_section.table(path)
        if section.is_enabled('status') and section.get('server'):
            faz.append(section.get('server'))
    snmp = global_section.table('system snmp sysinfo')
    return {
        'timezone': glob.get('timezone'),
        'admin': {
            'https_port': int_or_none(glob.get('admin-sport')),
            'http_port': int_or_none(glob.get('admin-port')),
            'ssh_port': int_or_none(glob.get('admin-ssh-port')),
        },
        'dns': {'servers': [s for s in servers if s], 'domain': dns.get('domain')},
        'ntp': {
            'sync': ntp.is_enabled('ntpsync'),
            'type': ntp.get('type'),
            'servers': ntp_servers,
        },
        'snmp': {
            'enabled': snmp.is_enabled('status'),
            'location': snmp.get('location'),
            'contact': snmp.get('contact-info'),
            'description': snmp.get('description'),
        },
        'syslog': syslog,
        'fortianalyzer': faz,
        'fortimanager': global_section.table('system central-management').get('fmg'),
    }
