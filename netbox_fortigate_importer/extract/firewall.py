"""Firewall objects of one VDOM: addresses, services, policies, NAT."""
from .util import int_or_none, pairs_to_prefix, parse_port_range, to_interface_ip, to_ip


def addresses(vdom, family=4):
    table = vdom.table('firewall address' if family == 4 else 'firewall address6')
    result = []
    for name, entry in table:
        kind = entry.get('type', 'ipmask' if family == 4 else 'ipprefix')
        item = {
            'name': name,
            'family': family,
            'type': kind,
            'comment': entry.get('comment', '') or '',
            'interface': entry.get('associated-interface') or None,
        }
        if kind in ('ipmask', 'ipprefix'):
            if family == 4:
                item['prefix'] = pairs_to_prefix(entry.get_list('subnet')) or '0.0.0.0/0'
            else:
                item['prefix'] = pairs_to_prefix(entry.get_list('ip6')) or '::/0'
        elif kind == 'iprange':
            item['start'] = to_ip(entry.get('start-ip')) or ('0.0.0.0' if family == 4 else '::')
            item['end'] = to_ip(entry.get('end-ip')) or item['start']
        elif kind == 'fqdn':
            item['fqdn'] = entry.get('fqdn', '') or ''
        elif kind == 'wildcard-fqdn':
            item['fqdn'] = entry.get('wildcard-fqdn', '') or ''
        elif kind == 'geography':
            item['country'] = entry.get('country', '') or ''
        elif kind == 'wildcard':
            item['wildcard'] = ' '.join(entry.get_list('wildcard'))
        elif kind == 'interface-subnet':
            item['prefix'] = pairs_to_prefix(entry.get_list('subnet'))
            item['interface'] = entry.get('interface') or item['interface']
        elif kind == 'mac':
            item['macs'] = entry.get_list('macaddr')
        elif kind == 'dynamic':
            item['sub_type'] = entry.get('sub-type', '') or ''
        result.append(item)
    return result


def address_groups(vdom, family=4):
    table = vdom.table('firewall addrgrp' if family == 4 else 'firewall addrgrp6')
    return [
        {
            'name': name,
            'family': family,
            'members': entry.get_list('member'),
            'exclude': entry.get_list('exclude-member') if entry.is_enabled('exclude') else [],
            'comment': entry.get('comment', '') or '',
        }
        for name, entry in table
    ]


def _ports(entry, key):
    ranges = []
    for token in entry.get_list(key):
        parsed = parse_port_range(token)
        if parsed:
            ranges.append(parsed)
    return ranges


def services(vdom):
    result = []
    for name, entry in vdom.table('firewall service custom'):
        protocol = entry.get('protocol', 'TCP/UDP/SCTP')
        item = {
            'name': name,
            'protocol': protocol,
            'category': entry.get('category', '') or '',
            'comment': entry.get('comment', '') or '',
            'tcp': _ports(entry, 'tcp-portrange'),
            'udp': _ports(entry, 'udp-portrange'),
            'sctp': _ports(entry, 'sctp-portrange'),
            'icmp_type': int_or_none(entry.get('icmptype')),
            'icmp_code': int_or_none(entry.get('icmpcode')),
            'protocol_number': int_or_none(entry.get('protocol-number')),
            'fqdn': entry.get('fqdn') or None,
            'iprange': entry.get('iprange') or None,
        }
        result.append(item)
    return result


def service_groups(vdom):
    return [
        {
            'name': name,
            'members': entry.get_list('member'),
            'comment': entry.get('comment', '') or '',
        }
        for name, entry in vdom.table('firewall service group')
    ]


def policies(vdom):
    result = []
    for policy_id, entry in vdom.table('firewall policy'):
        result.append({
            'id': int_or_none(policy_id),
            'name': entry.get('name', '') or '',
            'uuid': entry.get('uuid'),
            'enabled': entry.get('status', 'enable') != 'disable',
            'srcintf': entry.get_list('srcintf'),
            'dstintf': entry.get_list('dstintf'),
            'srcaddr': entry.get_list('srcaddr') + entry.get_list('srcaddr6'),
            'dstaddr': entry.get_list('dstaddr') + entry.get_list('dstaddr6'),
            'srcaddr_negate': entry.is_enabled('srcaddr-negate'),
            'dstaddr_negate': entry.is_enabled('dstaddr-negate'),
            'service': entry.get_list('service'),
            'service_negate': entry.is_enabled('service-negate'),
            'action': entry.get('action', 'deny'),
            'schedule': entry.get('schedule', 'always'),
            'nat': entry.is_enabled('nat'),
            'ippool': entry.is_enabled('ippool'),
            'poolname': entry.get_list('poolname'),
            'users': entry.get_list('users'),
            'groups': entry.get_list('groups'),
            'logtraffic': entry.get('logtraffic', ''),
            'comments': entry.get('comments', '') or '',
        })
    return result


def vips(vdom):
    result = []
    for name, entry in vdom.table('firewall vip'):
        ext = entry.get('extip', '') or ''
        ext_start, _, ext_end = ext.partition('-')
        mapped = []
        for _, mapped_entry in entry.table('mappedip'):
            start, _, end = mapped_entry.name.partition('-')
            mapped.append({'start': to_ip(start) or start, 'end': to_ip(end) if end else None})
        if not mapped:
            for token in entry.get_list('mappedip'):
                start, _, end = token.partition('-')
                mapped.append({'start': to_ip(start) or start, 'end': to_ip(end) if end else None})
        result.append({
            'name': name,
            'type': entry.get('type', 'static-nat'),
            'comment': entry.get('comment', '') or '',
            'extip_start': to_ip(ext_start),
            'extip_end': to_ip(ext_end) if ext_end else None,
            'extintf': entry.get('extintf', 'any'),
            'mapped': mapped,
            'portforward': entry.is_enabled('portforward'),
            'protocol': entry.get('protocol', 'tcp'),
            'extport': parse_port_range(entry.get('extport')),
            'mappedport': parse_port_range(entry.get('mappedport')),
        })
    return result


def vip_groups(vdom):
    return [
        {'name': name, 'members': entry.get_list('member'), 'interface': entry.get('interface'),
         'comment': entry.get('comments', '') or ''}
        for name, entry in vdom.table('firewall vipgrp')
    ]


def ip_pools(vdom):
    result = []
    for name, entry in vdom.table('firewall ippool'):
        result.append({
            'name': name,
            'type': entry.get('type', 'overload'),
            'start': to_ip(entry.get('startip')),
            'end': to_ip(entry.get('endip')),
            'source_start': to_ip(entry.get('source-startip')),
            'source_end': to_ip(entry.get('source-endip')),
            'comment': entry.get('comments', '') or '',
        })
    return result


def central_snat(vdom):
    result = []
    for rule_id, entry in vdom.table('firewall central-snat-map'):
        result.append({
            'id': int_or_none(rule_id),
            'enabled': entry.get('status', 'enable') != 'disable',
            'srcintf': entry.get_list('srcintf'),
            'dstintf': entry.get_list('dstintf'),
            'orig_addr': entry.get_list('orig-addr'),
            'dst_addr': entry.get_list('dst-addr'),
            'nat_ippool': entry.get_list('nat-ippool'),
            'nat': entry.get('nat', 'enable') != 'disable',
            'comments': entry.get('comments', '') or '',
        })
    return result


def interface_ip_lookup(interfaces):
    """Interface name -> its primary address, for 'interface-subnet' types."""
    return {i['name']: i['ip'] for i in interfaces if i['ip']}


__all__ = [
    'addresses', 'address_groups', 'services', 'service_groups', 'policies',
    'vips', 'vip_groups', 'ip_pools', 'central_snat', 'interface_ip_lookup', 'to_interface_ip',
]
