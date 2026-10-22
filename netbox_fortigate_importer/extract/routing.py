"""Routing of one VDOM: static routes, BGP, OSPF, prefix lists, route maps."""
from .util import int_or_none, pairs_to_prefix, to_ip


def static_routes(vdom, family=4):
    table = vdom.table('router static' if family == 4 else 'router static6')
    result = []
    for seq, entry in table:
        if family == 4:
            dst = pairs_to_prefix(entry.get_list('dst')) or '0.0.0.0/0'
        else:
            dst = pairs_to_prefix(entry.get_list('dst')) or '::/0'
        result.append({
            'seq': int_or_none(seq),
            'family': family,
            'enabled': entry.get('status', 'enable') != 'disable',
            'dst': dst,
            'gateway': to_ip(entry.get('gateway')),
            'device': entry.get('device') or None,
            'distance': int_or_none(entry.get('distance')),
            'priority': int_or_none(entry.get('priority')),
            'weight': int_or_none(entry.get('weight')),
            'blackhole': entry.is_enabled('blackhole'),
            'comment': entry.get('comment', '') or '',
            'vrf': int_or_none(entry.get('vrf')),
            'dst_address': entry.get('dstaddr') or None,
            'sdwan': entry.is_enabled('sdwan') or bool(entry.get('sdwan-zone')),
        })
    return result


def _redistribute(section):
    """`config redistribute "connected"` blocks (one table per source)."""
    found = {}
    for table_name, entry in section.tables.items():
        if not table_name.startswith('redistribute'):
            continue
        source = table_name[len('redistribute'):].strip()
        if source and entry.is_enabled('status'):
            found[source] = {'route_map': entry.get('route-map') or None}
    return found


def bgp(vdom):
    section = vdom.table('router bgp')
    asn = section.get('as')
    if not asn or asn == '0':
        return None
    neighbors = []
    for ip, entry in section.table('neighbor'):
        neighbors.append({
            'ip': to_ip(ip) or ip,
            'remote_as': entry.get('remote-as'),
            'description': entry.get('description', '') or '',
            'enabled': not entry.is_enabled('shutdown'),
            'update_source': entry.get('update-source') or None,
            'ebgp_multihop': entry.is_enabled('ebgp-enforce-multihop'),
            'ebgp_ttl': int_or_none(entry.get('ebgp-multihop-ttl')),
            'route_map_in': entry.get('route-map-in') or None,
            'route_map_out': entry.get('route-map-out') or None,
            'prefix_list_in': entry.get('prefix-list-in') or None,
            'prefix_list_out': entry.get('prefix-list-out') or None,
            'route_reflector_client': entry.is_enabled('route-reflector-client'),
            'next_hop_self': entry.is_enabled('next-hop-self'),
            'bfd': entry.is_enabled('bfd'),
            'soft_reconfiguration': entry.is_enabled('soft-reconfiguration'),
            'interface': entry.get('interface') or None,
            'group': None,
        })
    groups = []
    for name, entry in section.table('neighbor-group'):
        groups.append({
            'name': name,
            'remote_as': entry.get('remote-as'),
            'update_source': entry.get('update-source') or None,
            'route_map_in': entry.get('route-map-in') or None,
            'route_map_out': entry.get('route-map-out') or None,
        })
    for _, entry in section.table('neighbor-range'):
        prefix = pairs_to_prefix(entry.get_list('prefix'))
        if prefix:
            for group in groups:
                if group['name'] == entry.get('neighbor-group'):
                    group.setdefault('ranges', []).append(prefix)
    networks = []
    for _, entry in section.table('network'):
        prefix = pairs_to_prefix(entry.get_list('prefix'))
        if prefix:
            networks.append({'prefix': prefix, 'route_map': entry.get('route-map') or None})
    for _, entry in section.table('network6'):
        prefix = pairs_to_prefix(entry.get_list('prefix6'))
        if prefix:
            networks.append({'prefix': prefix, 'route_map': entry.get('route-map') or None})
    return {
        'as': asn,
        'router_id': to_ip(section.get('router-id')),
        'keepalive': int_or_none(section.get('keepalive-timer')),
        'holdtime': int_or_none(section.get('holdtime-timer')),
        'ebgp_multipath': section.is_enabled('ebgp-multipath'),
        'ibgp_multipath': section.is_enabled('ibgp-multipath'),
        'neighbors': neighbors,
        'neighbor_groups': groups,
        'networks': networks,
        'redistribute': _redistribute(section),
    }


def ospf(vdom):
    section = vdom.table('router ospf')
    router_id = to_ip(section.get('router-id'))
    areas = [
        {'id': area_id, 'type': entry.get('type', 'regular'), 'nssa': entry.get('nssa-translator-role')}
        for area_id, entry in section.table('area')
    ]
    if not router_id and not areas:
        return None
    networks = []
    for _, entry in section.table('network'):
        prefix = pairs_to_prefix(entry.get_list('prefix'))
        if prefix:
            networks.append({'prefix': prefix, 'area': entry.get('area', '0.0.0.0')})
    interfaces = []
    for name, entry in section.table('ospf-interface'):
        interfaces.append({
            'name': name,
            'interface': entry.get('interface') or None,
            'cost': int_or_none(entry.get('cost')),
            'priority': int_or_none(entry.get('priority')),
            'network_type': entry.get('network-type') or None,
            'authentication': entry.get('authentication', 'none'),
            'bfd': entry.get('bfd') == 'enable',
            'mtu_ignore': entry.is_enabled('mtu-ignore'),
        })
    return {
        'router_id': router_id,
        'areas': areas,
        'networks': networks,
        'interfaces': interfaces,
        'passive_interfaces': section.get_list('passive-interface'),
        'default_information_originate': section.get('default-information-originate', 'disable'),
        'redistribute': _redistribute(section),
    }


def prefix_lists(vdom, family=4):
    table = vdom.table('router prefix-list' if family == 4 else 'router prefix-list6')
    key = 'prefix' if family == 4 else 'prefix6'
    result = []
    for name, entry in table:
        rules = []
        for rule_id, rule in entry.table('rule'):
            tokens = rule.get_list(key)
            prefix = 'any' if tokens and tokens[0] == 'any' else pairs_to_prefix(tokens)
            rules.append({
                'id': int_or_none(rule_id),
                'action': rule.get('action', 'permit'),
                'prefix': prefix,
                'ge': int_or_none(rule.get('ge')),
                'le': int_or_none(rule.get('le')),
            })
        result.append({'name': name, 'family': family, 'comments': entry.get('comments', '') or '', 'rules': rules})
    return result


def access_lists(vdom, family=4):
    table = vdom.table('router access-list' if family == 4 else 'router access-list6')
    key = 'prefix' if family == 4 else 'prefix6'
    result = []
    for name, entry in table:
        rules = []
        for rule_id, rule in entry.table('rule'):
            tokens = rule.get_list(key)
            prefix = 'any' if tokens and tokens[0] == 'any' else pairs_to_prefix(tokens)
            rules.append({
                'id': int_or_none(rule_id),
                'action': rule.get('action', 'permit'),
                'prefix': prefix,
                'exact_match': rule.is_enabled('exact-match'),
                'ge': None, 'le': None,
            })
        result.append({'name': name, 'family': family, 'comments': entry.get('comments', '') or '', 'rules': rules})
    return result


_MATCH_KEYS = (
    'match-ip-address', 'match-ip6-address', 'match-ip-nexthop', 'match-ip6-nexthop',
    'match-as-path', 'match-community', 'match-interface', 'match-metric',
    'match-origin', 'match-route-type', 'match-tag', 'match-extcommunity',
)


def route_maps(vdom):
    result = []
    for name, entry in vdom.table('router route-map'):
        rules = []
        for rule_id, rule in entry.table('rule'):
            match = {k[len('match-'):]: ' '.join(rule.get_list(k)) for k in _MATCH_KEYS if rule.get_list(k)}
            sets = {
                k[len('set-'):]: ' '.join(v) for k, v in rule.values.items()
                if k.startswith('set-') and v
            }
            rules.append({
                'id': int_or_none(rule_id),
                'action': rule.get('action', 'permit'),
                'match': match,
                'set': sets,
            })
        result.append({'name': name, 'comments': entry.get('comments', '') or '', 'rules': rules})
    return result


def aspath_lists(vdom):
    result = []
    for name, entry in vdom.table('router aspath-list'):
        rules = [
            {'id': int_or_none(rid), 'action': r.get('action', 'permit'), 'regexp': r.get('regexp', '') or ''}
            for rid, r in entry.table('rule')
        ]
        result.append({'name': name, 'rules': rules})
    return result


def community_lists(vdom):
    result = []
    for name, entry in vdom.table('router community-list'):
        rules = [
            {'id': int_or_none(rid), 'action': r.get('action', 'permit'),
             'match': ' '.join(r.get_list('match')), 'regexp': r.get('regexp') or None}
            for rid, r in entry.table('rule')
        ]
        result.append({'name': name, 'type': entry.get('type', 'standard'), 'rules': rules})
    return result
