"""IPsec VPNs of one VDOM: phase 1 and phase 2 settings, without keys."""
from .util import int_or_none, pairs_to_prefix, to_ip


def split_proposal(token):
    """
    'aes256-sha256' -> ('aes256', 'sha256'); 'aes128gcm-prfsha256' ->
    ('aes128gcm', 'prfsha256'); 'aes256gcm' -> ('aes256gcm', None).
    """
    if '-' in token:
        enc, _, auth = token.partition('-')
        return enc, auth
    return token, None


def _proposals(entry):
    return [split_proposal(t) for t in entry.get_list('proposal')]


def phase1(vdom):
    result = []
    for path, route_based in (('vpn ipsec phase1-interface', True), ('vpn ipsec phase1', False)):
        for name, entry in vdom.table(path):
            dhgrp = [int(g) for g in entry.get_list('dhgrp') if g.isdigit()]
            result.append({
                'name': name,
                'route_based': route_based,
                'interface': entry.get('interface') or None,
                'ike_version': int_or_none(entry.get('ike-version')) or 1,
                'mode': entry.get('mode', 'main'),
                'type': entry.get('type', 'static'),
                'remote_gw': to_ip(entry.get('remote-gw')) or to_ip(entry.get('remote-gw6')),
                'remote_gw_ddns': entry.get('remotegw-ddns') or None,
                'local_gw': to_ip(entry.get('local-gw')),
                'authmethod': entry.get('authmethod', 'psk'),
                'peertype': entry.get('peertype', 'any'),
                'proposals': _proposals(entry) or [('aes128', 'sha256'), ('aes256', 'sha256')],
                'dhgroups': dhgrp or [14, 5],
                'keylife': int_or_none(entry.get('keylife')) or 86400,
                'nattraversal': entry.get('nattraversal', 'enable'),
                'dpd': entry.get('dpd', 'on-demand'),
                'net_device': entry.is_enabled('net-device'),
                'add_route': entry.get('add-route', 'enable') != 'disable',
                'comments': entry.get('comments', '') or '',
                'exchange_interface_ip': entry.is_enabled('exchange-interface-ip'),
            })
    return result


def phase2(vdom):
    result = []
    for path in ('vpn ipsec phase2-interface', 'vpn ipsec phase2'):
        for name, entry in vdom.table(path):
            dhgrp = [int(g) for g in entry.get_list('dhgrp') if g.isdigit()]
            result.append({
                'name': name,
                'phase1': entry.get('phase1name'),
                'proposals': _proposals(entry) or [('aes128', 'sha1'), ('aes256', 'sha1')],
                'pfs': entry.get('pfs', 'enable') != 'disable',
                'dhgroups': dhgrp or [14, 5],
                'keylife_seconds': int_or_none(entry.get('keylifeseconds')) or 43200,
                'keylife_kbs': int_or_none(entry.get('keylifekbs')),
                'replay': entry.get('replay', 'enable') != 'disable',
                'auto_negotiate': entry.is_enabled('auto-negotiate'),
                'src': _selector(entry, 'src'),
                'dst': _selector(entry, 'dst'),
                'comments': entry.get('comments', '') or '',
            })
    return result


def _selector(entry, side):
    kind = entry.get(f'{side}-addr-type', 'subnet')
    if kind in ('subnet', 'subnet6'):
        key = f'{side}-subnet' if kind == 'subnet' else f'{side}-subnet6'
        prefix = pairs_to_prefix(entry.get_list(key))
        return {'type': 'subnet', 'value': prefix or ('0.0.0.0/0' if kind == 'subnet' else '::/0')}
    if kind in ('name', 'name6'):
        return {'type': 'name', 'value': entry.get(f'{side}-name') or entry.get(f'{side}-name6')}
    if kind in ('range', 'range6'):
        return {'type': 'range', 'value': f"{entry.get(f'{side}-start-ip')}-{entry.get(f'{side}-end-ip')}"}
    if kind in ('ip', 'ip6'):
        return {'type': 'ip', 'value': entry.get(f'{side}-start-ip')}
    return {'type': kind, 'value': None}
