"""
IPsec VPNs as NetBox VPN objects.

FortiOS phase 1 -> IKE proposals (one per proposal and DH group) and an IKE
policy; phase 2 -> IPsec proposals and an IPsec policy; together an IPsec
profile. Each phase 1 is a tunnel with this firewall's termination on the
tunnel interface.

A tunnel between two FortiGates that are both imported is one NetBox tunnel
with two terminations: its name is built from both public addresses, sorted,
so the second firewall finds the tunnel the first one created.
Pre-shared keys are never imported (the parser drops them).
"""
from __future__ import annotations

import ipaddress

from django.contrib.contenttypes.models import ContentType

from .base import Desired, Ref

ENCRYPTION = {
    'des': 'des-cbc', '3des': '3des-cbc',
    'aes128': 'aes-128-cbc', 'aes192': 'aes-192-cbc', 'aes256': 'aes-256-cbc',
    'aes128gcm': 'aes-128-gcm', 'aes256gcm': 'aes-256-gcm',
}
AUTHENTICATION = {
    'md5': 'hmac-md5', 'sha1': 'hmac-sha1', 'sha256': 'hmac-sha256',
    'sha384': 'hmac-sha384', 'sha512': 'hmac-sha512',
}
AUTH_METHODS = {'psk': 'preshared-keys', 'signature': 'certificates'}


def _auth(token, gcm):
    # GCM carries its own integrity check; FortiOS writes the PRF (prfsha256)
    # after it, which NetBox has no field for.
    if gcm or not token or token.startswith('prf'):
        return None
    return AUTHENTICATION.get(token, 'unknown')


def tunnel_name(a, b):
    """Name of a tunnel between two public addresses, the same from both ends."""
    first, second = sorted([a, b], key=lambda ip: ipaddress.ip_address(ip))
    return f'IPsec {first} - {second}'


class VPNMapper:
    def __init__(self, native):
        from vpn.models import IKEPolicy, IKEProposal, IPSecPolicy, IPSecProfile, IPSecProposal, Tunnel, \
            TunnelTermination

        self.native = native
        self.ctx = native.ctx
        self.m = {
            'ike_proposal': IKEProposal, 'ike_policy': IKEPolicy, 'ipsec_proposal': IPSecProposal,
            'ipsec_policy': IPSecPolicy, 'ipsec_profile': IPSecProfile, 'tunnel': Tunnel,
            'termination': TunnelTermination,
        }
        self.keys = set()

    def add(self, desired):
        if desired.key in self.keys:
            return
        self.keys.add(desired.key)
        self.native.add(desired)

    def run(self):
        for vdom, data in self.ctx.data.get('vdoms', {}).items():
            phase2 = {}
            for p2 in data.get('ipsec_phase2', []):
                phase2.setdefault(p2['phase1'], []).append(p2)
            for p1 in data.get('ipsec_phase1', []):
                self.phase1(vdom, p1, phase2.get(p1['name'], []))

    def ike_proposals(self, p1):
        keys = []
        method = AUTH_METHODS.get(p1.get('authmethod'), 'preshared-keys')
        lifetime = p1.get('keylife')
        for enc_token, auth_token in p1.get('proposals', []):
            encryption = ENCRYPTION.get(enc_token)
            if encryption is None:
                self.ctx.note(f'IPsec {p1["name"]}: NetBox has no "{enc_token}" encryption, proposal skipped')
                continue
            auth = _auth(auth_token, encryption.endswith('gcm'))
            for group in p1.get('dhgroups') or [None]:
                name = f'FortiGate IKE {enc_token}-{auth_token or "none"} DH{group} {p1.get("authmethod", "psk")}'
                if lifetime:
                    name += f' {lifetime}s'
                key = f'vpn/ike-proposal/{name}'
                self.add(Desired(
                    key=key, model=self.m['ike_proposal'], section='vpn', label=name,
                    lookup={'name': name},
                    fields={'name': name, 'authentication_method': method, 'encryption_algorithm': encryption,
                            'authentication_algorithm': auth, 'group': group, 'sa_lifetime': lifetime},
                    release_only=True, shared=True,
                ))
                keys.append(key)
        return keys

    def ipsec_proposals(self, p2):
        keys = []
        for enc_token, auth_token in p2.get('proposals', []):
            encryption = ENCRYPTION.get(enc_token)
            if encryption is None and enc_token != 'null':
                self.ctx.note(f'IPsec {p2["name"]}: NetBox has no "{enc_token}" encryption, proposal skipped')
                continue
            auth = _auth(auth_token, bool(encryption and encryption.endswith('gcm')))
            if encryption is None and auth is None:
                continue
            name = f'FortiGate IPsec {enc_token}-{auth_token or "none"}'
            if p2.get('keylife_seconds'):
                name += f' {p2["keylife_seconds"]}s'
            if p2.get('keylife_kbs'):
                name += f' {p2["keylife_kbs"]}KB'
            key = f'vpn/ipsec-proposal/{name}'
            self.add(Desired(
                key=key, model=self.m['ipsec_proposal'], section='vpn', label=name, lookup={'name': name},
                fields={'name': name, 'encryption_algorithm': encryption, 'authentication_algorithm': auth,
                        'sa_lifetime_seconds': p2.get('keylife_seconds'),
                        'sa_lifetime_data': p2.get('keylife_kbs')},
                release_only=True, shared=True,
            ))
            keys.append(key)
        return keys

    def phase1(self, vdom, p1, phase2s):
        ctx = self.ctx
        base = f'vpn/{vdom}/{p1["name"]}'
        prefix = f'{ctx.name} {vdom} ' if ctx.multi_vdom else f'{ctx.name} '
        version = p1.get('ike_version') or 1
        policy_name = f'{prefix}{p1["name"]}'
        self.add(Desired(
            key=f'{base}/ike-policy', model=self.m['ike_policy'], section='vpn', vdom=vdom,
            label=f'IKE policy {policy_name}', lookup={'name': policy_name},
            fields={'name': policy_name, 'version': version,
                    'mode': (p1.get('mode') or 'main') if version == 1 else None,
                    'description': p1.get('comments') or ''},
            m2m={'proposals': [Ref(k) for k in self.ike_proposals(p1)]},
        ))
        profile = None
        if phase2s:
            p2 = phase2s[0]
            if len(phase2s) > 1:
                ctx.note(f'IPsec {p1["name"]}: NetBox holds one IPsec policy per tunnel, '
                         f'using phase 2 "{p2["name"]}" of {len(phase2s)}')
            ipsec_policy_name = f'{prefix}{p2["name"]}'
            pfs = (p2.get('dhgroups') or [None])[0] if p2.get('pfs') else None
            self.add(Desired(
                key=f'{base}/ipsec-policy', model=self.m['ipsec_policy'], section='vpn', vdom=vdom,
                label=f'IPsec policy {ipsec_policy_name}', lookup={'name': ipsec_policy_name},
                fields={'name': ipsec_policy_name, 'pfs_group': pfs},
                m2m={'proposals': [Ref(k) for k in self.ipsec_proposals(p2)]},
            ))
            profile = Ref(f'{base}/ipsec-profile')
            self.add(Desired(
                key=profile.key, model=self.m['ipsec_profile'], section='vpn', vdom=vdom,
                label=f'IPsec profile {policy_name}', lookup={'name': policy_name},
                fields={'name': policy_name, 'mode': 'esp', 'ike_policy': Ref(f'{base}/ike-policy'),
                        'ipsec_policy': Ref(f'{base}/ipsec-policy')},
            ))
        self.tunnel(vdom, p1, base, profile, policy_name)

    def tunnel(self, vdom, p1, base, profile, policy_name):
        ctx = self.ctx
        local = p1.get('local_gw')
        outside_key = None
        outer = self.native.interfaces.get(p1.get('interface') or '')
        if outer and outer.get('ip'):
            outside_key = self.native.ip_key(outer['name'], outer['ip'])
            local = local or outer['ip'].split('/')[0]
        remote = p1.get('remote_gw') if p1.get('type') == 'static' else None
        shared = bool(local and remote)
        name = tunnel_name(local, remote) if shared else policy_name
        fields = {'name': name, 'status': 'active', 'encapsulation': 'ipsec-tunnel'}
        create = {}
        if profile:
            # Both ends of a shared tunnel have their own profile: the first
            # firewall imported sets it.
            (create if shared else fields)['ipsec_profile'] = profile
        if p1.get('comments') and not shared:
            fields['description'] = p1['comments']
        tunnel_key = f'vpn/tunnel/{name}' if shared else f'{base}/tunnel'
        self.add(Desired(
            key=tunnel_key, model=self.m['tunnel'], section='vpn', vdom=vdom, label=f'Tunnel {name}',
            fields=fields, create_defaults=create, lookup={'name': name}, shared=shared,
        ))
        if not p1.get('route_based'):
            ctx.note(f'IPsec {p1["name"]} is policy-based: tunnel imported without a termination')
            return
        interface_type = ContentType.objects.get_by_natural_key('dcim', 'interface')
        interface = ctx.interface_ref(p1['name'])
        self.add(Desired(
            key=f'{base}/termination', model=self.m['termination'], section='vpn', vdom=vdom,
            label=f'Tunnel termination {p1["name"]}',
            fields={'tunnel': Ref(tunnel_key), 'role': 'peer' if remote else 'hub',
                    'termination_type': interface_type, 'termination_id': interface,
                    'outside_ip': Ref(outside_key) if outside_key else None},
            lookup={'termination_type': interface_type, 'termination_id': interface},
        ))
