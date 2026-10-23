"""
Desired netbox-security objects: the firewall's addresses, services, zones,
policies and NAT. Only imported when netbox-security is installed.

How FortiGate objects become netbox-security objects:

- Names are scoped per firewall (and VDOM) with netbox-security's
  `identifier` field, so two FortiGates can both have an address "all".
  NAT pools and rule sets have no identifier: their names start with it.
- Address (subnet) -> Address on a netbox-security CustomPrefix, not an IPAM
  prefix, so firewall objects don't fill IPAM with host routes. FQDN and
  wildcard FQDN -> Address with a DNS name. A range that isn't one subnet
  -> an AddressSet of the subnets that cover it exactly. Geography, MAC and
  dynamic addresses have no netbox-security form: skipped with a note.
- Address group / VIP group -> AddressSet. VIP -> Address of its mapped
  (inside) address, so a policy to a VIP reads as a policy to the server.
- Custom service -> Application (protocols, ports); service group ->
  ApplicationSet. netbox-security keeps ports as single numbers, so wide
  ranges are described instead of listed.
- Zone, and every interface a policy names directly -> SecurityZone,
  assigned to its interfaces.
- Policy -> one SecurityZonePolicy per source x destination interface, in
  the firewall's order (`index`). Policies reference AddressLists, one per
  address and side: netbox-security refuses the same list on both sides of
  a policy, which "all" to "all" would otherwise be.
- IP pool -> NatPool (+ member); VIP -> destination NAT rule; central SNAT
  or policy NAT -> source NAT rules. NAT rules point at IPAM objects (that
  is netbox-security's model), so the importer finds or creates those
  prefixes and ranges and never deletes them.
"""
from __future__ import annotations

import ipaddress

from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError

from .base import Desired, Ref

#: Write order of netbox-security models (core models are below 100).
ORDER = {
    'customprefix': 100, 'address': 101, 'addressset': 102, 'addresslist': 104,
    'application': 105, 'applicationset': 106, 'securityzone': 107, 'securityzoneassignment': 108,
    'securityzonepolicy': 110, 'natpool': 111, 'natpoolmember': 112, 'natruleset': 113,
    'natrulesetassignment': 114, 'natrule': 115,
}
#: IP protocol numbers to netbox-security protocols.
IP_PROTOCOLS = {0: 'ALL', 1: 'ICMP', 2: 'IGMP', 4: 'IPIP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP',
                58: 'ICMP6', 103: 'PIM', 132: 'SCTP'}
#: Most single ports listed for one application; wider ranges are described.
MAX_PORTS = 64
UNSUPPORTED_ADDRESS = {
    'geography': 'country addresses', 'mac': 'MAC addresses', 'dynamic': 'dynamic addresses',
    'wildcard': 'wildcard masks',
}


def nested_order(kind, depth):
    """A group inside a group is written after it (the plan sorts by order, then key)."""
    return ORDER[kind] + min(depth, 99) / 100


def _text(value, limit=200):
    value = ' '.join((value or '').split())
    return value if len(value) <= limit else value[:limit - 1] + '…'


def _ct(model):
    return ContentType.objects.get_for_model(model)


def range_networks(start, end):
    """The subnets that cover start..end exactly."""
    first, last = ipaddress.ip_address(start), ipaddress.ip_address(end)
    if last < first:
        first, last = last, first
    return [str(n) for n in ipaddress.summarize_address_range(first, last)]


def port_spec(ranges):
    return ', '.join(str(r['low']) if r['low'] == r['high'] else f'{r["low"]}-{r["high"]}' for r in ranges)


def expand_ports(ranges, which='dst'):
    """Single port numbers of some ranges, or None when there are too many."""
    ports = set()
    for r in ranges:
        low, high = (r['low'], r['high']) if which == 'dst' else (r.get('src_low'), r.get('src_high'))
        if low is None:
            continue
        high = high if high is not None else low
        if (low, high) == (0, 65535) or (low, high) == (1, 65535):
            continue
        ports.update(range(low, high + 1))
        if len(ports) > MAX_PORTS:
            return None
    return sorted(p for p in ports if p > 0)


class SecurityMapper:
    def __init__(self, ctx, existing=()):
        from dcim.models import Interface
        from ipam.models import IPRange, Prefix
        from netbox_security import models as sec

        self.ctx = ctx
        self.m = {
            'customprefix': sec.CustomPrefix, 'address': sec.Address, 'addressset': sec.AddressSet,
            'addresslist': sec.AddressList, 'application': sec.Application,
            'applicationset': sec.ApplicationSet, 'securityzone': sec.SecurityZone,
            'securityzoneassignment': sec.SecurityZoneAssignment, 'securityzonepolicy': sec.SecurityZonePolicy,
            'natpool': sec.NatPool, 'natpoolmember': sec.NatPoolMember, 'natruleset': sec.NatRuleSet,
            'natrulesetassignment': sec.NatRuleSetAssignment, 'natrule': sec.NatRule,
            'prefix': Prefix, 'iprange': IPRange, 'interface': Interface,
        }
        #: Desired objects of the other mappers, by key (prefixes, DHCP ranges).
        self.existing = {d.key: d for d in existing}
        self.out = []
        self.keys = set()
        self.interfaces = {i['name']: i for i in ctx.data.get('interfaces', [])}

    def add(self, desired):
        self.out.append(desired)
        self.keys.add(desired.key)
        return desired

    def new(self, kind, key, **kwargs):
        kwargs.setdefault('order', ORDER.get(kind))
        return self.add(Desired(key=key, model=self.m[kind], **kwargs))

    def run(self):
        for vdom, data in self.ctx.data.get('vdoms', {}).items():
            VdomMapper(self, vdom, data).run()
        return self.out

    # IPAM objects NAT rules and pools point at. Same keys as the core
    # mapper, so a connected prefix it already plans is reused.

    def ipam_prefix(self, vdom, network, label):
        ctx = self.ctx
        vrf_key = ctx.vrf_key(vdom)
        key = f'prefix/{vrf_key or "global"}/{network}'
        if key in self.existing or key in self.keys:
            return Ref(key)
        vrf = Ref(vrf_key) if vrf_key else None
        self.add(Desired(
            key=key, model=self.m['prefix'], section='nat', label=f'Prefix {network}', vdom=vdom,
            fields={'prefix': network, 'vrf': vrf}, lookup={'prefix': network, 'vrf': vrf},
            create_defaults={'status': 'active', 'description': _text(f'{ctx.name} {label}')},
            shared=True, release_only=True,
        ))
        return Ref(key)

    def ipam_range(self, vdom, start, end, label):
        """A Prefix when start..end is one subnet, else an IPRange; None if it overlaps another range."""
        networks = range_networks(start, end)
        if len(networks) == 1:
            return 'prefix', self.ipam_prefix(vdom, networks[0], label)
        ctx = self.ctx
        vrf_key = ctx.vrf_key(vdom)
        key = f'range/{vrf_key or "global"}/{start}-{end}'
        if key in self.keys:
            return 'address_range', Ref(key)
        bits = ipaddress.ip_address(start).max_prefixlen
        if self.range_overlaps(vrf_key, start, end):
            ctx.note(f'{label}: {start}-{end} overlaps another IP range in NetBox, left out of NAT')
            return None, None
        vrf = Ref(vrf_key) if vrf_key else None
        self.add(Desired(
            key=key, model=self.m['iprange'], section='nat', label=f'IP range {start}-{end}', vdom=vdom,
            fields={'start_address': f'{start}/{bits}', 'end_address': f'{end}/{bits}', 'vrf': vrf},
            lookup={'start_address__net_host': start, 'end_address__net_host': end, 'vrf': vrf},
            create_defaults={'status': 'active', 'description': _text(f'{ctx.name} {label}')},
            shared=True, release_only=True,
        ))
        return 'address_range', Ref(key)

    def range_overlaps(self, vrf_key, start, end):
        first, last = ipaddress.ip_address(start), ipaddress.ip_address(end)
        for desired in self.existing.values():
            if desired.model is not self.m['iprange'] or desired.fields.get('vrf') != (
                    Ref(vrf_key) if vrf_key else None):
                continue
            other_start = ipaddress.ip_interface(desired.fields['start_address']).ip
            other_end = ipaddress.ip_interface(desired.fields['end_address']).ip
            if other_start.version == first.version and other_start <= last and other_end >= first:
                return True
        vrf_id = None
        if vrf_key:
            managed = self.ctx.binding.managed_objects.filter(key=vrf_key).first()
            if managed is None:
                return False  # the VRF is new: nothing in it yet
            vrf_id = managed.object_id
        candidates = self.m['iprange'].objects.filter(vrf_id=vrf_id)
        for other in candidates.only('start_address', 'end_address'):
            if other.start_address.version != first.version:
                continue
            o_start = ipaddress.ip_address(str(other.start_address.ip))
            o_end = ipaddress.ip_address(str(other.end_address.ip))
            if (o_start, o_end) == (first, last):
                return False  # the same range: found and reused
            if o_start <= last and o_end >= first:
                return True
        return False


class VdomMapper:
    """The netbox-security objects of one VDOM."""

    def __init__(self, parent, vdom, data):
        self.p = parent
        self.ctx = parent.ctx
        self.vdom = vdom
        self.data = data
        ctx = self.ctx
        self.scope = f'{ctx.name} {vdom}' if ctx.multi_vdom else ctx.name
        self.identifier = self.scope[:100]
        self.base = f'sec/{vdom}'
        #: FortiGate address-like name -> ('address' | 'addressset', key)
        self.addresses = {}
        #: service name -> ('application' | 'applicationset', key)
        self.services = {}
        self.zones = {}
        #: zone key -> True when a policy uses it on both sides
        self.intra = set()

    def new(self, kind, key, **kwargs):
        kwargs.setdefault('vdom', self.vdom)
        return self.p.new(kind, key, **kwargs)

    def run(self):
        self.address_objects()
        self.group_objects()
        self.service_objects()
        self.zone_objects()
        self.policy_objects()
        self.zone_finish()
        self.nat()

    # Addresses

    def custom_prefix(self, network):
        key = f'sec/prefix/{network}'
        if key not in self.p.keys:
            self.p.new('customprefix', key, section='security', label=f'Custom prefix {network}', vdom='',
                       fields={'prefix': network}, lookup={'prefix': network, 'tenant': None},
                       shared=True, release_only=True)
        return Ref(key)

    def address(self, name, comment, network=None, dns_name=None, key=None):
        key = key or f'{self.base}/address/{name}'
        prefix_type = _ct(self.p.m['customprefix'])
        fields = {'name': name, 'identifier': self.identifier, 'description': _text(comment)}
        if network:
            fields.update(assigned_object_type=prefix_type, assigned_object_id=self.custom_prefix(network),
                          dns_name=None)
        else:
            fields.update(assigned_object_type=None, assigned_object_id=None, dns_name=dns_name)
        self.new('address', key, section='security', label=f'Address {name}', fields=fields,
                 lookup={'name': name, 'identifier': self.identifier})
        return key

    def address_objects(self):
        from netbox_security.validators import validate_fqdn

        for item in self.data.get('addresses', []):
            name, kind = item['name'], item['type']
            if name in self.addresses:
                continue
            if kind in UNSUPPORTED_ADDRESS:
                self.ctx.note(f'Address {name} ({self.vdom}): netbox-security has no {UNSUPPORTED_ADDRESS[kind]}, '
                              'skipped')
                continue
            if kind in ('ipmask', 'ipprefix', 'interface-subnet') and item.get('prefix'):
                network = str(ipaddress.ip_network(item['prefix'], strict=False))
                self.addresses[name] = ('address', self.address(name, item['comment'], network=network))
            elif kind == 'iprange':
                networks = range_networks(item['start'], item['end'])
                if len(networks) == 1:
                    self.addresses[name] = ('address', self.address(name, item['comment'], network=networks[0]))
                    continue
                parts = [self.address(f'{name} {n}', f'Part of range {item["start"]}-{item["end"]}', network=n,
                                      key=f'{self.base}/address/{name}/{n}') for n in networks]
                key = f'{self.base}/set/{name}'
                self.new('addressset', key, section='security', label=f'Address set {name}',
                         fields={'name': name, 'identifier': self.identifier,
                                 'description': _text(item['comment'] or f'{item["start"]}-{item["end"]}')},
                         m2m={'addresses': [Ref(k) for k in parts], 'address_sets': []},
                         lookup={'name': name, 'identifier': self.identifier})
                self.addresses[name] = ('addressset', key)
            elif kind in ('fqdn', 'wildcard-fqdn') and item.get('fqdn'):
                try:
                    validate_fqdn(item['fqdn'])
                except ValidationError:
                    self.ctx.note(f'Address {name} ({self.vdom}): "{item["fqdn"]}" is not a valid DNS name, skipped')
                    continue
                self.addresses[name] = ('address', self.address(name, item['comment'], dns_name=item['fqdn']))
            else:
                self.ctx.note(f'Address {name} ({self.vdom}): type {kind} without an address, skipped')
        for vip in self.data.get('vips', []):
            mapped = vip.get('mapped') or []
            if vip['name'] in self.addresses or len(mapped) != 1 or not mapped[0].get('start'):
                if vip['name'] not in self.addresses and vip.get('type') == 'static-nat':
                    self.ctx.note(f'VIP {vip["name"]} ({self.vdom}): no single mapped address, not usable in policies')
                continue
            start, end = mapped[0]['start'], mapped[0].get('end') or mapped[0]['start']
            try:
                networks = range_networks(start, end)
            except ValueError:
                continue
            if len(networks) != 1:
                continue
            comment = vip['comment'] or f'VIP {vip.get("extip_start")} -> {start}'
            self.addresses[vip['name']] = ('address', self.address(vip['name'], comment, network=networks[0]))

    def group_objects(self):
        groups = {g['name']: g for g in self.data.get('address_groups', [])}
        for g in self.data.get('vip_groups', []):
            groups.setdefault(g['name'], g)
        done = set()
        depth = {}

        def build(name, path=()):
            if name in done or name in path:
                return
            group = groups[name]
            for member in group['members']:
                if member in groups:
                    build(member, path + (name,))
            done.add(name)
            depth[name] = 1 + max([depth.get(m, 0) for m in group['members']] or [0])
            if name in self.addresses:
                return
            addresses, sets, missing = [], [], []
            for member in group['members']:
                kind, key = self.addresses.get(member, (None, None))
                if kind == 'address':
                    addresses.append(Ref(key))
                elif kind == 'addressset':
                    sets.append(Ref(key))
                else:
                    missing.append(member)
            if missing:
                self.ctx.note(f'Address group {name} ({self.vdom}): left out {", ".join(missing)}')
            if group.get('exclude'):
                self.ctx.note(f'Address group {name} ({self.vdom}): excluded members are not imported')
            key = f'{self.base}/set/{name}'
            self.new('addressset', key, section='security', label=f'Address set {name}',
                     fields={'name': name, 'identifier': self.identifier, 'description': _text(group['comment'])},
                     m2m={'addresses': addresses, 'address_sets': sets},
                     lookup={'name': name, 'identifier': self.identifier},
                     order=nested_order('addressset', depth[name]))
            self.addresses[name] = ('addressset', key)

        for name in groups:
            build(name)

    def address_list(self, name, side):
        """The AddressList a policy uses for one address on one side."""
        kind, target = self.addresses.get(name, (None, None))
        if not kind:
            return None
        key = f'{self.base}/list/{side}/{name}'
        if key not in self.p.keys:
            list_name = f'{name} ({"source" if side == "src" else "destination"})'
            target_type = _ct(self.p.m[kind])
            self.new('addresslist', key, section='security', label=f'Address list {list_name}',
                     fields={'name': list_name, 'assigned_object_type': target_type,
                             'assigned_object_id': Ref(target)},
                     lookup={'name': list_name, 'assigned_object_type': target_type,
                             'assigned_object_id': Ref(target)})
        return Ref(key)

    # Services

    def service_objects(self):
        for item in self.data.get('services', []):
            name = item['name']
            protocols, spec = [], []
            dst, src = [], []
            kind = (item.get('protocol') or '').upper()
            if kind.startswith('TCP/UDP'):
                for proto in ('tcp', 'udp', 'sctp'):
                    if item.get(proto):
                        protocols.append(proto.upper())
                        spec.append(f'{proto.upper()} {port_spec(item[proto])}')
                        dst += item[proto]
                        src += item[proto]
                if item.get('fqdn') or item.get('iprange'):
                    spec.append(f'to {item.get("fqdn") or item.get("iprange")}')
            elif kind in ('ICMP', 'ICMP6'):
                protocols.append(kind)
                if item.get('icmp_type') is not None:
                    spec.append(f'{kind} type {item["icmp_type"]}' +
                                (f' code {item["icmp_code"]}' if item.get('icmp_code') is not None else ''))
            elif kind == 'IP':
                number = item.get('protocol_number') or 0
                protocols.append(IP_PROTOCOLS.get(number, 'IP'))
                if number not in IP_PROTOCOLS:
                    spec.append(f'IP protocol {number}')
            else:
                protocols.append('ALL')
            dst_ports = expand_ports(dst, 'dst')
            src_ports = expand_ports(src, 'src')
            if dst_ports is None or src_ports is None:
                spec.append('(port range too wide to list)')
            description = '; '.join(x for x in [item.get('comment'), ', '.join(spec)] if x)
            key = f'{self.base}/application/{name}'
            self.new('application', key, section='security', label=f'Application {name}',
                     fields={'name': name, 'identifier': self.identifier,
                             'protocol': sorted(set(protocols)) or None,
                             'destination_ports': dst_ports or None, 'source_ports': src_ports or None,
                             'description': _text(description)},
                     lookup={'name': name, 'identifier': self.identifier})
            self.services[name] = ('application', key)

        groups = {g['name']: g for g in self.data.get('service_groups', [])}
        done = set()
        depth = {}

        def build(name, path=()):
            if name in done or name in path:
                return
            for member in groups[name]['members']:
                if member in groups:
                    build(member, path + (name,))
            done.add(name)
            depth[name] = 1 + max([depth.get(m, 0) for m in groups[name]['members']] or [0])
            apps, sets, missing = [], [], []
            for member in groups[name]['members']:
                kind, key = self.services.get(member, (None, None))
                (apps if kind == 'application' else sets if kind else missing).append(Ref(key) if kind else member)
            if missing:
                self.ctx.note(f'Service group {name} ({self.vdom}): left out {", ".join(missing)}')
            key = f'{self.base}/application-set/{name}'
            self.new('applicationset', key, section='security', label=f'Application set {name}',
                     fields={'name': name, 'identifier': self.identifier,
                             'description': _text(groups[name]['comment'])},
                     m2m={'applications': apps, 'application_sets': sets},
                     lookup={'name': name, 'identifier': self.identifier},
                     order=nested_order('applicationset', depth[name]))
            self.services[name] = ('applicationset', key)

        for name in groups:
            build(name)

    # Zones

    def zone(self, name, interfaces=(), description='', intrazone=False):
        if name in self.zones:
            return Ref(self.zones[name])
        key = f'{self.base}/zone/{name}'
        self.zones[name] = key
        self.new('securityzone', key, section='security', label=f'Security zone {name}',
                        fields={'name': name, 'identifier': self.identifier, 'allow_intra_zone': intrazone,
                                'description': _text(description)},
                        lookup={'name': name, 'identifier': self.identifier})
        interface_type = _ct(self.p.m['interface'])
        for interface in interfaces:
            if interface not in self.p.interfaces:
                continue
            ref = self.ctx.interface_ref(interface)
            self.new('securityzoneassignment', f'{key}/{interface}', section='security',
                     label=f'Zone {name} on {interface}',
                     fields={'zone': Ref(key), 'assigned_object_type': interface_type, 'assigned_object_id': ref},
                     lookup={'zone': Ref(key), 'assigned_object_type': interface_type, 'assigned_object_id': ref})
        return Ref(key)

    def zone_objects(self):
        for item in self.data.get('zones', []):
            self.zone(item['name'], item['interfaces'], item['description'], item.get('intrazone') == 'allow')

    def zone_for(self, name):
        """The zone of a policy's interface name (a zone, an interface, or "any")."""
        if name in self.zones:
            return Ref(self.zones[name])
        if name == 'any':
            return self.zone('any', description='Any interface')
        return self.zone(name, [name], f'Interface {name}')

    def zone_finish(self):
        for desired in self.p.out:
            if desired.key in self.intra and desired.model is self.p.m['securityzone']:
                desired.fields['allow_intra_zone'] = True

    # Policies

    def policy_objects(self):
        for position, policy in enumerate(self.data.get('policies', []), start=1):
            name = _text(policy['name'] or f'Policy {policy["id"]}', 100)
            src = [x for x in (self.address_list(a, 'src') for a in policy['srcaddr']) if x]
            dst = [x for x in (self.address_list(a, 'dst') for a in policy['dstaddr']) if x]
            missing = [a for a in policy['srcaddr'] + policy['dstaddr'] if a not in self.addresses]
            apps, sets = [], []
            for service in policy['service']:
                kind, key = self.services.get(service, (None, None))
                if kind == 'application':
                    apps.append(Ref(key))
                elif kind:
                    sets.append(Ref(key))
                else:
                    missing.append(service)
            actions = ['deny'] if policy['action'] == 'deny' else ['permit']
            if policy.get('logtraffic') == 'all':
                actions.append('log')
            extra = []
            if not policy.get('enabled', True):
                extra.append('disabled')
            for flag, what in (('srcaddr_negate', 'source'), ('dstaddr_negate', 'destination'),
                               ('service_negate', 'service')):
                if policy.get(flag):
                    extra.append(f'{what} negated')
            if policy.get('users') or policy.get('groups'):
                extra.append('users: ' + ', '.join(policy.get('users', []) + policy.get('groups', [])))
            if policy.get('schedule') not in (None, '', 'always'):
                extra.append(f'schedule {policy["schedule"]}')
            if missing:
                self.ctx.note(f'Policy {policy["id"]} ({self.vdom}): left out {", ".join(dict.fromkeys(missing))}')
            description = _text('; '.join(x for x in [f'FortiGate policy {policy["id"]}', *extra,
                                                      policy.get('comments')] if x))
            for src_intf in policy['srcintf'] or ['any']:
                for dst_intf in policy['dstintf'] or ['any']:
                    src_zone, dst_zone = self.zone_for(src_intf), self.zone_for(dst_intf)
                    if src_zone == dst_zone:
                        self.intra.add(src_zone.key)
                    key = f'{self.base}/policy/{policy["id"]}/{src_intf}/{dst_intf}'
                    self.new('securityzonepolicy', key, section='security',
                             label=f'Policy {policy["id"]} {src_intf} -> {dst_intf}',
                             fields={'name': name, 'identifier': self.identifier, 'index': position,
                                     'source_zone': src_zone, 'destination_zone': dst_zone,
                                     'policy_actions': actions, 'description': description},
                             m2m={'source_address': src, 'destination_address': dst,
                                  'applications': apps, 'application_sets': sets},
                             lookup={'name': name, 'identifier': self.identifier, 'source_zone': src_zone,
                                     'destination_zone': dst_zone})

    # NAT

    def nat(self):
        pools = {}
        for pool in self.data.get('ip_pools', []):
            if pool.get('start') and pool.get('end'):
                pools[pool['name']] = self.nat_pool(f'{self.scope} {pool["name"]}', f'{self.base}/pool/{pool["name"]}',
                                                    pool['start'], pool['end'], f'NAT pool {pool["name"]}')
        self.destination_nat()
        self.source_nat(pools)

    def nat_pool(self, name, key, start, end, label, ports=None):
        kind, ref = self.p.ipam_range(self.vdom, start, end, label)
        if not ref:
            return None
        name = _text(name, 100)
        self.new('natpool', key, section='nat', label=f'NAT pool {name}',
                 fields={'name': name, 'pool_type': 'address', 'status': 'active'},
                 lookup={'name': name, 'pool_type': 'address'})
        member = start if start == end else f'{start}-{end}'
        self.new('natpoolmember', f'{key}/member', section='nat', label=f'NAT pool member {member}',
                 fields={'pool': Ref(key), 'name': member, 'status': 'active', 'address': None,
                         'prefix': ref if kind == 'prefix' else None,
                         'address_range': ref if kind == 'address_range' else None,
                         'destination_ports': ports or None},
                 lookup={'pool': Ref(key), 'name': member})
        return Ref(key)

    def rule_set(self, kind, zones_from, zones_to):
        key = f'{self.base}/nat/{kind}'
        name = _text(f'{self.scope} {kind} NAT', 100)
        self.new('natruleset', key, section='nat', label=f'NAT rule set {name}',
                 fields={'name': name, 'nat_type': kind,
                         'direction': 'inbound' if kind == 'destination' else 'outbound'},
                 m2m={'source_zones': sorted(set(zones_from), key=lambda r: r.key),
                      'destination_zones': sorted(set(zones_to), key=lambda r: r.key)},
                 lookup={'name': name, 'nat_type': kind})
        target = self.ctx.vdc_ref(self.vdom) or self.ctx.device
        target_type = _ct(type(self.ctx.device)) if not isinstance(target, Ref) else \
            ContentType.objects.get_by_natural_key('dcim', 'virtualdevicecontext')
        self.new('natrulesetassignment', f'{key}/assignment', section='nat', label=f'NAT rule set {name} assignment',
                 fields={'ruleset': Ref(key), 'assigned_object_type': target_type, 'assigned_object_id': target},
                 lookup={'ruleset': Ref(key), 'assigned_object_type': target_type, 'assigned_object_id': target})
        return Ref(key)

    def prefixes_of(self, names, label):
        """IPAM prefixes for the subnet addresses among `names` ("all" is any: none)."""
        found = []
        for name in names:
            item = next((a for a in self.data.get('addresses', []) if a['name'] == name), None)
            if item and item['type'] in ('ipmask', 'ipprefix') and item.get('prefix'):
                network = str(ipaddress.ip_network(item['prefix'], strict=False))
                if ipaddress.ip_network(network).prefixlen == 0:
                    continue
                found.append(self.p.ipam_prefix(self.vdom, network, label))
        return found

    def destination_nat(self):
        vips = [v for v in self.data.get('vips', []) if v.get('type', 'static-nat') == 'static-nat'
                and v.get('extip_start') and v.get('mapped')]
        if not vips:
            return
        rules = []
        zones = []
        for vip in vips:
            mapped = vip['mapped'][0]
            mapped_ports = expand_ports([vip['mappedport']]) if vip.get('portforward') and vip.get('mappedport') else None
            pool = self.nat_pool(f'{self.scope} VIP {vip["name"]}', f'{self.base}/vip/{vip["name"]}/pool',
                                 mapped['start'], mapped.get('end') or mapped['start'], f'VIP {vip["name"]}',
                                 ports=mapped_ports)
            kind, ext = self.p.ipam_range(self.vdom, vip['extip_start'], vip.get('extip_end') or vip['extip_start'],
                                          f'VIP {vip["name"]}')
            if not pool or not ext:
                continue
            if vip.get('extintf') and vip['extintf'] != 'any':
                zones.append(self.zone_for(vip['extintf']))
            ports = expand_ports([vip['extport']]) if vip.get('portforward') and vip.get('extport') else None
            text = f'{vip["extip_start"]}'
            if vip.get('portforward') and vip.get('extport'):
                text += f':{port_spec([vip["extport"]])}/{vip.get("protocol", "tcp")}'
            text += f' -> {mapped["start"]}'
            if vip.get('portforward') and vip.get('mappedport'):
                text += f':{port_spec([vip["mappedport"]])}'
            rules.append((vip['name'], {
                'destination_prefixes': [ext] if kind == 'prefix' else [],
                'destination_ranges': [ext] if kind == 'address_range' else [],
            }, {'destination_pool': pool, 'destination_ports': ports or None,
                'description': _text('; '.join(x for x in [vip.get('comment'), text] if x))}))
        if rules:
            rule_set = self.rule_set('destination', zones, [])
            for name, m2m, fields in rules:
                self.nat_rule(rule_set, 'destination', name, m2m, fields)

    def source_nat(self, pools):
        rules, zones_from, zones_to = [], [], []
        central = self.data.get('central_snat', [])
        if central:
            for rule in central:
                pool = next((pools[p] for p in rule['nat_ippool'] if pools.get(p)), None)
                rules.append((f'Central SNAT {rule["id"]}', rule['srcintf'], rule['dstintf'], {
                    'source_prefixes': self.prefixes_of(rule['orig_addr'], 'source NAT'),
                    'destination_prefixes': self.prefixes_of(rule['dst_addr'], 'source NAT'),
                }, {'pool': pool, 'custom_interface': 'off' if not rule['nat'] else (None if pool else 'interface'),
                    'description': _text('; '.join(x for x in [
                        None if rule.get('enabled', True) else 'disabled', rule.get('comments')] if x))}))
        else:
            for policy in self.data.get('policies', []):
                if not policy.get('nat') or policy['action'] == 'deny':
                    continue
                pool = None
                if policy.get('ippool'):
                    pool = next((pools[p] for p in policy['poolname'] if pools.get(p)), None)
                rules.append((f'Policy {policy["id"]}', policy['srcintf'], policy['dstintf'], {
                    'source_prefixes': self.prefixes_of(policy['srcaddr'], 'source NAT'),
                    'destination_prefixes': self.prefixes_of(policy['dstaddr'], 'source NAT'),
                }, {'pool': pool, 'custom_interface': None if pool else 'interface',
                    'description': _text(f'NAT of FortiGate policy {policy["id"]}' +
                                         (f' ({policy["name"]})' if policy['name'] else ''))}))
        if not rules:
            return
        for _, src, dst, _, _ in rules:
            zones_from += [self.zone_for(i) for i in src if i != 'any']
            zones_to += [self.zone_for(i) for i in dst if i != 'any']
        rule_set = self.rule_set('source', zones_from, zones_to)
        for name, _, _, m2m, fields in rules:
            m2m.setdefault('source_ranges', [])
            m2m.setdefault('destination_ranges', [])
            self.nat_rule(rule_set, 'source', name, m2m, fields)

    def nat_rule(self, rule_set, kind, name, m2m, fields):
        key = f'{rule_set.key}/rule/{name}'
        values = {'rule_set': rule_set, 'name': name, 'status': 'active', 'pool': None,
                  'source_pool': None, 'destination_pool': None, 'custom_interface': None,
                  'destination_ports': None}
        values.update(fields)
        if values['custom_interface'] is None:
            values['custom_interface'] = 'None'
        m2m = {'source_prefixes': [], 'destination_prefixes': [], 'source_ranges': [], 'destination_ranges': [],
               **m2m}
        self.new('natrule', key, section='nat', label=f'NAT rule {name}', fields=values, m2m=m2m,
                 lookup={'rule_set': rule_set, 'name': name})
