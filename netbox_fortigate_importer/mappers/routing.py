"""
Desired netbox-routing objects: static routes, prefix lists, AS path and
community lists, route maps, BGP and OSPF. Only imported when
netbox-routing is installed.

How FortiGate objects become netbox-routing objects:

- Prefix lists, AS path lists, community lists and route maps have names
  that are unique across NetBox, so their names start with the firewall
  (and VDOM): "HQ-FW01 root RM-ISP-IN". Access lists become prefix lists
  too (netbox-routing has none), so route maps that match them still link.
- Prefix list entries point at netbox-routing's CustomPrefix ("any" has
  none). Communities are global in netbox-routing: found or created, never
  deleted.
- Static route -> StaticRoute on the device, in the VDOM's VRF; distance is
  the metric. Blackhole and SD-WAN routes use the interface next hop
  "blackhole" / "sdwan".
- BGP -> one BGPRouter per AS on the device, a BGPScope per VDOM (VRF), an
  address family per IP version, a BGPPeer per neighbor (its address is an
  IPAM IP address, found or created) with a peer address family carrying
  its route maps and prefix lists. Remote AS numbers become ASNs like the
  firewall's own. Neighbor groups become peer templates.
- OSPF -> an OSPFInstance per VDOM, areas (shared by every device, found
  or created), and an OSPFInterface for each interface a network statement
  covers. Passwords and keys are never imported (the parser dropped them).
"""
from __future__ import annotations

import ipaddress

from django.contrib.contenttypes.models import ContentType

from .base import Desired, Ref
from .native import is_private_asn

ORDER = {
    'customprefix': 120, 'prefixlist': 121, 'prefixlistentry': 122, 'aspath': 123, 'aspathentry': 124,
    'community': 125, 'communitylist': 126, 'communitylistentry': 127, 'routemap': 128, 'routemapentry': 129,
    'staticroute': 130, 'bgprouter': 131, 'bgpscope': 132, 'bgpaddressfamily': 133, 'bgppeertemplate': 134,
    'bgppeer': 135, 'bgppeeraddressfamily': 136, 'ospfarea': 140, 'ospfinstance': 141, 'ospfinterface': 142,
}
#: Well-known community names to their values.
WELL_KNOWN_COMMUNITIES = {
    'no-export': '65535:65281', 'no-advertise': '65535:65282', 'local-as': '65535:65283',
    'no-export-subconfed': '65535:65283', 'internet': '0:0',
}
AREA_TYPES = {'regular': 'standard', 'stub': 'stub', 'nssa': 'nssa'}
OSPF_AUTH = {'md5': 'message-digest', 'message-digest': 'message-digest', 'none': 'null'}
#: Route map match keys that link to another object instead of the JSON blob.
LINKED_MATCHES = {'ip-address': 'prefix', 'ip6-address': 'prefix', 'as-path': 'aspath',
                  'community': 'communitylist'}


def _text(value, limit=200):
    value = ' '.join((value or '').split())
    return value if len(value) <= limit else value[:limit - 1] + '…'


def community_value(text):
    text = (text or '').strip().lower()
    if text in WELL_KNOWN_COMMUNITIES:
        return WELL_KNOWN_COMMUNITIES[text]
    parts = text.split(':')
    if 1 <= len(parts) <= 3 and all(p.replace('.', '').isdigit() for p in parts):
        return text
    return None


def prefix_entry_bounds(prefix, ge, le):
    """(ge, le, note) that netbox-routing accepts for one FortiGate rule.

    netbox-routing refuses an le that isn't longer than the prefix (FortiGate
    writes "le 0" for an exact match) and, in the version tested, refuses ge
    and le together; the le is then left out and noted.
    """
    length = ipaddress.ip_network(prefix, strict=False).prefixlen if prefix else None
    note = ''
    if le is not None and length is not None and le <= length:
        le = None
    if ge is not None and length is not None and ge <= length:
        ge = None
    if ge is not None and le is not None:
        note = f'le {le} left out (netbox-routing takes ge or le, not both)'
        le = None
    return ge, le, note


class RoutingMapper:
    def __init__(self, ctx, existing=()):
        from netbox_routing import models as rt

        from dcim.models import Interface
        from ipam.models import ASN, RIR, IPAddress

        self.ctx = ctx
        self.m = {
            'customprefix': rt.CustomPrefix, 'prefixlist': rt.PrefixList, 'prefixlistentry': rt.PrefixListEntry,
            'aspath': rt.ASPath, 'aspathentry': rt.ASPathEntry, 'community': rt.Community,
            'communitylist': rt.CommunityList, 'communitylistentry': rt.CommunityListEntry,
            'routemap': rt.RouteMap, 'routemapentry': rt.RouteMapEntry, 'staticroute': rt.StaticRoute,
            'bgprouter': rt.BGPRouter, 'bgpscope': rt.BGPScope, 'bgpaddressfamily': rt.BGPAddressFamily,
            'bgppeertemplate': rt.BGPPeerTemplate, 'bgppeer': rt.BGPPeer,
            'bgppeeraddressfamily': rt.BGPPeerAddressFamily, 'ospfarea': rt.OSPFArea,
            'ospfinstance': rt.OSPFInstance, 'ospfinterface': rt.OSPFInterface,
            'asn': ASN, 'rir': RIR, 'ip': IPAddress, 'interface': Interface,
        }
        self.existing = {d.key: d for d in existing}
        self.out = []
        self.keys = set()
        self.interfaces = {i['name']: i for i in ctx.data.get('interfaces', [])}

    def known(self, key):
        return key in self.existing or key in self.keys

    def new(self, kind, key, **kwargs):
        kwargs.setdefault('order', ORDER.get(kind))
        desired = Desired(key=key, model=self.m[kind], **kwargs)
        self.out.append(desired)
        self.keys.add(key)
        return desired

    def run(self):
        for vdom, data in self.ctx.data.get('vdoms', {}).items():
            VdomRouting(self, vdom, data).run()
        return self.out

    # Shared objects

    def asn(self, number):
        """Ref to the ASN `number` (created like the firewall's own), or None."""
        key = f'asn/{number}'
        if self.known(key):
            return Ref(key)
        ctx = self.ctx
        rir = ctx.binding.asn_rir
        if rir is None and is_private_asn(number):
            if not self.known('rir/private'):
                self.out.append(Desired(
                    key='rir/private', model=self.m['rir'], section='routing', label='RIR Private',
                    lookup={'slug': 'private'}, create_defaults={'name': 'Private', 'is_private': True},
                    release_only=True, shared=True,
                ))
                self.keys.add('rir/private')
            rir = Ref('rir/private')
        if rir is None:
            ctx.note(f'AS {number}: set "RIR for new ASNs" on the FortiGate to import it')
            return None
        self.out.append(Desired(key=key, model=self.m['asn'], section='routing', label=f'AS {number}',
                                lookup={'asn': number}, create_defaults={'rir': rir},
                                release_only=True, shared=True))
        self.keys.add(key)
        return Ref(key)

    def custom_prefix(self, network):
        key = f'rt/prefix/{network}'
        if not self.known(key):
            self.new('customprefix', key, section='routing', label=f'Routing prefix {network}',
                     fields={'prefix': network}, lookup={'prefix': network}, shared=True, release_only=True)
        return Ref(key)

    def community(self, value):
        key = f'rt/community/{value}'
        if not self.known(key):
            self.new('community', key, section='routing', label=f'Community {value}',
                     fields={'community': value}, lookup={'community': value},
                     create_defaults={'status': 'active'}, shared=True, release_only=True)
        return Ref(key)


class VdomRouting:
    def __init__(self, parent, vdom, data):
        self.p = parent
        self.ctx = parent.ctx
        self.vdom = vdom
        self.data = data
        ctx = self.ctx
        self.scope = f'{ctx.name} {vdom}' if ctx.multi_vdom else ctx.name
        self.base = f'rt/{vdom}'
        self.vrf = ctx.vrf_ref(vdom)
        #: FortiGate list name -> key, per kind
        self.lists = {'prefix': {}, 'aspath': {}, 'communitylist': {}, 'routemap': {}}

    def new(self, kind, key, **kwargs):
        kwargs.setdefault('vdom', self.vdom)
        kwargs.setdefault('section', 'routing')
        return self.p.new(kind, key, **kwargs)

    def name(self, name, limit=100):
        return _text(f'{self.scope} {name}', limit)

    def run(self):
        self.prefix_lists()
        self.aspath_lists()
        self.community_lists()
        self.route_maps()
        self.static_routes()
        self.bgp()
        self.ospf()

    # Filters

    def prefix_lists(self):
        for item in self.data.get('prefix_lists', []) + self.data.get('access_lists', []):
            source = 'access list' if 'exact_match' in (item['rules'][0] if item['rules'] else {}) else 'prefix list'
            if item['name'] in self.lists['prefix']:
                self.ctx.note(f'{source.capitalize()} {item["name"]} ({self.vdom}): a prefix list has the same '
                              'name, skipped')
                continue
            key = f'{self.base}/prefix-list/{item["name"]}'
            name = self.name(item['name'])
            self.new('prefixlist', key, label=f'Prefix list {name}',
                     fields={'name': name, 'family': item['family'],
                             'description': _text(item.get('comments') or
                                                  (f'FortiGate access list {item["name"]}'
                                                   if source == 'access list' else ''))},
                     lookup={'name__iexact': name})
            self.lists['prefix'][item['name']] = key
            for rule in item['rules']:
                if rule['prefix'] is None:
                    # Never match more than the firewall does: a permit is left
                    # out, a deny denies everything from here on.
                    what = 'left out' if rule['action'] == 'permit' else 'imported as "deny any"'
                    self.ctx.note(f'{source.capitalize()} {item["name"]} rule {rule["id"]} ({self.vdom}): '
                                  f'its prefix cannot be read; {what}. Check it in NetBox.')
                    if rule['action'] == 'permit':
                        continue
                    rule = {**rule, 'prefix': 'any', 'ge': None, 'le': None, 'exact_match': False}
                prefix = None if rule['prefix'] == 'any' else str(
                    ipaddress.ip_network(rule['prefix'], strict=False))
                ge, le = rule.get('ge'), rule.get('le')
                if source == 'access list' and prefix and not rule.get('exact_match'):
                    le = ipaddress.ip_network(prefix).max_prefixlen
                ge, le, note = prefix_entry_bounds(prefix, ge, le)
                if note:
                    self.ctx.note(f'Prefix list {item["name"]} rule {rule["id"]} ({self.vdom}): {note}')
                prefix_type = ContentType.objects.get_for_model(self.p.m['customprefix']) if prefix else None
                self.new('prefixlistentry', f'{key}/{rule["id"]}', label=f'Prefix list {name} rule {rule["id"]}',
                         fields={'prefix_list': Ref(key), 'sequence': rule['id'], 'action': rule['action'],
                                 'assigned_prefix_type': prefix_type,
                                 'assigned_prefix_id': self.p.custom_prefix(prefix) if prefix else None,
                                 'ge': ge, 'le': le},
                         lookup={'prefix_list': Ref(key), 'sequence': rule['id']})

    def aspath_lists(self):
        for item in self.data.get('aspath_lists', []):
            key = f'{self.base}/aspath/{item["name"]}'
            name = self.name(item['name'])
            self.new('aspath', key, label=f'AS path list {name}', fields={'name': name},
                     lookup={'name__iexact': name})
            self.lists['aspath'][item['name']] = key
            for rule in item['rules']:
                self.new('aspathentry', f'{key}/{rule["id"]}', label=f'AS path {name} rule {rule["id"]}',
                         fields={'aspath': Ref(key), 'sequence': rule['id'], 'action': rule['action'],
                                 'pattern': _text(rule['regexp'], 200)},
                         lookup={'aspath': Ref(key), 'sequence': rule['id']})

    def community_lists(self):
        for item in self.data.get('community_lists', []):
            key = f'{self.base}/community-list/{item["name"]}'
            name = self.name(item['name'])
            self.new('communitylist', key, label=f'Community list {name}', fields={'name': name},
                     lookup={'name': name})
            self.lists['communitylist'][item['name']] = key
            for rule in item['rules']:
                values = [community_value(v) for v in (rule.get('match') or '').split()]
                if rule.get('regexp') or not values or None in values:
                    self.ctx.note(f'Community list {item["name"]} rule {rule["id"]} ({self.vdom}): '
                                  'only plain community values can be imported, skipped')
                    continue
                for value in values:
                    community = self.p.community(value)
                    self.new('communitylistentry', f'{key}/{rule["id"]}/{value}',
                             label=f'Community list {name} {rule["action"]} {value}',
                             fields={'community_list': Ref(key), 'action': rule['action'], 'community': community},
                             lookup={'community_list': Ref(key), 'community': community})

    def route_maps(self):
        for item in self.data.get('route_maps', []):
            key = f'{self.base}/route-map/{item["name"]}'
            name = self.name(item['name'])
            self.new('routemap', key, label=f'Route map {name}',
                     fields={'name': name, 'description': _text(item.get('comments'))},
                     lookup={'name__iexact': name})
            self.lists['routemap'][item['name']] = key
            for rule in item['rules']:
                linked = {'prefix': [], 'aspath': [], 'communitylist': []}
                match = {}
                for field, value in rule['match'].items():
                    kind = LINKED_MATCHES.get(field)
                    target = self.lists[kind].get(value) if kind else None
                    if target:
                        linked[kind].append(Ref(target))
                    else:
                        match[field] = value
                self.new('routemapentry', f'{key}/{rule["id"]}', label=f'Route map {name} rule {rule["id"]}',
                         fields={'route_map': Ref(key), 'sequence': rule['id'], 'action': rule['action'],
                                 'match': match or None, 'set': rule['set'] or None},
                         m2m={'match_prefix_list': linked['prefix'], 'match_aspath': linked['aspath'],
                              'match_community_list': linked['communitylist'], 'match_community': []},
                         lookup={'route_map': Ref(key), 'sequence': rule['id']})

    # Static routes

    def static_routes(self):
        device = self.ctx.device
        for route in self.data.get('static_routes', []):
            if route.get('dst_address'):
                self.ctx.note(f'Static route {route["seq"]} ({self.vdom}): destination is the address object '
                              f'"{route["dst_address"]}", skipped')
                continue
            vrf = self.ctx.vrf_ref(self.vdom, route.get('vrf'))
            if route['blackhole']:
                hop = 'blackhole'
            elif route['sdwan'] and not route['device']:
                hop = 'sdwan'
            else:
                hop = route['device']
            if not route['gateway'] and not hop:
                self.ctx.note(f'Static route {route["seq"]} ({self.vdom}): no gateway or interface, skipped')
                continue
            description = '; '.join(x for x in [None if route['enabled'] else 'disabled', route['comment']] if x)
            prefix = str(ipaddress.ip_network(route['dst'], strict=False))
            distance = route['distance'] if route['distance'] is not None else (
                254 if route['blackhole'] else 10)
            self.new('staticroute', f'{self.base}/static{route["family"]}/{route["seq"]}',
                     label=f'Static route {prefix} via {route["gateway"] or hop}',
                     fields={'prefix': prefix, 'vrf': vrf, 'next_hop': route['gateway'],
                             'interface_next_hop': hop, 'metric': min(distance, 255),
                             'name': f'{self.scope} {route["seq"]}'[:50],
                             'description': _text(description)},
                     m2m={'devices': [device]},
                     lookup={'prefix': prefix, 'vrf': vrf, 'next_hop': route['gateway'],
                             'interface_next_hop': hop, 'devices': device})

    # BGP

    def ip_ref(self, address, label):
        """Ref to an IPAM address for a BGP neighbor (found or created)."""
        host = str(ipaddress.ip_address(address))
        for key in (f'ip/{name}/{host}' for name in self.p.interfaces):
            if self.p.known(key):
                return Ref(key)
        key = f'{self.base}/bgp-ip/{host}'
        if self.p.known(key):
            return Ref(key)
        length = ipaddress.ip_address(host).max_prefixlen
        for net in self.ctx.data.get('connected', []):
            network = ipaddress.ip_network(net['prefix'], strict=False)
            if net.get('vdom') == self.vdom and ipaddress.ip_address(host) in network:
                length = network.prefixlen
                break
        self.p.out.append(Desired(
            key=key, model=self.p.m['ip'], section='routing', label=f'IP address {host}', vdom=self.vdom,
            fields={'address': f'{host}/{length}', 'vrf': self.vrf},
            lookup={'address__net_host': host, 'vrf': self.vrf},
            create_defaults={'status': 'active', 'description': _text(label)},
            shared=True, release_only=True,
        ))
        self.p.keys.add(key)
        return Ref(key)

    def interface_ip(self, name):
        item = self.p.interfaces.get(name) or {}
        if not item.get('ip'):
            return None
        key = f'ip/{name}/{item["ip"].split("/")[0]}'
        return Ref(key) if self.p.known(key) else None

    def bgp(self):
        bgp = self.data.get('bgp')
        if not bgp:
            return
        if not str(bgp['as']).isdigit():
            self.ctx.note(f'BGP ({self.vdom}): AS "{bgp["as"]}" is not a number, skipped')
            return
        local_as = self.p.asn(int(bgp['as']))
        if not local_as:
            return
        device = self.ctx.device
        device_type = ContentType.objects.get_by_natural_key('dcim', 'device')
        router = f'rt/bgp/{bgp["as"]}'
        if not self.p.known(router):
            name = _text(f'{self.ctx.name} AS{bgp["as"]}', 100)
            self.new('bgprouter', router, vdom='', label=f'BGP router AS{bgp["as"]}',
                     fields={'name': name, 'asn': local_as, 'assigned_object_type': device_type,
                             'assigned_object_id': device},
                     lookup={'asn': local_as, 'assigned_object_type': device_type, 'assigned_object_id': device})
        scope = f'{router}/scope/{self.ctx.vrf_key(self.vdom) or "global"}'
        if self.p.known(scope):
            self.ctx.note(f'BGP ({self.vdom}): shares its BGP scope with another VDOM (no VRF per VDOM)')
        else:
            self.new('bgpscope', scope, label=f'BGP scope {self.scope}',
                     fields={'router': Ref(router), 'vrf': self.vrf,
                             'description': _text(f'router-id {bgp["router_id"]}' if bgp.get('router_id') else '')},
                     lookup={'router': Ref(router), 'vrf': self.vrf})
        families = {}
        for version in sorted({ipaddress.ip_address(n['ip']).version for n in bgp['neighbors']
                               if self._is_ip(n['ip'])} | {4}):
            family = 'ipv4-unicast' if version == 4 else 'ipv6-unicast'
            key = f'{scope}/{family}'
            if not self.p.known(key):
                self.new('bgpaddressfamily', key, label=f'BGP {family} {self.scope}',
                         fields={'scope': Ref(scope), 'address_family': family},
                         lookup={'scope': Ref(scope), 'address_family': family})
            families[version] = Ref(key)

        for group in bgp.get('neighbor_groups', []):
            remote = self.p.asn(int(group['remote_as'])) if str(group.get('remote_as', '')).isdigit() else None
            name = self.name(group['name'])
            self.new('bgppeertemplate', f'{scope}/group/{group["name"]}', label=f'BGP peer group {name}',
                     fields={'name': name, 'remote_as': remote, 'enabled': True,
                             'description': _text('ranges: ' + ', '.join(group.get('ranges', []))
                                                  if group.get('ranges') else '')},
                     lookup={'name': name, 'remote_as': remote})

        peer_type = ContentType.objects.get_for_model(self.p.m['bgppeer'])
        for neighbor in bgp['neighbors']:
            if not self._is_ip(neighbor['ip']):
                continue
            remote = self.p.asn(int(neighbor['remote_as'])) if str(neighbor.get('remote_as') or '').isdigit() \
                else None
            peer_ip = self.ip_ref(neighbor['ip'], f'BGP neighbor of {self.ctx.name}: '
                                                  f'{neighbor["description"] or neighbor["ip"]}')
            key = f'{scope}/peer/{neighbor["ip"]}'
            extra = [x for x, on in (('route reflector client', neighbor['route_reflector_client']),
                                     ('next-hop-self', neighbor['next_hop_self']), ('BFD', neighbor['bfd']),
                                     ('soft reconfiguration', neighbor['soft_reconfiguration'])) if on]
            self.new('bgppeer', key, label=f'BGP peer {neighbor["ip"]}',
                     fields={'scope': Ref(scope), 'peer': peer_ip,
                             'name': _text(neighbor['description'], 100) or None,
                             'remote_as': remote, 'local_as': local_as, 'enabled': neighbor['enabled'],
                             'status': 'active' if neighbor['enabled'] else 'offline',
                             'source': self.interface_ip(neighbor['update_source']) if neighbor['update_source']
                             else None,
                             'ttl': neighbor['ebgp_ttl'] if neighbor['ebgp_multihop'] else None,
                             'description': _text(', '.join(extra))},
                     lookup={'scope': Ref(scope), 'peer': peer_ip})
            version = ipaddress.ip_address(neighbor['ip']).version
            policy = {
                'routemap_in': self._list('routemap', neighbor['route_map_in']),
                'routemap_out': self._list('routemap', neighbor['route_map_out']),
                'prefixlist_in': self._list('prefix', neighbor['prefix_list_in']),
                'prefixlist_out': self._list('prefix', neighbor['prefix_list_out']),
            }
            self.new('bgppeeraddressfamily', f'{key}/af', label=f'BGP peer {neighbor["ip"]} address family',
                     fields={'assigned_object_type': peer_type, 'assigned_object_id': Ref(key),
                             'address_family': families[version], 'enabled': neighbor['enabled'], **policy},
                     lookup={'assigned_object_type': peer_type, 'assigned_object_id': Ref(key),
                             'address_family': families[version]})
        if bgp.get('networks'):
            self.ctx.note(f'BGP ({self.vdom}): network statements are not imported (netbox-routing has no '
                          'place for them)')

    @staticmethod
    def _is_ip(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _list(self, kind, name):
        if not name:
            return None
        key = self.lists[kind].get(name)
        if not key:
            self.ctx.note(f'{name} ({self.vdom}): referenced by BGP but not in the configuration')
            return None
        return Ref(key)

    # OSPF

    def ospf(self):
        ospf = self.data.get('ospf')
        if not ospf:
            return
        if not ospf.get('router_id'):
            self.ctx.note(f'OSPF ({self.vdom}): no router ID, skipped')
            return
        key = f'{self.base}/ospf'
        name = self.name('OSPF')
        self.new('ospfinstance', key, label=f'OSPF {self.scope}',
                 fields={'name': name, 'router_id': ospf['router_id'], 'process_id': 1,
                         'device': self.ctx.device, 'vrf': self.vrf},
                 lookup={'device': self.ctx.device, 'name': name})
        areas = {}
        for area in ospf['areas']:
            area_key = f'rt/ospf-area/{area["id"]}'
            if not self.p.known(area_key):
                kind = 'backbone' if area['id'] in ('0', '0.0.0.0') else AREA_TYPES.get(area['type'], 'standard')
                self.new('ospfarea', area_key, vdom='', label=f'OSPF area {area["id"]}',
                         fields={'area_id': area['id']}, lookup={'area_id': area['id']},
                         create_defaults={'area_type': kind}, shared=True, release_only=True)
            areas[area['id']] = Ref(area_key)
        settings = {i['interface']: i for i in ospf['interfaces'] if i.get('interface')}
        passive = set(ospf.get('passive_interfaces') or [])
        covered = set()
        for name_, item in self.p.interfaces.items():
            if item.get('vdom') != self.vdom or not item.get('ip'):
                continue
            address = ipaddress.ip_interface(item['ip']).ip
            area = next((n['area'] for n in ospf['networks']
                         if address in ipaddress.ip_network(n['prefix'], strict=False)), None)
            if area is None:
                continue
            if area not in areas:
                area_key = f'rt/ospf-area/{area}'
                if not self.p.known(area_key):
                    self.new('ospfarea', area_key, vdom='', label=f'OSPF area {area}',
                             fields={'area_id': area}, lookup={'area_id': area},
                             create_defaults={'area_type': 'backbone' if area in ('0', '0.0.0.0') else 'standard'},
                             shared=True, release_only=True)
                areas[area] = Ref(area_key)
            covered.add(name_)
            options = settings.get(name_, {})
            auth = options.get('authentication')
            if auth and auth not in OSPF_AUTH:
                self.ctx.note(f'OSPF interface {name_} ({self.vdom}): {auth} authentication is not imported')
            ref = self.ctx.interface_ref(name_)
            self.new('ospfinterface', f'{key}/interface/{name_}', label=f'OSPF on {name_}',
                     fields={'instance': Ref(key), 'area': areas[area], 'interface': ref,
                             'passive': name_ in passive, 'priority': options.get('priority'),
                             'bfd': options.get('bfd') or None, 'authentication': OSPF_AUTH.get(auth)},
                     lookup={'interface': ref})
        for name_ in sorted(set(settings) - covered):
            self.ctx.note(f'OSPF interface {name_} ({self.vdom}): no network statement covers it, skipped')
