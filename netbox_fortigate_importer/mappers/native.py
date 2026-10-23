"""
Desired NetBox core objects for one FortiGate: the device's own fields,
platform, HA virtual chassis, VDOMs (virtual device contexts), VRFs, VLANs,
interfaces, IP addresses, prefixes, DHCP ranges, VRRP groups, BGP AS numbers
and IPsec VPNs.
"""
from __future__ import annotations

import ipaddress
import re

from django.contrib.contenttypes.models import ContentType
from django.utils.text import slugify

from .base import Desired, Ref

#: FortiOS interface kinds (extract.system) to NetBox interface types.
KIND_TYPES = {
    'vlan': 'virtual',
    'lag': 'lag',
    'bridge': 'bridge',
    'tunnel': 'virtual',
    'loopback': 'virtual',
    'virtual': 'virtual',
    'wireless': 'other-wireless',
}
#: Physical port speed (Mbps) to a NetBox interface type for new interfaces.
SPEED_TYPES = {
    1000: '1000base-t',
    2500: '2.5gbase-t',
    10000: '10gbase-x-sfpp',
    25000: '25gbase-x-sfp28',
    40000: '40gbase-x-qsfpp',
    100000: '100gbase-x-qsfp28',
}
_SPEED = re.compile(r'^(\d+)(full|half|auto)?$')


def parse_speed(value):
    """FortiOS "10000full" to (speed in Kbps, duplex) as NetBox stores them."""
    match = _SPEED.match(value or '')
    if not match:
        return None, None
    duplex = match.group(2) if match.group(2) in ('full', 'half') else None
    return int(match.group(1)) * 1000, duplex


def physical_type(item, is_vm):
    if is_vm:
        return 'virtual'
    speed, _ = parse_speed(item.get('speed'))
    if speed and speed // 1000 in SPEED_TYPES:
        return SPEED_TYPES[speed // 1000]
    if re.match(r'^x\d+$', item['name']):
        return '10gbase-x-sfpp'
    return '1000base-t'


def is_private_asn(asn):
    return 64512 <= asn <= 65534 or 4200000000 <= asn <= 4294967294


def _ct(app_label, model):
    return ContentType.objects.get_by_natural_key(app_label, model)


def prefix_length(netmask):
    try:
        return ipaddress.IPv4Network(f'0.0.0.0/{netmask}').prefixlen
    except ValueError:
        return None


class NativeMapper:
    """Builds the core NetBox objects. One instance per plan."""

    def __init__(self, ctx):
        from dcim.models import Device, DeviceType, Interface, Manufacturer, Platform, VirtualChassis, \
            VirtualDeviceContext
        from ipam.models import ASN, RIR, VLAN, VRF, FHRPGroup, FHRPGroupAssignment, IPAddress, IPRange, \
            Prefix, VLANGroup

        self.ctx = ctx
        self.m = {
            'device': Device, 'devicetype': DeviceType, 'interface': Interface, 'manufacturer': Manufacturer, 'platform': Platform,
            'vc': VirtualChassis, 'vdc': VirtualDeviceContext, 'asn': ASN, 'rir': RIR, 'vlan': VLAN,
            'vrf': VRF, 'fhrp': FHRPGroup, 'fhrp_assignment': FHRPGroupAssignment, 'ip': IPAddress,
            'iprange': IPRange, 'prefix': Prefix, 'vlangroup': VLANGroup,
        }
        self.out = []
        #: interface name -> key of its primary IPv4 address (for VPN outside IPs).
        self.ip_keys = {}
        self.interfaces = {item['name']: item for item in ctx.data.get('interfaces', [])}

    def add(self, desired):
        self.out.append(desired)
        return desired

    def run(self):
        self.platform()
        self.ha()
        self.vdoms()
        self.vrfs()
        self.vlans()
        self.interface_objects()
        self.addresses()
        self.prefixes()
        self.dhcp()
        self.asns()
        self.vpn()
        self.device()
        return self.out

    # Device, platform, HA

    def platform(self):
        # A platform tied to a manufacturer only fits that manufacturer's
        # device types: tie FortiOS to Fortinet only when the device is one.
        create = {'name': 'FortiOS'}
        if self.ctx.is_fortinet:
            self.add(Desired(
                key='manufacturer/fortinet', model=self.m['manufacturer'], section='device', label='Fortinet',
                lookup={'slug': 'fortinet'}, create_defaults={'name': 'Fortinet'}, release_only=True, shared=True,
            ))
            create['manufacturer'] = Ref('manufacturer/fortinet')
        self.add(Desired(
            key='platform/fortios', model=self.m['platform'], section='device', label='FortiOS',
            lookup={'slug': 'fortios'}, create_defaults=create, release_only=True, shared=True,
        ))

    def ha(self):
        ha = self.ctx.data.get('ha')
        if not ha or ha.get('mode') in (None, 'standalone'):
            return
        name = ha.get('group_name') or f'{self.ctx.name} HA'
        self.add(Desired(
            key='ha/virtual-chassis', model=self.m['vc'], section='device', label=f'HA cluster {name}',
            fields={'name': name, 'domain': f'ha-group-{ha.get("group_id") or 0}'},
            lookup={'name': name},
            deferred={'master': self.ctx.device},
            note='FortiGate HA cluster',
        ))

    def device(self):
        ctx = self.ctx
        info = ctx.info
        fields = {'platform': Ref('platform/fortios')}
        if info.get('serial') and not info.get('is_vm'):
            fields['serial'] = info['serial']
        if ctx.options.get('config_context'):
            fields['local_context_data.fortigate'] = self.config_context()
        ha = ctx.data.get('ha')
        if ha and ha.get('mode') not in (None, 'standalone'):
            fields['virtual_chassis'] = Ref('ha/virtual-chassis')
            fields['vc_position'] = 1
            fields['vc_priority'] = ha.get('priority')
        deferred = {}
        primary = self.primary_ip_key()
        if primary:
            deferred['primary_ip4'] = Ref(primary)
        if ctx.device_exists:
            self.add(Desired(
                key='device', model=self.m['device'], section='device', label=str(ctx.device),
                fields=fields, deferred=deferred, partial=True, instance=ctx.device,
            ))
            return
        # A firewall NetBox does not have yet: the device is created by the
        # apply, like everything else, and removed again by a rollback.
        new = ctx.new_device
        device_type = new['device_type'] or self.device_type()
        self.add(Desired(
            key='device', model=self.m['device'], section='device', label=f'Device {new["name"]}',
            fields=fields, deferred=deferred,
            lookup={'name': new['name'], 'site': new['site']},
            create_defaults={'role': new['role'], 'device_type': device_type, 'status': 'active'},
            note='new device for this FortiGate',
        ))

    def device_type(self):
        """A Fortinet device type named after the model, found or created."""
        model = self.ctx.info.get('model_name') or self.ctx.info.get('model_code') or 'FortiGate'
        slug = slugify(model)[:100]
        key = f'device-type/{slug}'
        self.add(Desired(
            key=key, model=self.m['devicetype'], section='device', label=f'Device type {model}',
            lookup={'manufacturer': Ref('manufacturer/fortinet'), 'model__iexact': model},
            create_defaults={'model': model, 'slug': slug}, release_only=True, shared=True,
        ))
        return Ref(key)

    def config_context(self):
        data = self.ctx.data
        info = data.get('info', {})
        context = {
            'model': info.get('model_name') or info.get('model_code'),
            'firmware': info.get('version'),
            'build': info.get('build'),
            'hostname': info.get('hostname'),
            'opmode': info.get('opmode'),
            'vdoms': sorted(data.get('vdoms', {})) if info.get('multi_vdom') else [],
        }
        ha = data.get('ha')
        if ha and ha.get('mode') not in (None, 'standalone'):
            context['ha'] = {k: ha.get(k) for k in ('mode', 'group_name', 'group_id', 'priority', 'hbdev', 'monitor')}
        context.update(data.get('settings') or {})
        return context

    def primary_ip_key(self):
        """
        The management address: an interface named mgmt*, else a loopback,
        else a LAN interface, that allows HTTPS or SSH.
        """
        def admin(item):
            return item.get('ip') and set(item.get('allowaccess') or []) & {'https', 'ssh'}

        candidates = [i for i in self.interfaces.values() if admin(i)]
        for test in (
            lambda i: i['name'].startswith('mgmt'),
            lambda i: i['kind'] == 'loopback',
            lambda i: i.get('role') == 'lan',
            lambda i: True,
        ):
            for item in candidates:
                if test(item):
                    return self.ip_key(item['name'], item['ip'])
        return None

    # VDOMs and VRFs

    def vdoms(self):
        if not self.ctx.multi_vdom:
            return
        for name in self.ctx.data.get('vdoms', {}):
            self.add(Desired(
                key=f'vdc/{name}', model=self.m['vdc'], section='vdom', label=f'VDOM {name}', vdom=name,
                fields={'device': self.ctx.device, 'name': name, 'status': 'active'},
                lookup={'device': self.ctx.device, 'name': name},
            ))

    def vrfs(self):
        keys = {}
        for vdom in self.ctx.data.get('vdoms', {}):
            key = self.ctx.vrf_key(vdom)
            if key:
                keys[key] = (vdom, None)
        for item in self.interfaces.values():
            if item.get('vrf'):
                keys[self.ctx.vrf_key(item['vdom'], item['vrf'])] = (item['vdom'], item['vrf'])
        for key, (vdom, vrf_id) in keys.items():
            name = self.ctx.vrf_name(vdom, vrf_id)
            self.add(Desired(
                key=key, model=self.m['vrf'], section='vdom', label=f'VRF {name}', vdom=vdom,
                fields={'name': name}, lookup={'name': name},
                create_defaults={'enforce_unique': True,
                                 'description': f'FortiGate {self.ctx.name} VDOM {vdom}'},
            ))

    # VLANs and interfaces

    def vlans(self):
        vlans = {}
        for item in self.interfaces.values():
            if item['kind'] == 'vlan' and item.get('vlan_id'):
                vlans.setdefault(item['vlan_id'], item)
        if not vlans:
            return
        ctx = self.ctx
        slug = slugify(f'{ctx.name}-vlans')[:100]
        site = ctx.site
        self.add(Desired(
            key='vlan-group', model=self.m['vlangroup'], section='interface', label=f'VLAN group {ctx.name}',
            fields={'name': f'{ctx.name} VLANs', 'slug': slug},
            lookup={'slug': slug},
            create_defaults={'scope_type': _ct('dcim', 'site'), 'scope_id': site.pk},
        ))
        for vid, item in sorted(vlans.items()):
            self.add(Desired(
                key=f'vlan/{vid}', model=self.m['vlan'], section='interface', label=f'VLAN {vid}',
                vdom=item['vdom'],
                fields={'group': Ref('vlan-group'), 'vid': vid, 'name': item['alias'] or item['name'],
                        'status': 'active'},
                lookup={'group': Ref('vlan-group'), 'vid': vid},
            ))

    def interface_objects(self):
        ctx = self.ctx
        is_vm = ctx.info.get('is_vm')
        children = {}
        for item in self.interfaces.values():
            if item['kind'] == 'vlan' and item.get('parent') and item.get('vlan_id'):
                children.setdefault(item['parent'], []).append(item['vlan_id'])
        lag_of = {m: i['name'] for i in self.interfaces.values() if i['kind'] == 'lag' for m in i['members']}
        names = list(self.interfaces)
        # Route-based IPsec tunnels have an interface even when `show` leaves it out.
        for vdom, data in ctx.data.get('vdoms', {}).items():
            for p1 in data.get('ipsec_phase1', []):
                if p1['route_based'] and p1['name'] not in self.interfaces:
                    self.interfaces[p1['name']] = {
                        'name': p1['name'], 'vdom': vdom, 'kind': 'tunnel', 'alias': '', 'description': '',
                        'enabled': True, 'ip': None, 'secondary_ips': [], 'ipv6': [], 'mtu': None,
                        'speed': None, 'vlan_id': None, 'parent': p1.get('interface'), 'members': [],
                        'bridge': None, 'vrf': None, 'vrrp': [], 'allowaccess': [],
                    }
                    names.append(p1['name'])
        for name in names:
            item = self.interfaces[name]
            kind = item['kind']
            speed, duplex = parse_speed(item.get('speed'))
            fields = {
                'device': ctx.device,
                'name': name,
                'label': item.get('alias') or '',
                'description': item.get('description') or '',
                'enabled': item.get('enabled', True),
                'mtu': item.get('mtu'),
                'vrf': ctx.vrf_ref(item['vdom'], item.get('vrf')),
                'lag': ctx.interface_ref(lag_of.get(name)),
                'bridge': ctx.interface_ref(item.get('bridge')),
                'parent': ctx.interface_ref(item['parent']) if kind == 'vlan' else None,
            }
            create = {}
            if kind == 'physical':
                create['type'] = physical_type(item, is_vm)
                if speed:
                    fields['speed'] = speed
                    fields['duplex'] = duplex
            else:
                fields['type'] = KIND_TYPES.get(kind, 'virtual')
            m2m = {}
            if ctx.multi_vdom and item.get('vdom'):
                m2m['vdcs'] = [ctx.vdc_ref(item['vdom'])]
            if kind == 'vlan' and item.get('vlan_id'):
                fields['mode'] = 'access'
                fields['untagged_vlan'] = Ref(f'vlan/{item["vlan_id"]}')
            elif name in children:
                fields['mode'] = 'tagged'
                fields['untagged_vlan'] = None
                m2m['tagged_vlans'] = [Ref(f'vlan/{vid}') for vid in sorted(set(children[name]))]
            self.add(Desired(
                key=f'interface/{name}', model=self.m['interface'], section='interface',
                label=f'Interface {name}', vdom=item.get('vdom') or '',
                fields=fields, m2m=m2m, create_defaults=create,
                lookup={'device': ctx.device, 'name': name},
            ))

    # IP addresses, prefixes, DHCP

    def ip_key(self, interface, address):
        host = address.split('/')[0]
        return f'ip/{interface}/{host}'

    def _ip(self, key, address, vrf, assigned_type, assigned_ref, label, vdom, role=None, shared=False,
            status='active', description=None):
        fields = {
            'address': address, 'vrf': vrf, 'assigned_object_type': assigned_type,
            'assigned_object_id': assigned_ref, 'role': role, 'status': status,
        }
        create = {}
        if description is not None:
            create['description'] = description
        self.add(Desired(
            key=key, model=self.m['ip'], section='ip', label=label, vdom=vdom, fields=fields,
            create_defaults=create, shared=shared,
            lookup={'address__net_host': address.split('/')[0], 'vrf': vrf},
        ))

    def addresses(self):
        ctx = self.ctx
        interface_type = _ct('dcim', 'interface')
        fhrp_type = _ct('ipam', 'fhrpgroup')
        for name, item in self.interfaces.items():
            vrf = ctx.vrf_ref(item['vdom'], item.get('vrf'))
            ref = ctx.interface_ref(name)
            loopback = 'loopback' if item['kind'] == 'loopback' else None
            if item.get('ip'):
                key = self.ip_key(name, item['ip'])
                self.ip_keys[name] = key
                self._ip(key, item['ip'], vrf, interface_type, ref, f'{item["ip"]} on {name}', item['vdom'],
                         role=loopback)
            for address in item.get('secondary_ips') or []:
                self._ip(self.ip_key(name, address), address, vrf, interface_type, ref,
                         f'{address} on {name}', item['vdom'], role='secondary')
            for address in item.get('ipv6') or []:
                self._ip(self.ip_key(name, address), address, vrf, interface_type, ref,
                         f'{address} on {name}', item['vdom'], role=loopback)
            for vrrp in item.get('vrrp') or []:
                self.vrrp(name, item, vrrp, vrf, interface_type, fhrp_type)

    def vrrp(self, name, item, vrrp, vrf, interface_type, fhrp_type):
        vrid = vrrp['vrid']
        group_key = f'fhrp/{name}/{vrid}'
        protocol = 'vrrp3' if vrrp.get('version') == 3 else 'vrrp2'
        self.add(Desired(
            key=group_key, model=self.m['fhrp'], section='ip', label=f'VRRP {vrid} on {name}',
            vdom=item['vdom'],
            fields={'protocol': protocol, 'group_id': vrid, 'name': f'{self.ctx.name} {name} VRRP {vrid}'},
        ))
        self.add(Desired(
            key=f'{group_key}/assignment', model=self.m['fhrp_assignment'], section='ip',
            label=f'VRRP {vrid} on {name}', vdom=item['vdom'],
            fields={'group': Ref(group_key), 'interface_type': interface_type,
                    'interface_id': self.ctx.interface_ref(name), 'priority': vrrp.get('priority') or 100},
            lookup={'group': Ref(group_key), 'interface_type': interface_type,
                    'interface_id': self.ctx.interface_ref(name)},
        ))
        if vrrp.get('address') and item.get('ip'):
            length = item['ip'].split('/')[1]
            address = f'{vrrp["address"]}/{length}'
            self._ip(f'{group_key}/vip', address, vrf, fhrp_type, Ref(group_key),
                     f'VRRP address {address}', item['vdom'], role='vrrp', shared=True)

    def prefixes(self):
        ctx = self.ctx
        if not ctx.options.get('create_connected_prefixes'):
            return
        site = ctx.site
        seen = set()
        for net in ctx.data.get('connected', []):
            vrf_key = ctx.vrf_key(net['vdom'], net.get('vrf'))
            key = f'prefix/{vrf_key or "global"}/{net["prefix"]}'
            if key in seen:
                continue
            seen.add(key)
            vrf = Ref(vrf_key) if vrf_key else None
            self.add(Desired(
                key=key, model=self.m['prefix'], section='ip', label=f'Prefix {net["prefix"]}', vdom=net['vdom'],
                fields={'prefix': net['prefix'], 'vrf': vrf},
                lookup={'prefix': net['prefix'], 'vrf': vrf},
                create_defaults={'status': 'active', 'scope_type': _ct('dcim', 'site'), 'scope_id': site.pk,
                                 'description': f'{ctx.name} {net["interface"]}'},
                shared=True,
            ))

    def dhcp(self):
        ctx = self.ctx
        for vdom, data in ctx.data.get('vdoms', {}).items():
            for server in data.get('dhcp_servers', []):
                item = self.interfaces.get(server['interface']) or {}
                vrf = ctx.vrf_ref(vdom, item.get('vrf'))
                length = prefix_length(server.get('netmask')) if server.get('netmask') else None
                if length is None and item.get('ip'):
                    length = int(item['ip'].split('/')[1])
                if length is None:
                    ctx.note(f'DHCP server {server["id"]} in {vdom}: no netmask, ranges skipped')
                    continue
                status = 'active' if server.get('enabled', True) else 'reserved'
                for index, rng in enumerate(server.get('ranges', [])):
                    start, end = f'{rng["start"]}/{length}', f'{rng["end"]}/{length}'
                    self.add(Desired(
                        key=f'dhcp/{vdom}/{server["id"]}/range/{rng["start"]}', model=self.m['iprange'],
                        section='ip', label=f'DHCP range {rng["start"]}-{rng["end"]}', vdom=vdom,
                        fields={'start_address': start, 'end_address': end, 'vrf': vrf, 'status': status,
                                'description': f'DHCP on {ctx.name} {server["interface"]}'},
                        lookup={'start_address__net_host': rng['start'], 'end_address__net_host': rng['end'],
                                'vrf': vrf},
                    ))
                for res in server.get('reserved', []):
                    if res.get('action', 'reserved') != 'reserved' or not res.get('ip'):
                        continue
                    address = f'{res["ip"]}/{length}'
                    self.add(Desired(
                        key=f'dhcp/{vdom}/{server["id"]}/reserved/{res["ip"]}', model=self.m['ip'],
                        section='ip', label=f'DHCP reservation {res["ip"]}', vdom=vdom,
                        fields={'address': address, 'vrf': vrf},
                        create_defaults={'status': 'dhcp', 'description': res.get('description') or
                                         f'DHCP reservation {res.get("mac") or ""}'.strip()},
                        lookup={'address__net_host': res['ip'], 'vrf': vrf},
                        shared=True,
                    ))

    # BGP AS numbers

    def asn_key(self, asn):
        return f'asn/{asn}'

    def asns(self):
        ctx = self.ctx
        numbers = set()
        for data in ctx.data.get('vdoms', {}).values():
            bgp = data.get('bgp')
            if bgp and str(bgp.get('as', '')).isdigit():
                numbers.add(int(bgp['as']))
        for asn in sorted(numbers):
            rir = ctx.binding.asn_rir
            if rir is None and is_private_asn(asn):
                rir = Ref('rir/private')
                if not any(d.key == 'rir/private' for d in self.out):
                    self.add(Desired(
                        key='rir/private', model=self.m['rir'], section='routing', label='RIR Private',
                        lookup={'slug': 'private'}, create_defaults={'name': 'Private', 'is_private': True},
                        release_only=True, shared=True,
                    ))
            if rir is None:
                ctx.note(f'AS {asn}: set "RIR for new ASNs" on the FortiGate to import it')
                continue
            self.add(Desired(
                key=self.asn_key(asn), model=self.m['asn'], section='routing', label=f'AS {asn}',
                lookup={'asn': asn}, create_defaults={'rir': rir}, release_only=True, shared=True,
            ))

    # IPsec VPN

    def vpn(self):
        from . import vpn

        vpn.VPNMapper(self).run()
