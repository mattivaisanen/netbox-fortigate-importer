"""
The vocabulary the mappers, planner and applier share.

A mapper turns part of the importer's document into `Desired` objects: what
one NetBox object should look like. The planner compares each one with
NetBox, the applier writes it.

Values in `Desired.fields` and `Desired.m2m` can be:

- plain values (str, int, bool, None, dict),
- `Ref(key)`: another Desired object of the same plan (resolved to its pk),
- a model instance that already exists outside the plan (the device, a site).

Field names may be dotted to own one key of a JSON field
(`local_context_data.fortigate`): only that key is compared and written.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from decimal import Decimal

from django.contrib.contenttypes.models import ContentType
from django.db import models


@dataclass(frozen=True)
class Ref:
    """A reference to another Desired object of the same plan, by key."""
    key: str

    def token(self):
        return f'$ref:{self.key}'


def is_ref_token(value):
    return isinstance(value, str) and value.startswith('$ref:')


def ref_key(token):
    return token[len('$ref:'):]


#: Order in which models are written (lower first). Deletes run in reverse.
MODEL_ORDER = {
    'dcim.manufacturer': 10,
    'dcim.platform': 11,
    'ipam.rir': 12,
    'ipam.role': 13,
    'ipam.vrf': 20,
    'ipam.asn': 21,
    'dcim.virtualchassis': 25,
    'dcim.device': 30,
    'dcim.virtualdevicecontext': 35,
    'ipam.vlangroup': 40,
    'ipam.vlan': 41,
    'dcim.interface': 50,
    'dcim.macaddress': 55,
    'ipam.fhrpgroup': 58,
    'ipam.prefix': 60,
    'ipam.iprange': 61,
    'ipam.ipaddress': 62,
    'ipam.fhrpgroupassignment': 63,
    'vpn.ikeproposal': 70,
    'vpn.ikepolicy': 71,
    'vpn.ipsecproposal': 72,
    'vpn.ipsecpolicy': 73,
    'vpn.ipsecprofile': 74,
    'vpn.tunnel': 75,
    'vpn.tunneltermination': 76,
}
#: Plugin models default to after the core ones; mappers can set their own.
DEFAULT_ORDER = 100


def model_label(model):
    return f'{model._meta.app_label}.{model._meta.model_name}'


@dataclass
class Desired:
    key: str
    model: type[models.Model]
    section: str
    label: str = ''
    vdom: str = ''
    #: Owned fields: compared on every import, written on create and update.
    fields: dict = field(default_factory=dict)
    #: Owned many-to-many fields: field name -> list of values.
    m2m: dict = field(default_factory=dict)
    #: Natural key to find an existing object nobody manages yet (adopt).
    lookup: dict | None = None
    #: Set only when creating; never compared.
    create_defaults: dict = field(default_factory=dict)
    #: Fields written in a last pass, after every other object exists
    #: (a device's primary IP, a virtual chassis master).
    deferred: dict = field(default_factory=dict)
    #: Other firewalls may manage the same object (a prefix both ends of a
    #: link see, a tunnel between two FortiGates). Removing it from one
    #: firewall releases it while another still manages it.
    shared: bool = False
    #: Reference data (platform, manufacturer, ASN, IKE proposals): found or
    #: created, never deleted by the importer, only released.
    release_only: bool = False
    #: An object the importer never creates or deletes (the bound device):
    #: it only owns some of its fields. Set `instance`.
    partial: bool = False
    #: The NetBox object, when the mapper already knows it.
    instance: models.Model | None = None
    #: Write order; defaults from MODEL_ORDER.
    order: int | None = None
    #: Note shown on the planned change.
    note: str = ''

    def __post_init__(self):
        if self.order is None:
            self.order = MODEL_ORDER.get(model_label(self.model), DEFAULT_ORDER)
        if not self.label:
            self.label = self.key

    @property
    def refs(self):
        """Keys of every Ref in fields, m2m and lookup."""
        found = []

        def walk(value):
            if isinstance(value, Ref):
                found.append(value.key)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    walk(item)
            elif isinstance(value, dict):
                for item in value.values():
                    walk(item)

        walk(self.fields)
        walk(self.m2m)
        walk(self.lookup or {})
        walk(self.create_defaults)
        walk(self.deferred)
        return list(dict.fromkeys(found))


def normalize(value):
    """A JSON-ready, comparable form of a field value."""
    if isinstance(value, Ref):
        return value.token()
    if isinstance(value, models.Model):
        return value.pk
    if isinstance(value, ContentType):
        return value.pk
    if isinstance(value, Decimal):
        return str(value.normalize()) if value == value.to_integral() else str(value)
    if isinstance(value, (ipaddress.IPv4Interface, ipaddress.IPv6Interface,
                          ipaddress.IPv4Network, ipaddress.IPv6Network,
                          ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return str(value)
    if isinstance(value, set):
        return sort_values(normalize(v) for v in value)
    if isinstance(value, (list, tuple)):
        # Order matters inside JSON (DNS servers); many-to-many values are
        # sorted by the caller with sort_values().
        return [normalize(v) for v in value]
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in value.items()}
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    # netaddr types, MAC addresses, choices: their string form.
    return str(value)


def sort_values(values):
    """A many-to-many value list in a stable order."""
    return sorted(values, key=lambda v: (isinstance(v, str), str(v)))


def model_field(model, name):
    """The Django field for `name` (the part before a dot)."""
    return model._meta.get_field(name.split('.', 1)[0])


def read_field(instance, name):
    """
    The current value of an owned field, normalized. FKs read as pk;
    dotted names read one key of a JSON field (None when missing).
    """
    base, _, sub = name.partition('.')
    django_field = instance._meta.get_field(base)
    if sub:
        data = getattr(instance, base) or {}
        return normalize(data.get(sub))
    if django_field.is_relation and django_field.many_to_one:
        return getattr(instance, django_field.attname)
    value = getattr(instance, django_field.attname)
    return normalize(value)


def read_m2m(instance, name):
    if instance.pk is None:
        return []
    return sort_values(getattr(instance, name).values_list('pk', flat=True))


def snapshot(instance, desired):
    """Owned field values of `instance`, normalized, for comparison."""
    values = {name: read_field(instance, name) for name in list(desired.fields) + list(desired.deferred)}
    for name in desired.m2m:
        values[name] = read_m2m(instance, name)
    return values


def write_field(instance, name, value):
    """Set an owned field on `instance` (value already resolved)."""
    base, _, sub = name.partition('.')
    django_field = instance._meta.get_field(base)
    if sub:
        data = dict(getattr(instance, base) or {})
        if value is None:
            data.pop(sub, None)
        else:
            data[sub] = value
        setattr(instance, base, data or None)
        return
    if django_field.is_relation and django_field.many_to_one:
        setattr(instance, django_field.attname, value.pk if isinstance(value, models.Model) else value)
        return
    if isinstance(value, models.Model):
        value = value.pk
    setattr(instance, django_field.attname, value)
