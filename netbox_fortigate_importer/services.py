"""
From an uploaded file to an import run, and finding the NetBox device a
configuration belongs to.

The uploaded bytes live only in this request's memory: they are hashed,
parsed and dropped. Only the extracted data (no secrets) is saved.
"""
from __future__ import annotations

import hashlib
import re

from django.db.models import Q
from django.views.decorators.debug import sensitive_variables

from .compare import content_hash
from .extract import load
from .models import FortiGateBinding, ImportRun, RunStatusChoices
from .parser.files import is_encrypted


#: How much larger than the upload limit a compressed file may grow.
INFLATE_FACTOR = 10


# Every local variable from here down (file bytes, text, password) is left
# out of Django's error pages and error e-mails if something fails.
@sensitive_variables()
def ingest(data: bytes, filename, user, password=None):
    """
    Parse an upload and save it as a new run. Raises the parser's errors
    (PasswordRequired when the file is encrypted and no password was given).
    The run is linked to its FortiGate when one is known for the file.
    """
    digest = hashlib.sha256(data).hexdigest()
    size = len(data)
    encrypted = is_encrypted(data)
    from .settings import get_setting

    max_size = int(get_setting('max_upload_mb') or 50) * 1024 * 1024 * INFLATE_FACTOR
    document = load(data, password, max_size=max_size)
    del data
    run = ImportRun(
        filename=(filename or '')[:255], file_sha256=digest, file_size=size, encrypted=encrypted,
        data_sha256=content_hash(document),
        info=document['info'], data=document, created_by=user, status=RunStatusChoices.PARSED,
    )
    run.binding = find_binding(document['info'])
    run.save()
    return run


def find_binding(info):
    """
    The FortiGate a configuration belongs to: same serial number, else the
    only FortiGate with the same hostname (and no other serial number),
    unless the hostname is generic (a FortiOS default such as
    "FortiGate-VM64"). Otherwise the user chooses on the device choice page.
    """
    serial = info.get('serial')
    if serial:
        binding = FortiGateBinding.objects.filter(serial=serial).first()
        if binding:
            return binding
    if not info.get('hostname') or is_generic_hostname(info['hostname'], info):
        return None
    found = list(bindings_by_hostname(info)[:2])
    return found[0] if len(found) == 1 else None


#: FortiOS's default hostnames are the model ("FortiGate-VM64", "FGT60F",
#: "FGVM64", "FortiWiFi-60F"): many firewalls share them.
_GENERIC_HOSTNAME = re.compile(
    r'^(?:(?:FortiGate|FortiWiFi)(?:-(?:VM\d*[A-Z0-9]*|\d+[A-Z][A-Z0-9-]*))?'
    r'|(?:FGT|FG|FWF|FGR)\d+[A-Z][A-Z0-9]*|FGVM\d*[A-Z0-9]*)$',
    re.IGNORECASE,
)


def is_generic_hostname(hostname, info=None):
    """
    True for a hostname that doesn't tell firewalls apart: a FortiOS default
    (the model name or code) or a serial number. Such names never pick a
    FortiGate on their own; the device page suggests the matches instead.
    """
    from .parser.layout import looks_like_serial

    name = (hostname or '').strip()
    if not name or _GENERIC_HOSTNAME.match(name) or looks_like_serial(name.upper()):
        return True
    info = info or {}
    return name.lower() in {str(info.get(k) or '').lower() for k in ('model_name', 'model_code')} - {''}


def bindings_by_hostname(info):
    """FortiGates with this configuration's hostname whose serial does not contradict it."""
    hostname = info.get('hostname')
    if not hostname:
        return FortiGateBinding.objects.none()
    found = FortiGateBinding.objects.filter(Q(hostname__iexact=hostname) | Q(name__iexact=hostname))
    serial = info.get('serial')
    if serial:
        found = found.filter(Q(serial='') | Q(serial=serial))
    return found


def candidate_devices(info, user=None, limit=10):
    """NetBox devices that look like this firewall (and `user` may see): serial, then name."""
    from dcim.models import Device

    devices = Device.objects.restrict(user, 'view') if user is not None else Device.objects.all()
    found = []
    serial = info.get('serial')
    if serial:
        found += list(devices.filter(serial__iexact=serial)[:limit])
    bound = bindings_by_hostname(info).exclude(device__isnull=True).values_list('device', flat=True)
    found += list(devices.filter(pk__in=list(bound)).exclude(pk__in=[d.pk for d in found])[:limit])
    hostname = info.get('hostname')
    if hostname:
        found += list(devices.filter(name__iexact=hostname).exclude(pk__in=[d.pk for d in found])[:limit])
    return found[:limit]


def bind(run, device, name=None):
    """Link a run to a device: the device's existing binding, or a new one."""
    info = run.info or {}
    binding = FortiGateBinding.objects.filter(device=device).first()
    if binding is None:
        binding = FortiGateBinding(
            name=(name or info.get('hostname') or device.name)[:100], device=device,
        )
        if FortiGateBinding.objects.filter(name=binding.name).exists():
            binding.name = f'{binding.name} ({device.pk})'[:100]
    # The serial the FortiGate had, when this configuration's differs (a
    # replaced unit, or the wrong device): the device page warns.
    serial = info.get('serial')
    binding.replaced_serial = binding.serial if binding.serial and serial and serial != binding.serial else ''
    binding.serial = serial or binding.serial
    binding.hostname = info.get('hostname') or binding.hostname
    binding.model_code = info.get('model_code') or binding.model_code
    binding.firmware = info.get('version') or binding.firmware
    binding.multi_vdom = bool(info.get('multi_vdom'))
    binding.virtual_chassis = device.virtual_chassis
    binding.full_clean()
    binding.save()
    run.binding = binding
    run.save(update_fields=['binding'])
    return binding


def refresh_binding(binding, info):
    """Keep a binding's header facts current with its latest configuration."""
    changed = False
    for field, key in (('serial', 'serial'), ('hostname', 'hostname'), ('model_code', 'model_code'),
                       ('firmware', 'version')):
        value = info.get(key)
        if value and getattr(binding, field) != value:
            setattr(binding, field, value)
            changed = True
    if bool(info.get('multi_vdom')) != binding.multi_vdom:
        binding.multi_vdom = bool(info.get('multi_vdom'))
        changed = True
    if changed:
        binding.save()


def bind_new_device(run, site, role, device_type=None, name=None):
    """
    Link a run to a FortiGate NetBox does not have yet. Nothing is written
    to NetBox here: the device becomes a planned "create" change of the run.
    """
    info = run.info or {}
    name = (name or info.get('hostname') or '').strip() or None
    binding = FortiGateBinding(
        name=(name or info.get('serial') or 'FortiGate')[:100],
        new_device={'name': name, 'site': site.pk, 'role': role.pk,
                    'device_type': device_type.pk if device_type else None},
        serial=info.get('serial') or '', hostname=info.get('hostname') or '',
        model_code=info.get('model_code') or '', firmware=info.get('version') or '',
        multi_vdom=bool(info.get('multi_vdom')),
    )
    if FortiGateBinding.objects.filter(name=binding.name).exists():
        binding.name = f'{binding.name} ({info.get("serial") or run.pk})'[:100]
    binding.full_clean()
    binding.save()
    run.binding = binding
    run.save(update_fields=['binding'])
    return binding
