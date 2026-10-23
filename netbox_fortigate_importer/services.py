"""
From an uploaded file to an import run, and finding the NetBox device a
configuration belongs to.

The uploaded bytes live only in this request's memory: they are hashed,
parsed and dropped. Only the extracted data (no secrets) is saved.
"""
from __future__ import annotations

import hashlib

from django.db.models import Q

from .extract import load
from .models import FortiGateBinding, ImportRun, RunStatusChoices
from .parser.files import is_encrypted


def ingest(data: bytes, filename, user, password=None):
    """
    Parse an upload and save it as a new run. Raises the parser's errors
    (PasswordRequired when the file is encrypted and no password was given).
    The run is linked to its FortiGate when one is known for the file.
    """
    digest = hashlib.sha256(data).hexdigest()
    size = len(data)
    encrypted = is_encrypted(data)
    document = load(data, password)
    del data
    run = ImportRun(
        filename=(filename or '')[:255], file_sha256=digest, file_size=size, encrypted=encrypted,
        info=document['info'], data=document, created_by=user, status=RunStatusChoices.PARSED,
    )
    run.binding = find_binding(document['info'])
    run.save()
    return run


def find_binding(info):
    """The FortiGate a configuration belongs to: same serial, else same hostname."""
    serial = info.get('serial')
    if serial:
        binding = FortiGateBinding.objects.filter(serial=serial).first()
        if binding:
            return binding
    hostname = info.get('hostname')
    if hostname:
        found = list(FortiGateBinding.objects.filter(Q(hostname__iexact=hostname) | Q(name__iexact=hostname))[:2])
        if len(found) == 1:
            return found[0]
    return None


def candidate_devices(info, limit=10):
    """NetBox devices that look like this firewall: serial, then name."""
    from dcim.models import Device

    found = []
    serial = info.get('serial')
    if serial:
        found += list(Device.objects.filter(serial__iexact=serial)[:limit])
    hostname = info.get('hostname')
    if hostname:
        found += list(Device.objects.filter(name__iexact=hostname).exclude(pk__in=[d.pk for d in found])[:limit])
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
    binding.serial = info.get('serial') or binding.serial
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
