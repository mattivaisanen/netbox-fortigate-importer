"""What a mapper knows while it builds the desired objects of one run."""
from __future__ import annotations

from dataclasses import dataclass, field

from django.utils.text import slugify

from .base import Ref


@dataclass
class Context:
    binding: object
    data: dict
    #: Settings for this run: plugin settings overridden by the binding's.
    options: dict
    #: Messages for the plan summary (skipped objects and why).
    notes: list = field(default_factory=list)

    @property
    def device(self):
        """The bound device, or a reference to the device this import creates."""
        return self.binding.device or Ref('device')

    @property
    def device_exists(self):
        return self.binding.device_id is not None

    @property
    def new_device(self):
        """How to create the device ({'name', 'site', ...} as objects), or {}."""
        if self.device_exists:
            return {}
        if not hasattr(self, '_new_device'):
            from dcim.models import DeviceRole, DeviceType, Site

            spec = self.binding.new_device or {}
            models = {'site': Site, 'role': DeviceRole, 'device_type': DeviceType}
            found = {'name': spec.get('name') or self.info.get('hostname') or self.binding.name}
            for name, model in models.items():
                found[name] = model.objects.filter(pk=spec.get(name)).first() if spec.get(name) else None
            self._new_device = found
        return self._new_device

    @property
    def site(self):
        return self.binding.device.site if self.device_exists else self.new_device['site']

    @property
    def device_type(self):
        """The device's type, or None when the import creates a Fortinet one."""
        return self.binding.device.device_type if self.device_exists else self.new_device['device_type']

    @property
    def is_fortinet(self):
        device_type = self.device_type
        return device_type is None or device_type.manufacturer.slug == 'fortinet'

    @property
    def info(self):
        return self.data.get('info', {})

    @property
    def multi_vdom(self):
        return bool(self.info.get('multi_vdom'))

    @property
    def name(self):
        """Short name used in the names of objects the importer creates."""
        return self.binding.name

    def slug(self, *parts):
        return slugify('-'.join(str(p) for p in parts))[:100]

    def note(self, text):
        if text not in self.notes:
            self.notes.append(text)

    # Keys. Interfaces are global on a FortiGate (one namespace for all
    # VDOMs), most other objects live in a VDOM.

    def interface_ref(self, name):
        return Ref(f'interface/{name}') if name else None

    def vdc_ref(self, vdom):
        return Ref(f'vdc/{vdom}') if self.multi_vdom and vdom else None

    def vrf_key(self, vdom, vrf_id=None):
        """Key of the VRF for a VDOM (and FortiOS VRF number), or None."""
        if vrf_id:
            return f'vrf/{vdom}/{vrf_id}'
        if self.multi_vdom and self.options.get('vrf_per_vdom'):
            return f'vrf/{vdom}'
        return None

    def vrf_ref(self, vdom, vrf_id=None):
        key = self.vrf_key(vdom, vrf_id)
        return Ref(key) if key else None

    def vrf_name(self, vdom, vrf_id=None):
        parts = [self.name]
        if self.multi_vdom:
            parts.append(vdom)
        if vrf_id:
            parts.append(f'vrf{vrf_id}')
        return ' '.join(parts)
