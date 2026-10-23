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
        return self.binding.device

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
