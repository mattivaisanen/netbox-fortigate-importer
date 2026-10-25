from django.contrib.contenttypes.models import ContentType
from django.db import models

from netbox.plugins import PluginTemplateExtension


def owned_fields(managed, obj):
    """[(label, edited)] for the fields the importer owns on `obj`."""
    from .mappers.base import read_field, read_m2m
    from .planner import META

    found = []
    for name, written in (managed.fields or {}).items():
        if name == META:
            continue
        try:
            field = obj._meta.get_field(name.split('.', 1)[0])
            now = read_m2m(obj, name) if field.many_to_many else read_field(obj, name)
        except Exception:  # noqa: BLE001 - a field the model no longer has
            continue
        label = str(field.verbose_name)
        if '.' in name:
            label = f'{label}: {name.split(".", 1)[1]}'
        found.append((label, now != written))
    return found


def managed_rows(obj, request):
    """[(ManagedObject, owned fields)] for `obj`, if the user may see them."""
    from .models import ManagedObject

    if request is None or not request.user.has_perm('netbox_fortigate_importer.view_fortigatebinding'):
        return []
    rows = ManagedObject.objects.filter(
        object_type=ContentType.objects.get_for_model(obj), object_id=obj.pk,
    ).select_related('binding', 'last_run')
    return [(row, owned_fields(row, obj)) for row in rows]


class DeviceFortiGatePanel(PluginTemplateExtension):
    """
    On a device bound to a FortiGate: its binding, last import and, since the
    device is itself a managed object, the fields the importer owns on it.
    One panel, so the device page does not also get "Managed by FortiGate".
    """
    models = ('dcim.device',)

    def right_page(self):
        device = self.context['object']
        binding = device.fortigate_bindings.first()
        if binding is None:
            return ''
        return self.render('netbox_fortigate_importer/inc/device_panel.html', extra_context={
            'binding': binding, 'last_run': binding.last_run,
            'managed': managed_rows(device, self.context.get('request')),
        })


class ManagedByFortiGatePanel(PluginTemplateExtension):
    """
    On every object the importer manages: which FortiGate owns it, which
    fields the next import compares, and which of those were edited in
    NetBox since (the next import flags them).
    """
    models = None

    def right_page(self):
        obj = self.context.get('object')
        if not isinstance(obj, models.Model) or obj.pk is None or obj._meta.app_label == 'netbox_fortigate_importer':
            return ''
        if obj._meta.label_lower == 'dcim.device' and obj.fortigate_bindings.exists():
            return ''  # DeviceFortiGatePanel shows it
        managed = managed_rows(obj, self.context.get('request'))
        if not managed:
            return ''
        return self.render('netbox_fortigate_importer/inc/managed_panel.html', extra_context={'managed': managed})


template_extensions = [DeviceFortiGatePanel, ManagedByFortiGatePanel]
