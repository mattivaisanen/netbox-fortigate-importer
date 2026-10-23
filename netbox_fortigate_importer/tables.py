import django_tables2 as tables
from django.utils.translation import gettext_lazy as _

from netbox.tables import NetBoxTable, columns

from .models import FortiGateBinding, ImportRun, PlannedChange


class FortiGateBindingTable(NetBoxTable):
    name = tables.Column(linkify=True)
    device = tables.Column(linkify=True)
    virtual_chassis = tables.Column(linkify=True)
    multi_vdom = columns.BooleanColumn()
    tags = columns.TagColumn(url_name='plugins:netbox_fortigate_importer:fortigatebinding_list')

    class Meta(NetBoxTable.Meta):
        model = FortiGateBinding
        fields = (
            'pk', 'id', 'name', 'device', 'virtual_chassis', 'serial', 'hostname', 'model_code', 'firmware',
            'multi_vdom', 'description', 'tags', 'created', 'last_updated',
        )
        default_columns = ('pk', 'name', 'device', 'serial', 'model_code', 'firmware', 'multi_vdom')


class ImportRunTable(NetBoxTable):
    id = tables.Column(linkify=True, verbose_name=_('Run'))
    binding = tables.Column(linkify=True)
    status = columns.ChoiceFieldColumn()
    filename = tables.Column(linkify=True)
    created_by = tables.Column()
    applied_by = tables.Column()
    encrypted = columns.BooleanColumn()
    hostname = tables.Column(accessor='info__hostname', verbose_name=_('Hostname'), orderable=False)
    firmware = tables.Column(accessor='info__version', verbose_name=_('Firmware'), orderable=False)
    actions = columns.ActionsColumn(actions=('delete',))

    class Meta(NetBoxTable.Meta):
        model = ImportRun
        fields = (
            'pk', 'id', 'binding', 'status', 'filename', 'hostname', 'firmware', 'encrypted', 'created',
            'created_by', 'planned', 'applied', 'applied_by', 'rolled_back',
        )
        default_columns = ('pk', 'id', 'binding', 'status', 'filename', 'firmware', 'created', 'created_by',
                           'applied')


class PlannedChangeTable(NetBoxTable):
    label = tables.Column(linkify=True, verbose_name=_('Change'))
    action = columns.ChoiceFieldColumn()
    decision = columns.ChoiceFieldColumn()
    outcome = columns.ChoiceFieldColumn()
    object_type = columns.ContentTypeColumn(verbose_name=_('Type'))
    object = tables.Column(linkify=True, orderable=False, verbose_name=_('NetBox object'))
    fields = tables.TemplateColumn(
        template_code='{% for d in record.diff|slice:":4" %}<span class="badge text-bg-'
                      '{% if d.conflict %}purple{% elif d.netbox_edited %}cyan{% else %}secondary{% endif %}'
                      ' me-1">{{ d.field }}</span>{% endfor %}{% if record.diff|length > 4 %}…{% endif %}',
        orderable=False, verbose_name=_('Fields'),
    )
    actions = columns.ActionsColumn(actions=())

    class Meta(NetBoxTable.Meta):
        model = PlannedChange
        fields = (
            'pk', 'id', 'order', 'label', 'action', 'decision', 'outcome', 'section', 'vdom', 'object_type',
            'object', 'fields', 'note', 'error', 'key',
        )
        default_columns = (
            'pk', 'label', 'action', 'decision', 'outcome', 'section', 'vdom', 'object', 'fields', 'note', 'error',
        )
