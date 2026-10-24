from rest_framework import serializers

from dcim.api.serializers import DeviceSerializer, VirtualChassisSerializer
from ipam.api.serializers import RIRSerializer
from netbox.api.fields import ChoiceField, ContentTypeField
from netbox.api.serializers import ValidatedModelSerializer
from netbox.api.serializers.features import ChangeLogMessageSerializer, TaggableModelSerializer

from ..models import (
    ActionChoices, DecisionChoices, FortiGateBinding, ImportRun, OutcomeChoices, PlannedChange, RunStatusChoices,
)


class FortiGateBindingSerializer(TaggableModelSerializer, ChangeLogMessageSerializer, ValidatedModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_fortigate_importer-api:fortigatebinding-detail')
    device = DeviceSerializer(nested=True)
    virtual_chassis = VirtualChassisSerializer(nested=True, required=False, allow_null=True)
    asn_rir = RIRSerializer(nested=True, required=False, allow_null=True)

    class Meta:
        model = FortiGateBinding
        fields = (
            'id', 'url', 'display', 'name', 'device', 'virtual_chassis', 'serial', 'hostname', 'model_code',
            'firmware', 'multi_vdom', 'options', 'asn_rir', 'description', 'comments', 'tags', 'created',
            'last_updated',
        )
        read_only_fields = ('serial', 'hostname', 'model_code', 'firmware', 'multi_vdom')
        brief_fields = ('id', 'url', 'display', 'name', 'description')


class ImportRunSerializer(ValidatedModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:netbox_fortigate_importer-api:importrun-detail')
    binding = FortiGateBindingSerializer(nested=True, read_only=True)
    status = ChoiceField(choices=RunStatusChoices, read_only=True)

    class Meta:
        model = ImportRun
        fields = (
            'id', 'url', 'display', 'binding', 'status', 'created', 'created_by', 'filename', 'file_sha256',
            'data_sha256', 'file_size', 'encrypted', 'info', 'summary', 'options', 'planned', 'applied', 'applied_by',
            'rolled_back', 'apply_request_id', 'rollback_request_id', 'dry_run', 'error',
        )
        read_only_fields = fields
        brief_fields = ('id', 'url', 'display', 'status')


class PlannedChangeSerializer(ValidatedModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_fortigate_importer-api:plannedchange-detail',
    )
    action = ChoiceField(choices=ActionChoices, read_only=True)
    decision = ChoiceField(choices=DecisionChoices)
    outcome = ChoiceField(choices=OutcomeChoices, read_only=True)
    object_type = ContentTypeField(read_only=True)

    class Meta:
        model = PlannedChange
        fields = (
            'id', 'url', 'display', 'run', 'order', 'key', 'section', 'vdom', 'label', 'action', 'object_type',
            'object_id', 'proposed', 'current', 'last_applied', 'diff', 'depends_on', 'note', 'decision',
            'decided_by', 'outcome', 'error', 'change_request_id',
        )
        read_only_fields = tuple(f for f in fields if f != 'decision')
        brief_fields = ('id', 'url', 'display', 'key', 'action', 'decision', 'outcome')


class UploadSerializer(serializers.Serializer):
    file = serializers.FileField()
    password = serializers.CharField(required=False, allow_blank=True, write_only=True, trim_whitespace=False)
    device = serializers.IntegerField(required=False, help_text='Device to import into, when no FortiGate matches.')
