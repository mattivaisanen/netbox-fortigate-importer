from django import forms
from django.utils.translation import gettext_lazy as _

from dcim.models import Device, DeviceRole, DeviceType, Site, VirtualChassis
from ipam.models import RIR
from netbox.forms import NetBoxModelFilterSetForm, NetBoxModelForm
from utilities.forms.forms import FilterForm
from utilities.forms.fields import CommentField, DynamicModelChoiceField, TagFilterField
from utilities.forms.rendering import FieldSet

from .models import DecisionChoices, FortiGateBinding, RunStatusChoices

#: Per-firewall overrides of plugin settings shown on the FortiGate form.
OPTION_FIELDS = {
    'auto_approve_creates': _('Approve new objects automatically'),
    'vrf_per_vdom': _('One VRF per VDOM'),
    'create_connected_prefixes': _('Create prefixes for connected networks'),
    'config_context': _('Put system settings in the config context'),
    'continue_on_error': _('Keep going past failed items'),
}
DEFAULT = ''
TRI_STATE = ((DEFAULT, _('Plugin default')), ('true', _('Yes')), ('false', _('No')))
DELETE_ACTIONS = (
    (DEFAULT, _('Plugin default')),
    ('delete', _('Delete (after review)')),
    ('deprecate', _('Mark deprecated (after review)')),
    ('unmanage', _('Keep in NetBox, stop managing')),
)


class FortiGateBindingForm(NetBoxModelForm):
    device = DynamicModelChoiceField(label=_('Device'), queryset=Device.objects.all())
    virtual_chassis = DynamicModelChoiceField(
        label=_('Virtual chassis'), queryset=VirtualChassis.objects.all(), required=False,
    )
    asn_rir = DynamicModelChoiceField(
        label=_('RIR for new ASNs'), queryset=RIR.objects.all(), required=False,
        help_text=_('Private AS numbers go under an RIR "Private" when this is empty.'),
    )
    default_delete_action = forms.ChoiceField(
        label=_('When an object disappears'), choices=DELETE_ACTIONS, required=False,
    )
    comments = CommentField()

    fieldsets = (
        FieldSet('name', 'device', 'virtual_chassis', 'description', 'tags', name=_('FortiGate')),
        FieldSet('asn_rir', 'default_delete_action', *OPTION_FIELDS, name=_('Import options')),
    )

    class Meta:
        model = FortiGateBinding
        fields = ('name', 'device', 'virtual_chassis', 'asn_rir', 'description', 'comments', 'tags')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        options = self.instance.options or {}
        for key, label in OPTION_FIELDS.items():
            self.fields[key] = forms.ChoiceField(label=label, choices=TRI_STATE, required=False)
            if key in options:
                self.initial[key] = 'true' if options[key] else 'false'
        self.initial['default_delete_action'] = options.get('default_delete_action', DEFAULT)

    def clean(self):
        super().clean()
        options = dict(self.instance.options or {})
        for key in OPTION_FIELDS:
            value = self.cleaned_data.get(key)
            if value in ('true', 'false'):
                options[key] = value == 'true'
            else:
                options.pop(key, None)
        action = self.cleaned_data.get('default_delete_action')
        if action:
            options['default_delete_action'] = action
        else:
            options.pop('default_delete_action', None)
        self.instance.options = options
        return self.cleaned_data


class FortiGateBindingFilterForm(NetBoxModelFilterSetForm):
    model = FortiGateBinding
    fieldsets = (
        FieldSet('q', 'filter_id', 'tag'),
        FieldSet('device_id', 'multi_vdom', name=_('FortiGate')),
    )
    device_id = DynamicModelChoiceField(queryset=Device.objects.all(), required=False, label=_('Device'))
    multi_vdom = forms.NullBooleanField(required=False, label=_('Multi-VDOM'),
                                        widget=forms.Select(choices=((None, '---------'), (True, _('Yes')),
                                                                     (False, _('No')))))
    tag = TagFilterField(model)


class ImportRunFilterForm(FilterForm):
    fieldsets = (FieldSet('q', 'status', 'binding_id'),)
    status = forms.MultipleChoiceField(choices=RunStatusChoices, required=False)
    binding_id = DynamicModelChoiceField(queryset=FortiGateBinding.objects.all(), required=False,
                                         label=_('FortiGate'))


class UploadForm(forms.Form):
    file = forms.FileField(label=_('Configuration file'))
    password = forms.CharField(
        label=_('Backup password'), required=False, strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'off'}),
        help_text=_('Only for encrypted backups. Used once to read the file, never saved.'),
    )


class BindForm(forms.Form):
    MODE_EXISTING = 'existing'
    MODE_NEW = 'new'
    mode = forms.ChoiceField(
        choices=((MODE_EXISTING, _('An existing device')), (MODE_NEW, _('A new device'))),
        widget=forms.RadioSelect, initial=MODE_EXISTING, label=_('Import into'),
    )
    device = DynamicModelChoiceField(queryset=Device.objects.all(), required=False, label=_('Device'))
    name = forms.CharField(required=False, label=_('Device name'))
    site = DynamicModelChoiceField(queryset=Site.objects.all(), required=False, label=_('Site'))
    role = DynamicModelChoiceField(queryset=DeviceRole.objects.all(), required=False, label=_('Role'))
    device_type = DynamicModelChoiceField(
        queryset=DeviceType.objects.all(), required=False, label=_('Device type'),
        help_text=_('Empty: a Fortinet device type named after the model is used (created if missing).'),
    )

    def clean(self):
        data = super().clean()
        if data.get('mode') == self.MODE_EXISTING:
            if not data.get('device'):
                self.add_error('device', _('Choose the device.'))
        else:
            for name in ('site', 'role'):
                if not data.get(name):
                    self.add_error(name, _('Required for a new device.'))
        return data


class DecisionForm(forms.Form):
    pk = forms.MultipleChoiceField(required=False)
    decision = forms.ChoiceField(choices=DecisionChoices)
    scope = forms.ChoiceField(choices=(('selected', 'selected'), ('filtered', 'filtered')), initial='selected')

