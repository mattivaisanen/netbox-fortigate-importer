"""
The importer's own records.

None of these models subclass NetBoxModel, on purpose: they are the
importer's bookkeeping, not network objects. Approval plugins such as
netbox-change-approval gate every NetBoxModel, and an import must not need
approval just to record that it ran. The network objects the importer writes
are ordinary NetBox objects and go through NetBox's (and those plugins')
normal checks. See DEVELOPER.md "Working with netbox-change-approval".

- FortiGateBinding: one firewall (device or HA cluster) and its settings.
  Change-logged, so who mapped which device is on record.
- ImportRun: one uploaded configuration, its parsed data, plan and results.
- PlannedChange: one proposed change of a run, with its decision and outcome.
- ManagedObject: which NetBox object the importer manages for which
  FortiGate object, and the field values it last wrote. The basis of the
  three-way delta.
"""
import uuid

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.core.exceptions import ValidationError
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from netbox.models import BaseModel, ChangeLoggedModel
from netbox.models.features import JobsMixin, JournalingMixin, TagsMixin
from utilities.choices import ChoiceSet
from utilities.querysets import RestrictedQuerySet


class RunStatusChoices(ChoiceSet):
    PARSED = 'parsed'
    PLANNING = 'planning'
    PLANNED = 'planned'
    APPLYING = 'applying'
    APPLIED = 'applied'
    PENDING_APPROVAL = 'pending-approval'
    FAILED = 'failed'
    ROLLING_BACK = 'rolling-back'
    ROLLED_BACK = 'rolled-back'
    DISCARDED = 'discarded'
    SUPERSEDED = 'superseded'

    CHOICES = (
        (PARSED, _('Parsed'), 'cyan'),
        (PLANNING, _('Planning'), 'blue'),
        (PLANNED, _('Ready for review'), 'yellow'),
        (APPLYING, _('Applying'), 'blue'),
        (APPLIED, _('Applied'), 'green'),
        (PENDING_APPROVAL, _('Waiting for approval'), 'orange'),
        (FAILED, _('Failed'), 'red'),
        (ROLLING_BACK, _('Rolling back'), 'blue'),
        (ROLLED_BACK, _('Rolled back'), 'gray'),
        (DISCARDED, _('Discarded'), 'gray'),
        (SUPERSEDED, _('Superseded'), 'gray'),
    )

    #: A run in one of these may still be applied.
    APPLICABLE = (PLANNED,)
    #: A run in one of these has nothing running in the background.
    IDLE = (PARSED, PLANNED, APPLIED, PENDING_APPROVAL, FAILED, ROLLED_BACK, DISCARDED, SUPERSEDED)


class ActionChoices(ChoiceSet):
    CREATE = 'create'
    UPDATE = 'update'
    ADOPT = 'adopt'
    DELETE = 'delete'
    UNMANAGE = 'unmanage'
    DEPRECATE = 'deprecate'
    CONFLICT = 'conflict'
    NOOP = 'noop'

    CHOICES = (
        (CREATE, _('Create'), 'green'),
        (UPDATE, _('Update'), 'blue'),
        (ADOPT, _('Adopt'), 'cyan'),
        (DELETE, _('Delete'), 'red'),
        (UNMANAGE, _('Stop managing'), 'gray'),
        (DEPRECATE, _('Deprecate'), 'orange'),
        (CONFLICT, _('Conflict'), 'purple'),
        (NOOP, _('No change'), 'gray'),
    )

    #: Actions that write to NetBox.
    WRITES = (CREATE, UPDATE, ADOPT, DELETE, DEPRECATE, CONFLICT)


class DecisionChoices(ChoiceSet):
    PENDING = 'pending'
    APPROVED = 'approved'
    SKIPPED = 'skipped'
    #: Conflicts only: keep what NetBox has, accept it as the new baseline.
    KEEP_NETBOX = 'keep-netbox'

    CHOICES = (
        (PENDING, _('Needs review'), 'yellow'),
        (APPROVED, _('Approved'), 'green'),
        (SKIPPED, _('Skipped'), 'gray'),
        (KEEP_NETBOX, _('Keep NetBox'), 'cyan'),
    )


class OutcomeChoices(ChoiceSet):
    NONE = ''
    APPLIED = 'applied'
    FAILED = 'failed'
    SKIPPED = 'skipped'
    SUBMITTED = 'submitted'
    BLOCKED = 'blocked'
    REJECTED = 'rejected'
    ROLLED_BACK = 'rolled-back'

    CHOICES = (
        (NONE, _('Not applied'), 'gray'),
        (APPLIED, _('Applied'), 'green'),
        (FAILED, _('Failed'), 'red'),
        (SKIPPED, _('Skipped'), 'gray'),
        (SUBMITTED, _('Waiting for approval'), 'orange'),
        (BLOCKED, _('Blocked by a pending change'), 'purple'),
        (REJECTED, _('Rejected by approver'), 'red'),
        (ROLLED_BACK, _('Rolled back'), 'gray'),
    )


class FortiGateBinding(JournalingMixin, TagsMixin, ChangeLoggedModel):
    """
    One FortiGate (a single unit or an HA cluster) and the NetBox device it
    is imported into. Later imports of the same firewall reuse the binding.
    """
    name = models.CharField(verbose_name=_('name'), max_length=100, unique=True)
    device = models.ForeignKey(
        to='dcim.Device', on_delete=models.PROTECT, related_name='fortigate_bindings',
        null=True, blank=True, verbose_name=_('device'),
        help_text=_('Empty until the first apply creates the new device.'),
    )
    #: For a firewall that is not in NetBox yet: how to create its device
    #: ({'name', 'site', 'role', 'device_type'}, pks). The device is a planned
    #: change like any other, written only when an import is applied.
    new_device = models.JSONField(verbose_name=_('new device'), default=dict, blank=True)
    virtual_chassis = models.ForeignKey(
        to='dcim.VirtualChassis', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='fortigate_bindings', verbose_name=_('virtual chassis'),
        help_text=_('HA cluster this firewall belongs to.'),
    )
    serial = models.CharField(verbose_name=_('serial number'), max_length=50, blank=True)
    hostname = models.CharField(verbose_name=_('hostname'), max_length=100, blank=True)
    model_code = models.CharField(verbose_name=_('model'), max_length=50, blank=True)
    firmware = models.CharField(verbose_name=_('firmware'), max_length=50, blank=True)
    multi_vdom = models.BooleanField(verbose_name=_('multi-VDOM'), default=False)
    #: Per-firewall overrides of the plugin settings (vrf_per_vdom, ...).
    options = models.JSONField(verbose_name=_('options'), default=dict, blank=True)
    asn_rir = models.ForeignKey(
        to='ipam.RIR', on_delete=models.SET_NULL, null=True, blank=True, related_name='+',
        verbose_name=_('RIR for new ASNs'),
        help_text=_('RIR to file BGP AS numbers under when the importer creates them.'),
    )
    description = models.CharField(verbose_name=_('description'), max_length=200, blank=True)
    comments = models.TextField(verbose_name=_('comments'), blank=True)

    class Meta:
        ordering = ('name',)
        verbose_name = _('FortiGate')
        verbose_name_plural = _('FortiGates')

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('plugins:netbox_fortigate_importer:fortigatebinding', args=[self.pk])

    def clean(self):
        super().clean()
        if self.device_id is None and not self.new_device:
            raise ValidationError({'device': _('Choose the device.')})

    def option(self, key):
        """A per-firewall option, falling back to the plugin setting."""
        from .settings import get_setting

        if key in (self.options or {}):
            return self.options[key]
        return get_setting(key)

    @property
    def last_run(self):
        return self.runs.exclude(status=RunStatusChoices.DISCARDED).order_by('-created').first()


class ImportRun(JobsMixin, BaseModel):
    """
    One uploaded configuration. Holds the importer's data extracted from the
    file (never the file itself), the plan built from it and what happened.
    """
    binding = models.ForeignKey(
        to=FortiGateBinding, on_delete=models.CASCADE, null=True, blank=True,
        related_name='runs', verbose_name=_('FortiGate'),
    )
    status = models.CharField(
        verbose_name=_('status'), max_length=30, choices=RunStatusChoices, default=RunStatusChoices.PARSED,
    )
    created = models.DateTimeField(verbose_name=_('created'), auto_now_add=True)
    created_by = models.ForeignKey(
        to=settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='+', verbose_name=_('uploaded by'),
    )
    filename = models.CharField(verbose_name=_('file name'), max_length=255, blank=True)
    file_sha256 = models.CharField(verbose_name=_('SHA-256 of the file'), max_length=64, blank=True)
    file_size = models.PositiveBigIntegerField(verbose_name=_('file size'), default=0)
    #: SHA-256 of the extracted data: the same for the same configuration,
    #: plain or encrypted (compare.content_hash).
    data_sha256 = models.CharField(verbose_name=_('SHA-256 of the configuration'), max_length=64, blank=True)
    encrypted = models.BooleanField(verbose_name=_('encrypted'), default=False)
    #: Header facts (model, firmware, hostname, serial, VDOM mode).
    info = models.JSONField(verbose_name=_('configuration info'), default=dict, blank=True)
    #: The importer's data extracted from the file. The only copy kept.
    data = models.JSONField(verbose_name=_('extracted data'), default=dict, blank=True)
    #: Counts per section/model/action, warnings, skipped sections.
    summary = models.JSONField(verbose_name=_('summary'), default=dict, blank=True)
    #: The settings the plan was made with.
    options = models.JSONField(verbose_name=_('options'), default=dict, blank=True)
    planned = models.DateTimeField(verbose_name=_('planned'), null=True, blank=True)
    applied = models.DateTimeField(verbose_name=_('applied'), null=True, blank=True)
    applied_by = models.ForeignKey(
        to=settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='+', verbose_name=_('applied by'),
    )
    rolled_back = models.DateTimeField(verbose_name=_('rolled back'), null=True, blank=True)
    #: request_id of the NetBox change log entries written by the apply.
    apply_request_id = models.UUIDField(verbose_name=_('change log request ID'), null=True, blank=True)
    rollback_request_id = models.UUIDField(verbose_name=_('rollback request ID'), null=True, blank=True)
    #: Last dry run: per-item outcome and counts.
    dry_run = models.JSONField(verbose_name=_('dry run result'), default=dict, blank=True)
    error = models.TextField(verbose_name=_('error'), blank=True)
    #: netbox-change-approval change set holding this run's requests, if any.
    change_set_id = models.PositiveBigIntegerField(null=True, blank=True)

    class Meta:
        ordering = ('-created',)
        verbose_name = _('import run')
        verbose_name_plural = _('import runs')
        permissions = (
            ('apply_importrun', 'Can apply import runs'),
            ('rollback_importrun', 'Can roll back import runs'),
        )

    def __str__(self):
        name = self.binding.name if self.binding_id else (self.info.get('hostname') or self.filename)
        return f'{name} #{self.pk}'

    def get_absolute_url(self):
        return reverse('plugins:netbox_fortigate_importer:importrun', args=[self.pk])

    def get_status_color(self):
        return RunStatusChoices.colors.get(self.status)

    @property
    def is_idle(self):
        return self.status in RunStatusChoices.IDLE

    @property
    def can_apply(self):
        return self.status in RunStatusChoices.APPLICABLE and self.binding_id is not None

    @property
    def can_rollback(self):
        return self.status in (RunStatusChoices.APPLIED, RunStatusChoices.PENDING_APPROVAL) \
            and self.apply_request_id is not None

    def new_request_id(self):
        self.apply_request_id = uuid.uuid4()
        return self.apply_request_id


class PlannedChange(models.Model):
    """One proposed change of an import run."""
    run = models.ForeignKey(to=ImportRun, on_delete=models.CASCADE, related_name='changes')
    order = models.PositiveIntegerField(default=0)
    #: Stable FortiGate-side identity, e.g. "root/interface/vlan10".
    key = models.CharField(max_length=500)
    section = models.CharField(max_length=50)
    vdom = models.CharField(max_length=50, blank=True)
    label = models.CharField(max_length=300, blank=True)
    action = models.CharField(max_length=20, choices=ActionChoices)
    object_type = models.ForeignKey(to='contenttypes.ContentType', on_delete=models.CASCADE, related_name='+')
    object_id = models.PositiveBigIntegerField(null=True, blank=True)
    object = GenericForeignKey('object_type', 'object_id')
    #: What NetBox should have, field by field (references by key).
    proposed = models.JSONField(default=dict, blank=True)
    #: What NetBox has now (owned fields only).
    current = models.JSONField(default=dict, blank=True)
    #: What the importer wrote last time (owned fields only).
    last_applied = models.JSONField(default=dict, blank=True)
    #: [{"field", "current", "proposed", "last", "netbox_edited"}]
    diff = models.JSONField(default=list, blank=True)
    #: Keys this change needs first.
    depends_on = models.JSONField(default=list, blank=True)
    note = models.CharField(max_length=500, blank=True)
    decision = models.CharField(max_length=20, choices=DecisionChoices, default=DecisionChoices.PENDING)
    decided_by = models.ForeignKey(
        to=settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+',
    )
    outcome = models.CharField(max_length=20, choices=OutcomeChoices, default=OutcomeChoices.NONE, blank=True)
    error = models.TextField(blank=True)
    #: The ManagedObject row as it was before apply, for rollback.
    managed_before = models.JSONField(null=True, blank=True)
    #: netbox-change-approval request created for this change, if any.
    change_request_id = models.PositiveBigIntegerField(null=True, blank=True)

    objects = RestrictedQuerySet.as_manager()

    class Meta:
        ordering = ('run', 'order', 'pk')
        verbose_name = _('planned change')
        verbose_name_plural = _('planned changes')
        constraints = (
            models.UniqueConstraint(fields=('run', 'key'), name='nbfgi_unique_change_key_per_run'),
        )
        indexes = (
            models.Index(fields=('run', 'action')),
            models.Index(fields=('run', 'decision')),
        )

    def __str__(self):
        return f'{self.get_action_display()} {self.label or self.key}'

    def get_absolute_url(self):
        return reverse('plugins:netbox_fortigate_importer:plannedchange', args=[self.pk])

    def get_action_color(self):
        return ActionChoices.colors.get(self.action)

    def get_decision_color(self):
        return DecisionChoices.colors.get(self.decision)

    def get_outcome_color(self):
        return OutcomeChoices.colors.get(self.outcome)

    @property
    def writes(self):
        return self.action in ActionChoices.WRITES

    @property
    def will_apply(self):
        return self.writes and self.decision == DecisionChoices.APPROVED

    def clean(self):
        super().clean()
        if self.decision == DecisionChoices.KEEP_NETBOX and self.action != ActionChoices.CONFLICT:
            raise ValidationError({'decision': _('"Keep NetBox" only applies to conflicts.')})


class ManagedObject(models.Model):
    """
    A NetBox object the importer manages for one FortiGate object. `fields`
    holds the owned field values as the importer last wrote them.
    """
    binding = models.ForeignKey(to=FortiGateBinding, on_delete=models.CASCADE, related_name='managed_objects')
    key = models.CharField(max_length=500)
    object_type = models.ForeignKey(to='contenttypes.ContentType', on_delete=models.CASCADE, related_name='+')
    object_id = models.PositiveBigIntegerField()
    object = GenericForeignKey('object_type', 'object_id')
    fields = models.JSONField(default=dict, blank=True)
    first_run = models.ForeignKey(to=ImportRun, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    last_run = models.ForeignKey(to=ImportRun, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    #: False while the object waits for approval (netbox-change-approval).
    confirmed = models.BooleanField(default=True)
    updated = models.DateTimeField(auto_now=True)

    objects = RestrictedQuerySet.as_manager()

    class Meta:
        ordering = ('binding', 'key')
        verbose_name = _('managed object')
        verbose_name_plural = _('managed objects')
        constraints = (
            models.UniqueConstraint(fields=('binding', 'key'), name='nbfgi_unique_managed_key'),
        )
        indexes = (
            models.Index(fields=('object_type', 'object_id')),
        )

    def __str__(self):
        return self.key

    def snapshot(self):
        """This row as JSON, for PlannedChange.managed_before."""
        return {
            'pk': self.pk, 'object_type': self.object_type_id, 'object_id': self.object_id,
            'fields': self.fields, 'confirmed': self.confirmed,
            'first_run': self.first_run_id, 'last_run': self.last_run_id,
        }
