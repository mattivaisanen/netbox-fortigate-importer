"""
The plan: what an import would change in NetBox, item by item.

Every desired object is compared three ways, field by field:

- `want`: what the FortiGate configuration says now,
- `current`: what NetBox has now,
- `last`: what the importer wrote last time (ManagedObject.fields).

  want == current               nothing to do
  current == last, want differs the firewall changed: update
  want == last, current differs someone edited NetBox and the firewall did
                                not change: keep NetBox (shown, not written)
  all three differ              conflict: a person decides

Objects the importer managed that are no longer in the configuration are
deleted, deprecated or released, as the settings say. Reference data
(platform, ASNs, IKE proposals) and objects another FortiGate also manages
are only released.

The plan is saved as PlannedChange rows. Nothing is written to NetBox here.
"""
from __future__ import annotations

from collections import Counter

from django.contrib.contenttypes.models import ContentType
from django.db import models, transaction
from django.utils import timezone

from .jobs import busy
from .mappers import Context, collect
from .mappers.base import Ref, model_field, model_label, normalize, read_field, read_m2m, snapshot, sort_values
from .models import ActionChoices, DecisionChoices, ImportRun, ManagedObject, PlannedChange, RunStatusChoices

#: Key in ManagedObject.fields holding the importer's notes about the object.
META = '@meta'

#: Settings a binding can override for its own imports.
RUN_OPTIONS = (
    'auto_approve_creates', 'vrf_per_vdom', 'create_connected_prefixes', 'config_context',
    'import_tag', 'default_delete_action', 'continue_on_error',
)


class PlanError(Exception):
    pass


def run_options(binding):
    return {key: binding.option(key) for key in RUN_OPTIONS}


def _blank(value):
    return value in (None, '', [], {})


def coerce(model, name, value):
    """A desired value in the form NetBox stores it (None -> '' for text)."""
    if '.' in name or value is not None:
        return value
    try:
        field = model._meta.get_field(name)
    except Exception:
        return value
    if isinstance(field, (models.CharField, models.TextField)) and not field.null:
        return ''
    return value


def _fk_name(model, name):
    """`device` -> `device_id` for foreign keys, so lookups take a pk."""
    if '__' in name:
        return name
    field = model._meta.get_field(name)
    return field.attname if field.is_relation and field.many_to_one else name


def field_default(model, name):
    try:
        field = model._meta.get_field(name.split('.', 1)[0])
    except Exception:
        return None
    if '.' in name or field.is_relation:
        return None
    return normalize(field.get_default())


class Planner:
    def __init__(self, run):
        self.run = run
        self.binding = run.binding
        self.options = run_options(self.binding)
        self.managed = {m.key: m for m in self.binding.managed_objects.select_related('object_type')}
        #: key -> pk of the NetBox object, for the keys that exist already.
        self.resolved = {}
        #: (model label, pk) -> key, to not adopt one object for two keys.
        self.claimed = {}
        self.notes = []

    # Values

    def resolve(self, value):
        """Normalized value with references replaced by pks where known."""
        if isinstance(value, Ref):
            return self.resolved.get(value.key, value.token())
        if isinstance(value, list):
            return [self.resolve(v) for v in value]
        if isinstance(value, dict):
            return {k: self.resolve(v) for k, v in value.items()}
        return normalize(value)

    def wanted(self, desired):
        """(raw, resolved) owned values. Raw keeps references as tokens."""
        raw, resolved = {}, {}
        for name, value in list(desired.fields.items()) + list(desired.deferred.items()):
            value = coerce(desired.model, name, value)
            raw[name] = normalize(value)
            resolved[name] = self.resolve(value)
        for name, values in desired.m2m.items():
            raw[name] = sort_values(normalize(v) for v in values)
            resolved[name] = sort_values(self.resolve(v) for v in values)
        return raw, resolved

    # Finding objects

    def lookup(self, desired):
        if not desired.lookup:
            return None, ''
        query = {}
        for name, value in desired.lookup.items():
            if isinstance(value, Ref):
                if value.key not in self.resolved:
                    # The object it hangs on does not exist yet: neither does this.
                    return None, ''
                value = self.resolved[value.key]
                name = _fk_name(desired.model, name)
            elif isinstance(value, models.Model):
                value = value.pk
                name = _fk_name(desired.model, name)
            elif value is None and '__' not in name:
                name = f'{name}__isnull'
                value = True
            query[name] = value
        found = list(desired.model.objects.filter(**query).order_by('pk')[:2])
        if not found:
            return None, ''
        note = 'NetBox has more than one match; the oldest is used' if len(found) > 1 else ''
        return found[0], note

    def find(self, desired, managed):
        """(object, how, note): how is 'managed', 'adopt', 'gone' or 'new'."""
        if desired.instance is not None:
            obj = desired.model.objects.filter(pk=desired.instance.pk).first()
            if obj is None:
                return None, 'gone', 'the object no longer exists in NetBox'
            return obj, 'managed' if managed else 'adopt', ''
        if managed is not None:
            if managed.object_type.model_class() is desired.model:
                obj = desired.model.objects.filter(pk=managed.object_id).first()
                if obj is not None:
                    return obj, 'managed', ''
            obj, note = self.lookup(desired)
            if obj is not None:
                return obj, 'adopt', 'the object imported last time is gone; a matching one was found'
            return None, 'gone', 'deleted in NetBox since the last import'
        obj, note = self.lookup(desired)
        if obj is not None:
            return obj, 'adopt', note
        return None, 'new', ''

    def other_managers(self, obj):
        ct = ContentType.objects.get_for_model(obj)
        return list(
            ManagedObject.objects.filter(object_type=ct, object_id=obj.pk)
            .exclude(binding=self.binding).select_related('binding')
            .values_list('binding__name', flat=True).distinct()
        )

    # Building the plan

    def build(self, desired_objects):
        rows = []
        order = 0
        wanted_keys = set()
        ordered = sorted(desired_objects, key=lambda d: (d.order, d.key))
        # Find every object first, so references to objects planned later
        # (a device's primary IP) resolve when the values are compared.
        found = [self.find_one(desired) for desired in ordered]
        for desired, located in zip(ordered, found):
            wanted_keys.add(desired.key)
            order += 1
            row = self.plan_one(desired, order, *located)
            if row is not None:
                rows.append(row)
        for key, managed in sorted(self.managed.items()):
            if key in wanted_keys:
                continue
            order += 1
            rows.append(self.plan_removal(managed, order))
        return rows

    def find_one(self, desired):
        """(object, how, notes) for one desired object; records its pk."""
        obj, how, note = self.find(desired, self.managed.get(desired.key))
        notes = [n for n in (desired.note, note) if n]
        if obj is not None:
            claim = (model_label(desired.model), obj.pk)
            if claim in self.claimed and not desired.partial:
                notes.append(f'NetBox object already used for {self.claimed[claim]}; a new one is created')
                obj, how = None, 'new'
            else:
                self.claimed[claim] = desired.key
                self.resolved[desired.key] = obj.pk
        return obj, how, notes

    def plan_one(self, desired, order, obj, how, notes):
        managed = self.managed.get(desired.key)
        note = notes[-1] if notes else ''
        if obj is None and desired.partial:
            self.notes.append(f'{desired.label}: {note or "not found"}, skipped')
            return None

        raw, want = self.wanted(desired)
        create = {}
        if obj is None:
            for name, value in (desired.lookup or {}).items():
                # Many-to-many lookups only find; the m2m values set them.
                if '__' not in name and not model_field(desired.model, name).many_to_many:
                    create[name] = normalize(value)
            for name, value in desired.create_defaults.items():
                create[name] = normalize(value)

        current = snapshot(obj, desired) if obj is not None else {}
        last = None
        if managed is not None and how == 'managed':
            last = {k: v for k, v in (managed.fields or {}).items() if k != META}

        diff = []
        conflict = update = False
        for name, value in want.items():
            if obj is None:
                diff.append({'field': name, 'current': None, 'proposed': value})
                continue
            cur = current.get(name)
            if cur == value:
                continue
            entry = {'field': name, 'current': cur, 'proposed': value}
            if last is None or name not in last:
                entry['last'] = None
                update = True
            else:
                entry['last'] = last[name]
                if cur == last[name]:
                    update = True
                elif value == last[name]:
                    entry['netbox_edited'] = True
                else:
                    entry['conflict'] = True
                    conflict = True
            diff.append(entry)

        others = self.other_managers(obj) if obj is not None else []
        if obj is None:
            action = ActionChoices.CREATE
            auto = self.options['auto_approve_creates'] and how == 'new'
        elif how == 'adopt':
            action = ActionChoices.ADOPT
            fills_blanks = all(
                _blank(d['current']) or d['current'] == field_default(desired.model, d['field'])
                for d in diff
            )
            auto = fills_blanks and (desired.shared or desired.release_only or not others)
        elif conflict:
            action, auto = ActionChoices.CONFLICT, False
        elif update:
            action, auto = ActionChoices.UPDATE, False
        else:
            action, auto = ActionChoices.NOOP, True
        if how == 'gone':
            notes.append('deleted in NetBox since the last import')
        if others and not (desired.shared or desired.release_only):
            notes.append(f'also managed by {", ".join(others)}')

        flags = [f for f in ('shared', 'release_only', 'partial') if getattr(desired, f)]
        return PlannedChange(
            run=self.run, order=order, key=desired.key, section=desired.section, vdom=desired.vdom,
            label=desired.label[:300], action=action,
            object_type=ContentType.objects.get_for_model(desired.model),
            object_id=obj.pk if obj is not None else None,
            proposed={'fields': {k: raw[k] for k in desired.fields},
                      'deferred': {k: raw[k] for k in desired.deferred},
                      'm2m': {k: raw[k] for k in desired.m2m},
                      'create': create, 'flags': flags},
            current=current, last_applied=last or {}, diff=diff, depends_on=desired.refs,
            note='; '.join(dict.fromkeys(notes))[:500],
            decision=DecisionChoices.APPROVED if auto else DecisionChoices.PENDING,
            managed_before=managed.snapshot() if managed is not None else None,
        )

    def plan_removal(self, managed, order):
        meta = (managed.fields or {}).get(META, {})
        flags = meta.get('flags', [])
        model = managed.object_type.model_class()
        obj = model.objects.filter(pk=managed.object_id).first() if model else None
        values = {k: v for k, v in (managed.fields or {}).items() if k != META}
        current = {}
        if obj is not None:
            for name in values:
                try:
                    if model._meta.get_field(name.split('.')[0]).many_to_many:
                        current[name] = read_m2m(obj, name)
                    else:
                        current[name] = read_field(obj, name)
                except Exception:
                    continue
        note = ''
        auto = False
        if obj is None:
            action, auto, note = ActionChoices.UNMANAGE, True, 'already deleted in NetBox'
        elif 'release_only' in flags or 'partial' in flags:
            action, auto, note = ActionChoices.UNMANAGE, True, 'kept in NetBox, no longer managed'
        elif 'shared' in flags and self.other_managers(obj):
            action, auto = ActionChoices.UNMANAGE, True
            note = f'kept: still managed by {", ".join(self.other_managers(obj))}'
        else:
            setting = self.options['default_delete_action']
            if setting == 'unmanage':
                action, auto = ActionChoices.UNMANAGE, True
            elif setting == 'deprecate' and has_deprecated_status(model):
                action = ActionChoices.DEPRECATE
            else:
                action = ActionChoices.DELETE
            note = 'no longer in the configuration'
        return PlannedChange(
            run=self.run, order=order, key=managed.key, section=meta.get('section', ''),
            vdom=meta.get('vdom', ''), label=(meta.get('label') or managed.key)[:300], action=action,
            object_type=managed.object_type, object_id=managed.object_id if obj is not None else None,
            proposed={'flags': flags, 'order': meta.get('order')}, current=current, last_applied=values,
            note=note, decision=DecisionChoices.APPROVED if auto else DecisionChoices.PENDING,
            managed_before=managed.snapshot(),
        )


def has_deprecated_status(model):
    try:
        field = model._meta.get_field('status')
    except Exception:
        return False
    return any(value == 'deprecated' for value, _ in (field.flatchoices or []))


def summarize(run, rows, notes):
    by_action = Counter(row.action for row in rows)
    by_section = {}
    for row in rows:
        by_section.setdefault(row.section or 'other', Counter())[row.action] += 1
    pending = sum(1 for row in rows if row.decision == DecisionChoices.PENDING)
    data = run.data or {}
    return {
        'actions': dict(by_action),
        'sections': {k: dict(v) for k, v in sorted(by_section.items())},
        'pending': pending,
        'notes': notes,
        'warnings': data.get('warnings', []),
        'stats': data.get('stats', {}),
    }


def attach_created_device(binding):
    """
    A FortiGate whose new device was created later than its apply (an
    approval plugin let it through): link that device now.
    """
    if binding.device_id is not None:
        return
    from dcim.models import Device

    managed = binding.managed_objects.filter(key='device').select_related('object_type').first()
    if managed is None or managed.object_type.model_class() is not Device:
        return
    device = Device.objects.filter(pk=managed.object_id).first()
    if device is not None:
        binding.snapshot()
        binding.device = device
        binding.save()


def plan(run: ImportRun):
    """Build (or rebuild) the plan of a run. Returns the saved rows."""
    if run.binding_id is None:
        raise PlanError('Choose the NetBox device this configuration belongs to first.')
    if not run.is_idle or run.status not in (RunStatusChoices.PARSED, RunStatusChoices.PLANNED):
        raise PlanError(f'A run that is "{run.get_status_display()}" cannot be planned again.')
    if busy(run):
        raise PlanError('This run has a job queued or running. Plan again when it has finished.')
    attach_created_device(run.binding)
    planner = Planner(run)
    ctx = Context(binding=run.binding, data=run.data, options=planner.options)
    desired = collect(ctx)
    rows = planner.build(desired)
    notes = ctx.notes + planner.notes
    with transaction.atomic():
        # An apply or rollback holds this lock while it runs; once it is
        # free, the run may have changed.
        locked = ImportRun.objects.select_for_update().get(pk=run.pk)
        if locked.status not in (RunStatusChoices.PARSED, RunStatusChoices.PLANNED) or busy(locked):
            raise PlanError('This run has a job queued or running, or was applied meanwhile; it cannot be '
                            'planned again now.')
        run.changes.all().delete()
        PlannedChange.objects.bulk_create(rows)
        run.options = planner.options
        run.summary = summarize(run, rows, notes)
        run.status = RunStatusChoices.PLANNED
        run.planned = timezone.now()
        run.dry_run = {}
        run.error = ''
        run.save()
    return rows
