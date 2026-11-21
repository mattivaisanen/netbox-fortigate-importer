"""
Applying a plan: writing the approved changes to NetBox.

- One NetBox request ID for the whole apply, so the change log groups it
  and rollback can find every change.
- Runs as the user who applied it (change log, permissions of approval
  plugins), through NetBox's request processors like a script job.
- Each item is written in its own savepoint with full_clean() + save(), so
  one failure is reported with all the others. By default any failure rolls
  the whole apply back; with `continue_on_error` the rest is kept.
- Before writing, every object is checked against the plan: if someone
  changed it since the plan was made, the item fails ("plan again").
- A dry run does all of the above and rolls everything back.

Order: removals first (most dependent objects first), then creates and
updates in plan order, then the deferred fields (primary IPs, virtual
chassis master) once every object exists.
"""
from __future__ import annotations

import copy
import logging
import uuid
from contextlib import nullcontext

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from . import integrations, journal
from .mappers.base import Ref, is_ref_token, read_field, read_m2m, ref_key, sort_values, unescape_literal, write_field
from .models import (
    ActionChoices,
    DecisionChoices,
    ImportRun,
    ManagedObject,
    OutcomeChoices,
    PlannedChange,
    RunStatusChoices,
)
from .planner import META

logger = logging.getLogger('netbox_fortigate_importer.apply')

REMOVALS = (ActionChoices.DELETE, ActionChoices.UNMANAGE, ActionChoices.DEPRECATE)


class ApplyError(Exception):
    pass


class _Rollback(Exception):
    """Raised inside the transaction to undo a dry run or a failed apply."""


class Unresolved(Exception):
    pass


class Drift(Exception):
    pass


class Submitted(Exception):
    """An item queued for approval (or blocked) instead of written."""

    def __init__(self, approval_exc):
        self.approval_exc = approval_exc
        super().__init__('queued for approval')


def error_text(exc):
    if isinstance(exc, ValidationError):
        if hasattr(exc, 'message_dict'):
            return '; '.join(f'{k}: {" ".join(v)}' if k != '__all__' else ' '.join(v)
                             for k, v in exc.message_dict.items())
        return ' '.join(exc.messages)
    return str(exc) or exc.__class__.__name__


def may(user, obj, action):
    """
    True if `user` may `action` ("add", "change", "delete") `obj`, with
    NetBox's object permissions and their constraints, like a form would.
    For an unsaved object only the model permission is checked; constraints
    are checked once it is saved.
    """
    if user is None:
        return False
    model = type(obj)
    if not user.has_perm(f'{model._meta.app_label}.{action}_{model._meta.model_name}'):
        return False
    if obj.pk is None or user.is_superuser:
        return True
    queryset = model._default_manager.all()
    if not hasattr(queryset, 'restrict'):
        return True  # no object constraints for this model
    return queryset.restrict(user, action).filter(pk=obj.pk).exists()


def require(user, obj, action):
    if not may(user, obj, action):
        try:
            label = f' {obj}' if obj.pk else ''
        except Exception:  # noqa: BLE001 - only for the message
            label = ''
        raise PermissionDenied(f'{getattr(user, "username", "nobody")} may not {action} '
                               f'{obj._meta.verbose_name}{label}')


#: Rows that go with an object and are no work of their own.
_CASCADE_IGNORED = {('extras', 'taggeditem'), ('extras', 'cachedvalue'), ('extras', 'bookmark'),
                    ('extras', 'subscription')}


def cascade_victims(obj, allowed=frozenset(), owned=frozenset()):
    """
    What deleting `obj` would also delete (database cascades and NetBox's
    generic relations) or change (references set to null), apart from
    `allowed` ((content type pk, pk) pairs). References on `owned` objects
    (this FortiGate's, whose fields the plan writes) may be cleared.
    Returns labels such as "IP address 10.0.0.1/24", at most 20.
    """
    from django.contrib.contenttypes.models import ContentType
    from django.db.models.deletion import Collector

    collector = Collector(using=obj._state.db or 'default')
    collector.collect([obj])
    found = []

    def consider(instance):
        meta = instance._meta
        if meta.auto_created or (meta.app_label, meta.model_name) in _CASCADE_IGNORED:
            return
        if type(instance) is type(obj) and instance.pk == obj.pk:
            return
        if (ContentType.objects.get_for_model(instance).pk, instance.pk) in allowed:
            return
        found.append(f'{meta.verbose_name} {instance}')

    for model, instances in collector.data.items():
        for instance in instances:
            consider(instance)
    for queryset in collector.fast_deletes:
        meta = queryset.model._meta
        if meta.auto_created or (meta.app_label, meta.model_name) in _CASCADE_IGNORED:
            continue
        for instance in queryset[:50]:
            consider(instance)
    # SET_NULL: objects that would only lose their reference (a switch port's
    # untagged VLAN, another device's primary IP) are changed too.
    deleted = {(type(i), i.pk) for instances in collector.data.values() for i in instances}
    for (field, _), batches in collector.field_updates.items():
        for batch in batches:
            for instance in list(batch)[:50]:
                pair = (ContentType.objects.get_for_model(instance).pk, instance.pk)
                if (type(instance), instance.pk) in deleted or pair in allowed or pair in owned:
                    continue
                found.append(f'{field.verbose_name} of {instance._meta.verbose_name} {instance}')
    return found[:20]


def fake_request(user, request_id):
    from utilities.request import NetBoxFakeRequest

    return NetBoxFakeRequest({
        'META': {}, 'COOKIES': {}, 'POST': {}, 'GET': {}, 'FILES': {},
        'user': user, 'method': 'POST', 'path': '', 'path_info': '', 'id': request_id,
    })


class Applier:
    def __init__(self, run: ImportRun, user, dry_run=False, expected_plan=None):
        self.run = run
        self.user = user
        self.dry_run = dry_run
        #: When the plan the user asked to apply was made (ISO time), if known.
        self.expected_plan = expected_plan
        self.binding = run.binding
        self.load()
        self.results = {}
        self.message = f'FortiGate import: {run}'
        self.tag = None
        self.gate = None
        #: (content type, pk) of the objects this apply deletes.
        self.removing = set()
        #: Keys whose object was written but whose deferred fields failed.
        self.deferred_failed = set()
        #: Keys of the objects this apply created.
        self.created = set()
        #: Keys of planned creates that matched an object NetBox made during this apply.
        self.matched = set()

    def load(self):
        self.options = self.run.options or {}
        self.rows = list(self.run.changes.select_related('object_type').order_by('order', 'pk'))
        #: key -> pk, for resolving references.
        self.keys = {row.key: row.object_id for row in self.rows if row.object_id}

    # Checks

    def lock(self):
        """
        Inside the transaction: lock the run and its FortiGate, so a re-plan,
        a decision or another apply or rollback of the same FortiGate waits
        for this one, then read the run and its plan afresh.
        """
        from .models import FortiGateBinding

        if self.run.binding_id is not None:
            list(FortiGateBinding.objects.select_for_update().filter(pk=self.run.binding_id).values_list('pk'))
        self.run = ImportRun.objects.select_for_update().get(pk=self.run.pk)
        self.binding = self.run.binding
        self.load()

    def check(self):
        run = self.run
        if self.expected_plan and (run.planned is None or run.planned.isoformat() != self.expected_plan):
            raise ApplyError('The plan was made again after this was requested. Review it and apply again.')
        if run.binding_id is None:
            raise ApplyError('The run is not linked to a FortiGate.')
        if run.status not in RunStatusChoices.APPLICABLE:
            raise ApplyError(f'A run that is "{run.get_status_display()}" cannot be applied.')
        later = ImportRun.objects.filter(
            binding=run.binding, applied__isnull=False, applied__gt=run.planned or run.created,
        ).exclude(pk=run.pk)
        if later.exists():
            raise ApplyError('Another import of this FortiGate was applied after this plan was made. Plan again.')

    # Values

    def resolve(self, value):
        if is_ref_token(value):
            key = ref_key(value)
            pk = self.keys.get(key)
            if pk is None:
                raise Unresolved(key)
            return pk
        if isinstance(value, list):
            return [self.resolve(v) for v in value]
        if isinstance(value, dict):
            return {k: self.resolve(v) for k, v in value.items()}
        return unescape_literal(value)

    def baseline(self, row, deferred_written=True):
        """
        The owned values as written, for ManagedObject.fields. Deferred
        fields that were not written (the item waits for approval, or the
        deferred pass failed) keep their earlier baseline, or none, so the
        next plan proposes them again.
        """
        values = {}
        proposed = row.proposed or {}
        for name, value in proposed.get('fields', {}).items():
            values[name] = self.resolve(value)
        earlier = ((row.managed_before or {}).get('fields') or {})
        for name, value in proposed.get('deferred', {}).items():
            if deferred_written:
                values[name] = self.resolve(value)
            elif name in earlier:
                values[name] = earlier[name]
        for name, value in proposed.get('m2m', {}).items():
            values[name] = sort_values(self.resolve(value))
        earlier_meta = earlier.get(META) or {}
        values[META] = {
            'label': row.label, 'section': row.section, 'vdom': row.vdom, 'order': row.order,
            'flags': proposed.get('flags', []), 'model': row.object_type.natural_key(),
            # Made by someone else first: a removal only stops managing it.
            'adopted': (row.action == ActionChoices.ADOPT or row.key in self.matched
                        or 'adopted' in proposed.get('flags', []) or bool(earlier_meta.get('adopted'))),
        }
        return values

    def fields_to_write(self, row):
        """Owned fields this row writes (all for a create)."""
        proposed = row.proposed or {}
        if row.object_id is None:
            return set(proposed.get('fields', {})) | set(proposed.get('deferred', {})) | set(proposed.get('m2m', {}))
        names = set()
        for entry in row.diff:
            if entry.get('netbox_edited'):
                continue
            if entry.get('conflict') and row.decision == DecisionChoices.KEEP_NETBOX:
                continue
            names.add(entry['field'])
        return names

    # Writing one object

    def check_drift(self, row, obj):
        model = row.object_type.model_class()
        for name, planned in (row.current or {}).items():
            try:
                field = model._meta.get_field(name.split('.')[0])
            except Exception:
                continue
            now = read_m2m(obj, name) if field.many_to_many else read_field(obj, name)
            if now != planned:
                raise Drift(f'{name} changed in NetBox after the plan was made; plan again')

    def save(self, obj, action):
        """
        full_clean() and save(), like a form, as the applying user: their
        NetBox permissions (and constraints, such as "only these sites")
        apply before and after the write.
        """
        obj._changelog_message = self.message
        require(self.user, obj, action)
        obj.full_clean()
        obj.save()
        require(self.user, obj, action)

    def write(self, row, deferred=False):
        model = row.object_type.model_class()
        proposed = row.proposed or {}
        names = self.fields_to_write(row)
        deferred_names = set(proposed.get('deferred', {}))
        if deferred:
            names &= deferred_names
            if not names:
                return
            obj = model.objects.get(pk=self.keys[row.key])
            obj.snapshot()
            for name in names:
                write_field(obj, name, self.resolve(proposed['deferred'][name]))
            self.save(obj, 'change')
            return

        names -= deferred_names
        created = row.object_id is None
        obj = self.made_by_netbox(row, model) if created else None
        if obj is not None:
            # NetBox made it while this apply ran (a new device gets the
            # interfaces of its device type): update it instead.
            created = False
            require(self.user, obj, 'change')
            obj.snapshot()
            self.keys[row.key] = obj.pk
            self.matched.add(row.key)
        elif created:
            obj = model()
            for name, value in proposed.get('create', {}).items():
                write_field(obj, name, self.resolve(value))
        else:
            obj = model.objects.filter(pk=row.object_id).first()
            if obj is None:
                raise Drift('the object was deleted in NetBox after the plan was made; plan again')
            self.check_drift(row, obj)
            require(self.user, obj, 'change')
            obj.snapshot()
        m2m = {}
        for name in names:
            if name in proposed.get('m2m', {}):
                m2m[name] = self.resolve(proposed['m2m'][name])
            else:
                write_field(obj, name, self.resolve(proposed['fields'][name]))
        action = 'add' if created else 'change'
        if created or names:
            # Also for many-to-many only changes, like a form: full_clean(),
            # the change log message, then the relations.
            self.save(obj, action)
        for name, pks in m2m.items():
            getattr(obj, name).set(pks)
        if m2m:
            require(self.user, obj, action)
        if created:
            self.keys[row.key] = obj.pk
            self.created.add(row.key)
        if created or row.key in self.matched:
            if self.tag is not None and hasattr(obj, 'tags'):
                obj.tags.add(self.tag)
        if row.key == 'device' and self.binding.device_id != obj.pk:
            # Created, or a new device's name and site found in NetBox.
            self.attach_device(obj)
        return obj

    def made_by_netbox(self, row, model):
        """
        The object a planned create would duplicate, if NetBox made it during
        this apply: the interfaces (and other components) NetBox adds from
        the device type when this apply creates the device.
        """
        if 'device' not in self.created:
            return None
        proposed = row.proposed or {}
        names = proposed.get('lookup') or []
        create = proposed.get('create', {})
        if create.get('device') != Ref('device').token() or 'device' not in names:
            return None
        query = {}
        for name in names:
            value = self.resolve(create[name])
            field = model._meta.get_field(name)
            query[field.attname if field.is_relation and field.many_to_one else name] = value
        return model.objects.filter(**query).order_by('pk').first()

    def attach_device(self, device):
        """Link the FortiGate to the device this apply created."""
        from .models import FortiGateBinding

        # A fresh copy: a dry run (or a failed item) rolls this back in the
        # database, and the run's own binding must not keep the device.
        binding = FortiGateBinding.objects.get(pk=self.binding.pk)
        binding.snapshot()
        binding.device = device
        binding._changelog_message = self.message
        binding.full_clean()
        binding.save()

    def remove(self, row):
        model = row.object_type.model_class()
        obj = model.objects.filter(pk=row.object_id).first() if row.object_id else None
        if row.action == ActionChoices.UNMANAGE or obj is None:
            return
        self.check_drift(row, obj)
        if row.action == ActionChoices.DEPRECATE:
            obj.snapshot()
            obj.status = 'deprecated'
            self.save(obj, 'change')
        else:
            require(self.user, obj, 'delete')
            owned = set(ManagedObject.objects.filter(binding=self.binding).values_list('object_type_id', 'object_id'))
            victims = cascade_victims(obj, self.removing, owned)
            if victims:
                raise ApplyError('deleting it would also delete ' + ', '.join(victims) +
                                 '; remove or move those first, or choose "stop managing"')
            obj.snapshot()
            obj._changelog_message = self.message
            obj.delete()
        self.keys.pop(row.key, None)

    # Bookkeeping

    def record(self, row, outcome, error=''):
        self.results[row.key] = {'outcome': outcome, 'error': error}

    def managed_after(self, row, outcome, deferred_written=True):
        """Update the ManagedObject of a row that was written (or queued)."""
        confirmed = outcome == OutcomeChoices.APPLIED
        if row.action in REMOVALS:
            if confirmed or row.action == ActionChoices.UNMANAGE:
                ManagedObject.objects.filter(binding=self.binding, key=row.key).delete()
            return
        pk = self.keys.get(row.key)
        if pk is None:
            return
        ManagedObject.objects.update_or_create(
            binding=self.binding, key=row.key,
            defaults={
                'object_type': row.object_type, 'object_id': pk, 'fields': self.baseline(row, deferred_written),
                'last_run': self.run, 'confirmed': confirmed,
            },
            create_defaults={
                'object_type': row.object_type, 'object_id': pk, 'fields': self.baseline(row, deferred_written),
                'first_run': self.run, 'last_run': self.run, 'confirmed': confirmed,
            },
        )

    def import_tag(self):
        from django.utils.text import slugify

        from extras.models import Tag

        name = self.options.get('import_tag')
        if not name:
            return None
        tag = Tag.objects.filter(slug=slugify(name)).first()
        if tag is None:
            tag = Tag(name=name, slug=slugify(name), color='e04e39',
                      description='Created by the FortiGate importer')
            self.save(tag, 'add')
        return tag

    # The loop

    def item(self, row, func, record=True):
        """
        Run func(row) in a savepoint. Records and returns the outcome: applied,
        submitted or blocked (change approval), skipped or failed.
        """
        from netbox.context import events_queue

        queue = events_queue.get()
        before = self._copy_queue(queue)
        sid = transaction.savepoint()
        try:
            with self.gate.item(row) if self.gate else nullcontext():
                func(row)
        except Submitted as exc:
            transaction.savepoint_rollback(sid)
            self._restore(queue, before)
            self.gate.record(row, exc)
            return self.gated(row)
        except Unresolved as exc:
            transaction.savepoint_rollback(sid)
            self._restore(queue, before)
            self.record(row, OutcomeChoices.SKIPPED, self.unresolved_text(str(exc)))
            return OutcomeChoices.SKIPPED
        except Exception as exc:  # noqa: BLE001 - every failure is reported on its item
            transaction.savepoint_rollback(sid)
            self._restore(queue, before)
            logger.debug('Item %s failed', row.key, exc_info=True)
            self.record(row, OutcomeChoices.FAILED, error_text(exc))
            return OutcomeChoices.FAILED
        transaction.savepoint_commit(sid)
        outcome = self.gated(row) if self.gate else None
        if outcome is None:
            outcome = OutcomeChoices.APPLIED
            if record:
                self.record(row, outcome)
        return outcome

    def gated(self, row):
        """The change-approval outcome of a row, recorded, or None."""
        found = self.gate.outcome(row) if self.gate else None
        if found is None:
            return None
        outcome, change_request_id = found
        self.record(row, outcome)
        self.results[row.key]['change_request'] = change_request_id
        return outcome

    def unresolved_text(self, key):
        """Why an item could not be written: the change it needs, by name, and what became of it."""
        needed = next((r for r in self.rows if r.key == key), None)
        if needed is None:
            return f'needs "{key}", which is not in this plan'
        result = self.results.get(key, {})
        if needed.decision == DecisionChoices.PENDING:
            why = 'it is not reviewed yet: approve it too'
        elif needed.decision == DecisionChoices.SKIPPED:
            why = 'it is skipped: approve it too'
        elif result.get('outcome') == OutcomeChoices.FAILED:
            why = f'it failed: {result.get("error")}'
        elif result.get('outcome') == OutcomeChoices.SKIPPED:
            why = 'it was skipped'
        else:
            why = 'it was not written'
        return f'needs "{needed.label}", but {why}'

    @staticmethod
    def _copy_queue(queue):
        # Two levels deep is enough: NetBox only replaces an event's fields
        # and its snapshots. A full deepcopy made applies three times slower.
        copied = {}
        for key, event in (queue or {}).items():
            event = copy.copy(event)
            if isinstance(event.get('snapshots'), dict):
                event['snapshots'] = dict(event['snapshots'])
            copied[key] = event
        return copied

    @staticmethod
    def _restore(queue, before):
        if queue is not None:
            queue.clear()
            queue.update(before)

    def write_all(self):
        try:
            self.tag = self.import_tag()
        except Exception as exc:  # noqa: BLE001
            raise ApplyError(f'Could not create the import tag: {error_text(exc)}')

        todo = []
        for row in self.rows:
            if row.action == ActionChoices.NOOP or row.decision == DecisionChoices.APPROVED:
                todo.append(row)
            elif row.decision == DecisionChoices.KEEP_NETBOX and row.action == ActionChoices.CONFLICT:
                todo.append(row)
            else:
                reason = 'not reviewed' if row.decision == DecisionChoices.PENDING else ''
                self.record(row, OutcomeChoices.SKIPPED, reason)

        removals = [r for r in todo if r.action in REMOVALS]
        self.removing = {(r.object_type_id, r.object_id) for r in removals if r.action == ActionChoices.DELETE}
        removals.sort(key=lambda r: -((r.proposed or {}).get('order') or r.order))
        writes = [r for r in todo if r.action not in REMOVALS]

        for row in removals:
            self.item(row, self.remove)
        for row in writes:
            if row.action == ActionChoices.NOOP:
                self.record(row, OutcomeChoices.APPLIED)
                continue
            self.item(row, self.write)
        for row in writes:
            outcome = self.results[row.key]['outcome']
            if outcome not in (OutcomeChoices.APPLIED, OutcomeChoices.SUBMITTED) or row.key not in self.keys:
                continue
            if (row.proposed or {}).get('deferred') and outcome == OutcomeChoices.APPLIED:
                deferred = self.item(row, lambda r: self.write(r, deferred=True), record=False)
                if deferred != OutcomeChoices.APPLIED:
                    self.deferred_failed.add(row.key)
                    self.deferred_outcome(row, deferred)
        for row in todo:
            outcome = self.results[row.key]['outcome']
            if row.key in self.deferred_failed:
                # The object itself was written and is kept (continue_on_error).
                self.managed_after(row, OutcomeChoices.APPLIED, deferred_written=False)
            elif outcome in (OutcomeChoices.APPLIED, OutcomeChoices.SUBMITTED):
                self.managed_after(row, outcome, deferred_written=outcome == OutcomeChoices.APPLIED)

    def deferred_outcome(self, row, outcome):
        """
        The object was written, its fields written last were not: it stays
        "applied", with why, unless the failure undoes the whole apply.
        """
        if outcome == OutcomeChoices.FAILED and not self.options.get('continue_on_error'):
            return
        if outcome not in (OutcomeChoices.SKIPPED, OutcomeChoices.FAILED):
            return  # waiting for approval: shown as such
        names = ', '.join(sorted((row.proposed or {}).get('deferred', {})))
        self.results[row.key] = {'outcome': OutcomeChoices.APPLIED,
                                 'error': f'written without {names}: {self.results[row.key]["error"]}'}

    def counts(self):
        counts = {}
        for result in self.results.values():
            counts[result['outcome']] = counts.get(result['outcome'], 0) + 1
        return counts

    def failed(self):
        return any(r['outcome'] == OutcomeChoices.FAILED for r in self.results.values())

    def execute(self):
        """Apply (or dry-run) the plan. Returns the results per key."""
        from utilities.request import apply_request_processors

        request_id = uuid.uuid4()
        request = fake_request(self.user, request_id)
        committed = False
        try:
            with apply_request_processors(request):
                with transaction.atomic():
                    self.lock()
                    self.check()
                    continue_on_error = self.options.get('continue_on_error')
                    # Dry runs too: approvals are simulated, and the change
                    # set and requests roll back with everything else.
                    if integrations.has_change_approval():
                        from .integrations.change_approval import Gate

                        self.gate = Gate(self)
                    with self.gate if self.gate else nullcontext():
                        self.write_all()
                    if self.dry_run or (self.failed() and not continue_on_error):
                        raise _Rollback()
                    committed = True
        except _Rollback:
            pass
        self.finish(request_id, committed)
        return self.results

    def finish(self, request_id, committed):
        run = self.run
        now = timezone.now()
        if self.dry_run:
            run.dry_run = {'at': now.isoformat(), 'counts': self.counts(), 'items': self.results,
                           'failed': self.failed()}
            run.save(update_fields=['dry_run'])
            return
        by_key = {row.key: row for row in self.rows}
        changed = []
        for key, result in self.results.items():
            row = by_key[key]
            outcome = result['outcome']
            if not committed and outcome in (OutcomeChoices.APPLIED, OutcomeChoices.SUBMITTED, OutcomeChoices.BLOCKED):
                # Rolled back with everything else, change requests included.
                outcome = OutcomeChoices.SKIPPED
                result = {'outcome': outcome, 'error': 'rolled back: another item failed'}
            row.outcome = outcome
            row.error = result['error']
            if committed:
                row.change_request_id = result.get('change_request')
            if committed and row.object_id is None and key in self.keys and row.action not in REMOVALS:
                row.object_id = self.keys[key]
            changed.append(row)
        PlannedChange.objects.bulk_update(changed, ['outcome', 'error', 'object_id', 'change_request_id'])
        if committed:
            run.status = (RunStatusChoices.PENDING_APPROVAL if self.gate and self.gate.pending
                          else RunStatusChoices.APPLIED)
            run.applied = now
            run.applied_by = self.user
            run.apply_request_id = request_id
            run.error = 'Some items failed; see the list.' if self.failed() else ''
            ImportRun.objects.filter(binding=run.binding, status=RunStatusChoices.PLANNED) \
                .exclude(pk=run.pk).update(status=RunStatusChoices.SUPERSEDED)
        else:
            run.error = 'Nothing was applied: some items failed. Fix them or skip them, then apply again.'
        run.save()
        if committed:
            journal.applied(run, self.user)


def apply(run, user, dry_run=False, expected_plan=None):
    return Applier(run, user, dry_run=dry_run, expected_plan=expected_plan).execute()
