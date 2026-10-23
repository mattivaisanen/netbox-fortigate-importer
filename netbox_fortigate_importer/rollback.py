"""
Rolling an applied import back, from NetBox's own change log.

Every change the apply wrote carries the apply's request ID. Rollback walks
those change log entries newest first and undoes each: a created object is
deleted, an updated one gets its earlier data back, a deleted one is
recreated with its old ID. It runs as one request with its own request ID, so
the rollback is in the change log too.

Rollback refuses when any of those objects was changed after the import (by
someone, or by a later import): it would overwrite that newer work. The
importer's records (ManagedObject) go back to how they were before the apply.

With netbox-change-approval, requests of the import that still wait for a
decision are withdrawn first.
"""
from __future__ import annotations

import uuid

from django.db import transaction
from django.utils import timezone

from . import integrations
from .applier import error_text, fake_request
from .models import ManagedObject, OutcomeChoices, PlannedChange, RunStatusChoices


class RollbackError(Exception):
    pass


def _changes(run):
    from core.models import ObjectChange
    from django.contrib.contenttypes.models import ContentType
    from extras.models import Tag

    # The import tag stays: other imports' objects may carry it. Change
    # requests the import queued are withdrawn, not deleted.
    return list(ObjectChange.objects.filter(request_id=run.apply_request_id)
                .exclude(changed_object_type=ContentType.objects.get_for_model(Tag))
                .exclude(changed_object_type__app_label=integrations.CHANGE_APPROVAL)
                .select_related('changed_object_type').order_by('-time', '-pk'))


def later_edits(run, changes=None):
    """Objects of this import changed by something else after it: [(repr, user, time)]."""
    from core.models import ObjectChange

    changes = changes if changes is not None else _changes(run)
    if not changes:
        return []
    last = max(change.time for change in changes)
    objects = {(c.changed_object_type_id, c.changed_object_id) for c in changes}
    found = []
    later = ObjectChange.objects.filter(time__gt=last).exclude(request_id=run.apply_request_id)
    for change in later.order_by('time'):
        if (change.changed_object_type_id, change.changed_object_id) in objects:
            found.append((change.object_repr, change.user_name, change.time))
    return found


def _undo(change):
    from core.choices import ObjectChangeActionChoices as Action
    from utilities.serialization import deserialize_object

    model = change.changed_object_type.model_class()
    current = model.objects.filter(pk=change.changed_object_id).first()
    if change.action == Action.ACTION_CREATE:
        if current is not None:
            current.snapshot()
            current.delete()
        return
    if not change.prechange_data:
        raise RollbackError(f'{change.object_repr}: the change log has no earlier data to restore')
    restored = deserialize_object(model, change.prechange_data, pk=change.changed_object_id)
    if current is not None:
        restored.object._state.adding = False
        restored.object._state.db = current._state.db
        restored.object._prechange_snapshot = current.serialize_object()
    restored.object.full_clean()
    restored.save()


def withdraw_requests(run, user):
    """Withdraw this import's change requests that wait for a decision."""
    if not integrations.has_change_approval():
        return 0
    from netbox_change_approval.models import ChangeRequest, StatusChoices

    ids = list(run.changes.filter(outcome=OutcomeChoices.SUBMITTED, change_request_id__isnull=False)
               .values_list('change_request_id', flat=True))
    count = 0
    for request in ChangeRequest.objects.filter(pk__in=ids, status=StatusChoices.PENDING):
        request.retract(user)
        count += 1
    return count


def rollback(run, user):
    from utilities.request import apply_request_processors

    if not run.can_rollback:
        raise RollbackError(f'A run that is "{run.get_status_display()}" cannot be rolled back.')
    changes = _changes(run)
    edits = later_edits(run, changes)
    if edits:
        names = ', '.join(sorted({repr_ for repr_, _, _ in edits})[:10])
        raise RollbackError(f'Changed in NetBox after this import, so rollback would overwrite newer work: {names}')
    newer = run.binding.runs.filter(applied__gt=run.applied).exclude(pk=run.pk) if run.binding_id else None
    if newer is not None and newer.exclude(status=RunStatusChoices.ROLLED_BACK).exists():
        raise RollbackError('A later import of this FortiGate was applied. Roll that one back first.')

    request_id = uuid.uuid4()
    request = fake_request(user, request_id)
    with apply_request_processors(request):
        with transaction.atomic():
            withdraw_requests(run, user)
            for change in changes:
                try:
                    _undo(change)
                except RollbackError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    raise RollbackError(f'{change.object_repr}: {error_text(exc)}') from exc
            restore_records(run)
            run.status = RunStatusChoices.ROLLED_BACK
            run.rolled_back = timezone.now()
            run.rollback_request_id = request_id
            run.save()
    return len(changes)


def restore_records(run):
    """The importer's ManagedObject rows as they were before the apply."""
    rows = list(run.changes.exclude(outcome=OutcomeChoices.NONE))
    for change in rows:
        before = change.managed_before
        ManagedObject.objects.filter(binding_id=run.binding_id, key=change.key).delete()
        if before:
            ManagedObject.objects.create(
                binding_id=run.binding_id, key=change.key, object_type_id=before['object_type'],
                object_id=before['object_id'], fields=before['fields'],
                confirmed=before.get('confirmed', True),
                first_run_id=before.get('first_run'), last_run_id=before.get('last_run'),
            )
    PlannedChange.objects.filter(run=run, outcome__in=(OutcomeChoices.APPLIED, OutcomeChoices.SUBMITTED)) \
        .update(outcome=OutcomeChoices.ROLLED_BACK)
