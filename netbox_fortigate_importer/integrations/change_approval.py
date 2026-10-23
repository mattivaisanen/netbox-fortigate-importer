"""
Working with netbox-change-approval (optional; imported only when installed).

An import runs as the user who applied it. Whatever needs approval for that
user needs approval here too: the change is queued as a change request
instead of being written, and the rest of the import carries on.

- The apply opens a change set "FortiGate import: <run>" and every request
  it queues joins it, so approvers decide the import as one, and submits it
  at the end. No requests: the change set is removed.
- Each item runs under change-approval's batch collector, the way a bulk
  edit does: a gated update or delete is queued and its savepoint rolled
  back; a create is written and marked pending (change-approval shows
  pending creates right away).
- An object that already waits for approval is "blocked": not changed.
- When a request is approved, rejected or withdrawn, the planned change and
  the importer's record of the object follow (see `request_saved`).
- Superusers and users with change-approval's bypass permission write
  directly, like everywhere else in NetBox.
"""
from __future__ import annotations

from contextlib import contextmanager

from django.db.models.signals import post_save

from ..applier import Submitted
from ..models import ImportRun, ManagedObject, OutcomeChoices, PlannedChange, RunStatusChoices


class Gate:
    def __init__(self, applier):
        self.applier = applier
        self.change_set = None
        self.pending = 0
        #: key -> (outcome, change request pk)
        self.outcomes = {}
        self._stack = []

    def __enter__(self):
        from netbox_change_approval.bulk import BatchCollector, collecting
        from netbox_change_approval.context import batch_scope
        from netbox_change_approval.models import ChangeSet

        run = self.applier.run
        self.change_set = ChangeSet.objects.create(
            name=f'FortiGate import: {run}'[:100], created_by=self.applier.user,
        )
        collect = collecting(BatchCollector.RAISE)
        self.collector = collect.__enter__()
        scope = batch_scope(self.change_set.batch_id)
        scope.__enter__()
        self._stack = [scope, collect]
        return self

    def __exit__(self, *exc_info):
        from netbox_change_approval import changesets

        for manager in self._stack:
            manager.__exit__(*exc_info)
        self._stack = []
        if exc_info[0] is not None:
            return False
        if self.change_set.requests().exists():
            changesets.submit(self.change_set)
            self.applier.run.change_set_id = self.change_set.pk
        else:
            self.change_set.delete()
            self.change_set = None
        return False

    @contextmanager
    def item(self, row):
        from netbox_change_approval.exceptions import ChangeApprovalRequired

        queued = len(self.collector.queued)
        try:
            yield
        except ChangeApprovalRequired as exc:
            raise Submitted(exc)
        if len(self.collector.queued) > queued:
            # A gated delete: change-approval kept the object and saved the
            # request already.
            self.mark(row, OutcomeChoices.SUBMITTED, self.collector.queued[-1].pk)
            return
        self.check_pending(row)

    def record(self, row, exc):
        """After the item's savepoint is rolled back: save its request."""
        self.collector.record(exc.approval_exc)
        change_request = exc.approval_exc.change_request
        if exc.approval_exc.locked:
            self.mark(row, OutcomeChoices.BLOCKED, change_request.pk)
        else:
            self.mark(row, OutcomeChoices.SUBMITTED, change_request.pk)

    def mark(self, row, outcome, change_request_id):
        self.outcomes[row.key] = (outcome, change_request_id)
        if outcome == OutcomeChoices.SUBMITTED:
            self.pending += 1

    def check_pending(self, row):
        """A create written as "pending" has a request waiting for it."""
        from netbox_change_approval.models import ChangeRequest, StatusChoices

        pk = self.applier.keys.get(row.key)
        if pk is None:
            return
        request = ChangeRequest.objects.filter(
            content_type_id=row.object_type_id, object_id=pk, status=StatusChoices.PENDING,
            batch_id=self.change_set.batch_id,
        ).order_by('-pk').first()
        if request is not None:
            self.mark(row, OutcomeChoices.SUBMITTED, request.pk)

    def outcome(self, row):
        return self.outcomes.get(row.key)


# Following decisions

def request_saved(sender, instance, created=False, **kwargs):
    """A change request was decided: update the planned change and the record."""
    from netbox_change_approval.models import StatusChoices

    if created or instance.status == StatusChoices.PENDING:
        return
    changes = list(PlannedChange.objects.filter(change_request_id=instance.pk).select_related('run'))
    for change in changes:
        if change.outcome != OutcomeChoices.SUBMITTED:
            continue
        managed = ManagedObject.objects.filter(binding_id=change.run.binding_id, key=change.key).first()
        if instance.status == StatusChoices.APPLIED:
            change.outcome = OutcomeChoices.APPLIED
            if change.action in ('delete', 'deprecate', 'unmanage'):
                # Like a direct apply: the importer stops managing it.
                if change.action in ('delete', 'deprecate') and managed is not None:
                    managed.delete()
            elif managed is not None:
                managed.confirmed = True
                managed.save(update_fields=['confirmed', 'updated'])
        else:
            change.outcome = OutcomeChoices.REJECTED
            restore_managed(change, managed)
        change.save(update_fields=['outcome'])
        settle_run(change.run)


def restore_managed(change, managed):
    """Put the importer's record back as it was before the rejected change."""
    before = change.managed_before
    if before is None:
        if managed is not None:
            managed.delete()
        return
    if managed is None:
        managed = ManagedObject(binding_id=change.run.binding_id, key=change.key)
    managed.object_type_id = before['object_type']
    managed.object_id = before['object_id']
    managed.fields = before['fields']
    managed.confirmed = before.get('confirmed', True)
    managed.save()


def settle_run(run):
    if run.status != RunStatusChoices.PENDING_APPROVAL:
        return
    if not run.changes.filter(outcome=OutcomeChoices.SUBMITTED).exists():
        ImportRun.objects.filter(pk=run.pk).update(status=RunStatusChoices.APPLIED)


def connect():
    from netbox_change_approval.models import ChangeRequest

    post_save.connect(request_saved, sender=ChangeRequest, dispatch_uid='netbox_fortigate_importer:requests')
