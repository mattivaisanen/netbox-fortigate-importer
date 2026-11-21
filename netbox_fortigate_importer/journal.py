"""
A NetBox journal entry on the firewall's device for every apply and
rollback, so the device's own history shows when its configuration was
synced and by whom.

Written after the apply or rollback has committed and outside its request:
the entry is not part of the import's change log, so rolling the import back
leaves it alone. A failing journal entry never fails the import.
"""
import logging

from django.db import transaction

from .models import FortiGateBinding, OutcomeChoices
from .settings import get_setting

logger = logging.getLogger('netbox_fortigate_importer.journal')


def _target(run):
    """The device, or the FortiGate itself while it has none (a created device rolled back)."""
    binding = FortiGateBinding.objects.select_related('device').filter(pk=run.binding_id).first()
    if binding is None:
        return None
    return binding.device or binding


def _counts(run, outcome):
    found = {}
    for action in run.changes.filter(outcome=outcome).values_list('action', flat=True):
        found[action] = found.get(action, 0) + 1
    labels = {'create': 'created', 'update': 'updated', 'adopt': 'adopted', 'delete': 'deleted',
              'unmanage': 'no longer managed', 'deprecate': 'deprecated', 'conflict': 'updated'}
    merged = {}
    for action, n in found.items():
        merged[labels.get(action, action)] = merged.get(labels.get(action, action), 0) + n
    return ', '.join(f'{n} {label}' for label, n in merged.items()) or 'nothing changed'


def _write(run, user, kind, text):
    from extras.models import JournalEntry

    if not get_setting('journal_entries'):
        return None
    target = _target(run)
    if target is None:
        return None
    try:
        with transaction.atomic():
            entry = JournalEntry(assigned_object=target, created_by=user, kind=kind, comments=text)
            entry.full_clean()
            entry.save()
            return entry
    except Exception:  # noqa: BLE001 - the import itself is already done
        logger.exception('Could not write the journal entry for import %s', run.pk)
        return None


def own_entries(objects):
    """
    (content type pk, pk) of the importer's journal entries on `objects`
    ((content type pk, pk) pairs). Rolling back an import that created the
    device deletes them with the device instead of refusing.
    """
    from django.contrib.contenttypes.models import ContentType

    from extras.models import JournalEntry

    by_type = {}
    for type_id, pk in objects:
        by_type.setdefault(type_id, set()).add(pk)
    found = set()
    entry_type = ContentType.objects.get_for_model(JournalEntry).pk
    for type_id, pks in by_type.items():
        entries = JournalEntry.objects.filter(
            assigned_object_type_id=type_id, assigned_object_id__in=pks,
            comments__startswith='FortiGate ', comments__contains='/fortigate-importer/runs/',
        )
        found |= {(entry_type, pk) for pk in entries.values_list('pk', flat=True)}
    return found


def _link(run):
    return f'[import #{run.pk}]({run.get_absolute_url()})'


def applied(run, user):
    """After an apply committed."""
    source = f' from `{run.filename}`' if run.filename else ''
    text = f'FortiGate configuration imported{source} ({_link(run)}): {_counts(run, OutcomeChoices.APPLIED)}.'
    submitted = run.changes.filter(outcome=OutcomeChoices.SUBMITTED).count()
    kind = 'success'
    if submitted:
        text += f' {submitted} changes wait for approval.'
        kind = 'info'
    failed = run.changes.filter(outcome=OutcomeChoices.FAILED).count()
    if failed:
        text += f' {failed} changes failed.'
        kind = 'warning'
    return _write(run, user, kind, text)


def rolled_back(run, user):
    """After a rollback committed."""
    undone = run.changes.filter(outcome=OutcomeChoices.ROLLED_BACK).count()
    text = f'FortiGate import rolled back ({_link(run)}): {undone} changes undone.'
    return _write(run, user, 'warning', text)
