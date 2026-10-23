"""
Which planned changes need which others.

A change refers to other planned objects (an interface to its device, a
static route to its VRF). If a change is approved but an object it needs is
not, the apply has to skip it. These helpers find those gaps so the review
page can offer to approve the missing changes too.
"""
from __future__ import annotations

from .models import ActionChoices, DecisionChoices

#: Decisions under which a change gets written (or its object already exists).
WILL_EXIST = (DecisionChoices.APPROVED, DecisionChoices.KEEP_NETBOX)


def _rows(run):
    return {row.key: row for row in run.changes.only(
        'pk', 'key', 'label', 'action', 'decision', 'depends_on', 'section', 'object_id', 'object_type')}


def ready(row):
    """True when the object of `row` exists after the apply without it being approved."""
    return row.action == ActionChoices.NOOP or row.decision in WILL_EXIST or (
        row.object_id is not None and row.action not in ActionChoices.WRITES)


def missing_for(run, selected_pks):
    """
    Changes the selected ones need that are not approved, following
    dependencies of dependencies. Ordered as the plan.
    """
    rows = _rows(run)
    selected = {row.key for row in rows.values() if row.pk in set(selected_pks)}
    missing, seen = {}, set()
    todo = list(selected)
    while todo:
        key = todo.pop()
        if key in seen:
            continue
        seen.add(key)
        row = rows.get(key)
        if row is None:
            continue
        for dep in row.depends_on or []:
            dep_row = rows.get(dep)
            if dep_row is None:
                # Not in the plan: an object that exists already.
                continue
            # An existing object (adopt, update, conflict) is there for
            # references even when its change is skipped.
            needed = dep_row.object_id is None and not ready(dep_row)
            if needed and dep not in selected:
                missing[dep] = dep_row
            todo.append(dep)
    return sorted(missing.values(), key=lambda r: r.pk)


def dependents_of(run, skipped_pks):
    """Approved changes that need one of the skipped ones (they will be skipped too)."""
    rows = _rows(run)
    skipped = {row.key for row in rows.values() if row.pk in set(skipped_pks) and row.object_id is None}
    found, changed = {}, True
    while changed:
        changed = False
        for row in rows.values():
            if row.key in skipped or row.decision != DecisionChoices.APPROVED:
                continue
            if any(dep in skipped for dep in row.depends_on or []):
                found[row.key] = row
                skipped.add(row.key)
                changed = True
    return sorted(found.values(), key=lambda r: r.pk)


def describe(row):
    return f'{row.label} ({row.get_decision_display().lower()})'
