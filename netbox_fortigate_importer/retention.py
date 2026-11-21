"""
Pruning old import runs.

Every run keeps the data extracted from its configuration, the plan and the
results, which adds up over months of imports. Runs older than
`run_retention_days` are deleted, with their planned changes, except:

- a run that is still busy or waits for approval;
- the latest run of each FortiGate (Firewall Changes and the "imported
  before" warning compare against it);
- an applied run that can still be rolled back: NetBox's change log still
  has its entries (CHANGELOG_RETENTION decides how long).

`manage.py prune_fortigate_runs` does it by hand; with the setting above 0,
a daily system job does it too.
"""
from datetime import timedelta

from django.db.models import Max
from django.utils import timezone

from netbox.jobs import JobRunner, system_job

from .models import ImportRun, RunStatusChoices
from .settings import get_setting

#: Statuses a run may be pruned in. Anything busy, or waiting for
#: approvers, stays.
PRUNABLE = (
    RunStatusChoices.PARSED, RunStatusChoices.PLANNED, RunStatusChoices.APPLIED, RunStatusChoices.FAILED,
    RunStatusChoices.ROLLED_BACK, RunStatusChoices.DISCARDED, RunStatusChoices.SUPERSEDED,
)


def prunable_runs(days):
    """The runs older than `days` days that nothing needs any more."""
    from core.models import ObjectChange

    cutoff = timezone.now() - timedelta(days=days)
    latest = ImportRun.objects.filter(binding__isnull=False).exclude(status=RunStatusChoices.DISCARDED) \
        .values('binding').annotate(last=Max('created')).values_list('binding', 'last')
    candidates = ImportRun.objects.filter(created__lt=cutoff, status__in=PRUNABLE)
    keep = set()
    latest = dict(latest)
    for run in candidates.only('pk', 'binding_id', 'created', 'status', 'apply_request_id'):
        if run.binding_id and latest.get(run.binding_id) == run.created:
            keep.add(run.pk)
        elif run.status == RunStatusChoices.APPLIED and run.apply_request_id and \
                ObjectChange.objects.filter(request_id=run.apply_request_id).exists():
            keep.add(run.pk)
    return candidates.exclude(pk__in=keep)


def prune(days):
    """Delete prunable runs; returns how many runs were deleted."""
    runs = prunable_runs(days)
    count = runs.count()
    runs.delete()
    return count


@system_job(interval=24 * 60)
class PruneImportRunsJob(JobRunner):
    """Daily: delete old import runs, when run_retention_days is set."""

    class Meta:
        name = 'Prune FortiGate import runs'

    def run(self, *args, **kwargs):
        days = get_setting('run_retention_days')
        if not days:
            self.logger.info('run_retention_days is 0: keeping every import run')
            return
        self.logger.info(f'Deleted {prune(days)} import runs older than {days} days')
