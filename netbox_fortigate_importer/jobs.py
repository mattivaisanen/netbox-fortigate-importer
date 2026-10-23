"""Background jobs (NetBox's job queue): dry run, apply and rollback."""
import logging

from netbox.jobs import JobRunner

logger = logging.getLogger('netbox_fortigate_importer.jobs')


class ImportRunJob(JobRunner):
    """One action on one import run. Shown on the run's Jobs tab."""

    class Meta:
        name = 'FortiGate import'

    def run(self, action='apply', *args, planned=None, **kwargs):
        from .models import ImportRun

        run = ImportRun.objects.get(pk=self.job.object_id)
        user = self.job.user
        try:
            self._run(run, user, action, planned)
        except Exception as exc:
            # Shown on the run's page, not only in the job's log.
            label = {'dry-run': 'Dry run', 'apply': 'Apply', 'rollback': 'Rollback'}.get(action, action)
            ImportRun.objects.filter(pk=run.pk).update(error=f'{label} did not run: {error_text(exc)}'[:2000])
            raise

    def _run(self, run, user, action, planned):
        from . import applier, rollback
        from .models import RunStatusChoices

        if action == 'dry-run':
            applier.apply(run, user, dry_run=True, expected_plan=planned)
            self.logger.info('Dry run: %s', run.dry_run.get('counts'))
        elif action == 'apply':
            applier.apply(run, user, expected_plan=planned)
            run.refresh_from_db()
            self.logger.info('Applied: %s', run.get_status_display())
            if run.status == RunStatusChoices.PLANNED and run.error:
                self.logger.warning(run.error)
        elif action == 'rollback':
            count = rollback.rollback(run, user)
            self.logger.info('Rolled back %s changes', count)
        else:
            raise ValueError(f'unknown action {action}')


class QueueError(Exception):
    """NetBox could not queue the job (database or Redis trouble)."""


def error_text(exc):
    from .applier import error_text as text

    return text(exc)


def enqueue(run, user, action):
    """
    Queue an action. Apply and dry run remember which plan the user saw, so
    they refuse to run if the plan is made again in between.
    """
    planned = run.planned.isoformat() if run.planned and action in ('apply', 'dry-run') else None
    try:
        return ImportRunJob.enqueue(instance=run, user=user, action=action, planned=planned)
    except Exception as exc:  # noqa: BLE001 - shown to the user instead of a server error
        logger.exception('Could not queue %s for import run %s', action, run.pk)
        raise QueueError(
            f'NetBox could not queue the job: {error_text(exc)}. Check that NetBox\'s database, Redis and '
            f'background worker (netbox-worker) are healthy, then try again.'
        ) from exc


def workers_running():
    """True or False when Redis can tell whether a background worker runs; None when it can't."""
    try:
        from django_rq import get_connection
        from rq import Worker

        return Worker.count(connection=get_connection('default')) > 0
    except Exception:  # noqa: BLE001
        return None


def busy(run):
    """True while a job of this run is queued or running: its plan and decisions must not change."""
    return active_job(run) is not None


def active_job(run):
    from core.choices import JobStatusChoices

    return run.jobs.filter(status__in=JobStatusChoices.ENQUEUED_STATE_CHOICES).first()
