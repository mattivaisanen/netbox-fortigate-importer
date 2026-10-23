"""Background jobs (NetBox's job queue): dry run, apply and rollback."""
from netbox.jobs import JobRunner


class ImportRunJob(JobRunner):
    """One action on one import run. Shown on the run's Jobs tab."""

    class Meta:
        name = 'FortiGate import'

    def run(self, action='apply', *args, planned=None, **kwargs):
        from . import applier, rollback
        from .models import ImportRun, RunStatusChoices

        run = ImportRun.objects.get(pk=self.job.object_id)
        user = self.job.user
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
            try:
                count = rollback.rollback(run, user)
            except rollback.RollbackError as exc:
                run.error = str(exc)
                run.save(update_fields=['error'])
                raise
            self.logger.info('Rolled back %s changes', count)
        else:
            raise ValueError(f'unknown action {action}')


def enqueue(run, user, action):
    """
    Queue an action. Apply and dry run remember which plan the user saw, so
    they refuse to run if the plan is made again in between.
    """
    planned = run.planned.isoformat() if run.planned and action in ('apply', 'dry-run') else None
    return ImportRunJob.enqueue(instance=run, user=user, action=action, planned=planned)


def busy(run):
    """True while a job of this run is queued or running: its plan and decisions must not change."""
    return active_job(run) is not None


def active_job(run):
    from core.choices import JobStatusChoices

    return run.jobs.filter(status__in=JobStatusChoices.ENQUEUED_STATE_CHOICES).first()
