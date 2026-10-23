"""Background jobs (NetBox's job queue): dry run, apply and rollback."""
from netbox.jobs import JobRunner


class ImportRunJob(JobRunner):
    """One action on one import run. Shown on the run's Jobs tab."""

    class Meta:
        name = 'FortiGate import'

    def run(self, action='apply', *args, **kwargs):
        from . import applier, rollback
        from .models import ImportRun, RunStatusChoices

        run = ImportRun.objects.get(pk=self.job.object_id)
        user = self.job.user
        if action == 'dry-run':
            applier.apply(run, user, dry_run=True)
            self.logger.info('Dry run: %s', run.dry_run.get('counts'))
        elif action == 'apply':
            applier.apply(run, user)
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


def active_job(run):
    from core.choices import JobStatusChoices

    return run.jobs.filter(status__in=JobStatusChoices.ENQUEUED_STATE_CHOICES).first()
