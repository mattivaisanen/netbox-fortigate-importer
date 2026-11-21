"""Delete old import runs that nothing needs any more. See retention.py."""
from django.core.management.base import BaseCommand, CommandError

from netbox_fortigate_importer import retention
from netbox_fortigate_importer.settings import get_setting


class Command(BaseCommand):
    help = (
        'Delete import runs older than run_retention_days (or --days), except busy runs, runs waiting for '
        'approval, the latest run of each FortiGate and applied runs that can still be rolled back.'
    )

    def add_arguments(self, parser):
        parser.add_argument('--days', type=int, help='Age in days (default: the run_retention_days setting).')
        parser.add_argument('--dry-run', action='store_true', help='Only show how many runs would be deleted.')

    def handle(self, *args, days=None, dry_run=False, **options):
        days = days if days is not None else get_setting('run_retention_days')
        if not days or days < 1:
            raise CommandError('Give --days, or set run_retention_days above 0.')
        if dry_run:
            self.stdout.write(f'{retention.prunable_runs(days).count()} import runs would be deleted.')
            return
        self.stdout.write(self.style.SUCCESS(f'Deleted {retention.prune(days)} import runs older than {days} days.'))
