"""Retention, uninstall and the optional-plugin version check."""
from datetime import timedelta
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.utils import timezone

from extras.models import JournalEntry

from netbox_fortigate_importer import integrations, retention
from netbox_fortigate_importer.models import ImportRun, RunStatusChoices

from .test_apply import HQ, ImportTestCase, data_of


class RetentionTest(ImportTestCase):
    def age(self, run, days):
        ImportRun.objects.filter(pk=run.pk).update(created=timezone.now() - timedelta(days=days))

    def test_prunes_old_runs_but_keeps_latest_and_rollbackable(self):
        binding, applied = self.first_import()
        discarded = self.make_run(binding, data_of(HQ))
        ImportRun.objects.filter(pk=discarded.pk).update(status=RunStatusChoices.DISCARDED)
        failed = self.make_run(binding, data_of(HQ))
        ImportRun.objects.filter(pk=failed.pk).update(status=RunStatusChoices.FAILED)
        latest = self.make_run(binding, data_of(HQ))
        for run, days in ((applied, 200), (discarded, 150), (failed, 120), (latest, 100)):
            self.age(run, days)

        self.assertEqual(retention.prune(90), 2)
        # The applied run can still be rolled back; the latest stays for comparisons.
        self.assertEqual(set(ImportRun.objects.values_list('pk', flat=True)), {applied.pk, latest.pk})

    def test_applied_run_without_change_log_is_pruned(self):
        from core.models import ObjectChange

        binding, applied = self.first_import()
        self.make_run(binding, data_of(HQ))  # a newer run is the latest
        self.age(applied, 200)
        ObjectChange.objects.filter(request_id=applied.apply_request_id).delete()  # changelog retention
        self.assertEqual(retention.prune(90), 1)

    def test_command_needs_days(self):
        out = StringIO()
        call_command('prune_fortigate_runs', '--days', '30', '--dry-run', stdout=out)
        self.assertIn('0 import runs would be deleted', out.getvalue())


class UninstallTest(ImportTestCase):
    def test_removes_rows_pointing_at_importer_records(self):
        binding = self.make_binding()
        JournalEntry.objects.create(assigned_object=binding, comments='note')
        call_command('prepare_fortigate_uninstall', '--no-input', stdout=StringIO())
        self.assertFalse(JournalEntry.objects.filter(assigned_object_id=binding.pk,
                                                     assigned_object_type__app_label='netbox_fortigate_importer'))
        # The device the binding points at is NetBox data and stays.
        self.assertTrue(type(binding.device).objects.filter(pk=binding.device_id).exists())


class VersionCheckTest(ImportTestCase):
    def test_warns_outside_tested_minor_version(self):
        with mock.patch.object(integrations, 'installed', return_value=True), \
                mock.patch.object(integrations.metadata, 'version', return_value='9.9.0'), \
                self.assertLogs('netbox_fortigate_importer', 'WARNING') as logs:
            integrations.check_versions()
        self.assertEqual(len(logs.records), len(integrations.TESTED))

    def test_patch_releases_are_fine(self):
        tested = {dist: version.rsplit('.', 1)[0] + '.99' for dist, version in integrations.TESTED.values()}
        with mock.patch.object(integrations, 'installed', return_value=True), \
                mock.patch.object(integrations.metadata, 'version', side_effect=tested.get):
            self.assertEqual(integrations.untested_versions(), [])
