"""Reviewing a plan: dependencies, dry-run results, the device choice page and job errors."""
from unittest import mock

from django.urls import reverse

from dcim.models import Device, Interface, InterfaceTemplate

from netbox_fortigate_importer import applier, dependencies, rollback
from netbox_fortigate_importer.jobs import ImportRunJob, counts_text
from netbox_fortigate_importer.models import (
    ActionChoices,
    DecisionChoices,
    FortiGateBinding,
    ImportRun,
    OutcomeChoices,
    RunStatusChoices,
)

from .test_views import URL, ViewBase
from .utils import BRANCH, read


class ReviewTest(ViewBase):
    def setUp(self):
        super().setUp()
        self.device = Device.objects.create(name='b1', site=self.site, device_type=self.device_type, role=self.role)
        FortiGateBinding.objects.create(name='Branch', device=self.device, serial='FGT60FTK21005678')
        self.upload(read(BRANCH))
        self.run = ImportRun.objects.get()

    def decide(self, pks, decision, **extra):
        return self.client.post(reverse(URL + 'importrun_decide', args=[self.run.pk]), {
            'pk': pks, 'decision': decision, 'scope': 'selected', **extra,
        })

    def change_with_new_dependency(self):
        """A planned create that needs another planned create."""
        creates = {c.key: c for c in self.run.changes.filter(action=ActionChoices.CREATE)}
        for change in creates.values():
            needed = [creates[k] for k in change.depends_on if k in creates]
            if needed:
                return change, needed
        self.fail('the fixture has no create that needs another create')

    def test_approving_asks_for_what_the_change_needs(self):
        self.run.changes.update(decision=DecisionChoices.SKIPPED)
        change, needed = self.change_with_new_dependency()
        page = self.decide([change.pk], DecisionChoices.APPROVED)
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, 'They need')
        for row in needed:
            self.assertContains(page, row.label)
        change.refresh_from_db()
        self.assertEqual(change.decision, DecisionChoices.SKIPPED, 'nothing is decided before the answer')

        # "Approve them too": the change and everything it needs.
        missing = dependencies.missing_for(self.run, [change.pk])
        self.decide([change.pk], DecisionChoices.APPROVED, dependencies='include')
        for row in [change, *missing]:
            row.refresh_from_db()
            self.assertEqual(row.decision, DecisionChoices.APPROVED, row.key)
        self.assertEqual(dependencies.missing_for(self.run, [change.pk]), [])

    def test_approving_only_the_selection(self):
        self.run.changes.update(decision=DecisionChoices.SKIPPED)
        change, needed = self.change_with_new_dependency()
        self.decide([change.pk], DecisionChoices.APPROVED, dependencies='only')
        change.refresh_from_db()
        self.assertEqual(change.decision, DecisionChoices.APPROVED)
        for row in needed:
            row.refresh_from_db()
            self.assertEqual(row.decision, DecisionChoices.SKIPPED)
        # The apply then says what is missing, by name.
        results = applier.apply(self.run, self.user, dry_run=True)
        self.assertEqual(results[change.key]['outcome'], OutcomeChoices.SKIPPED)
        self.assertIn('is skipped: approve it too', results[change.key]['error'])
        self.assertIn(needed[0].label, ' '.join(r['error'] for r in results.values()))

    def test_no_question_when_nothing_is_missing(self):
        change, _ = self.change_with_new_dependency()
        response = self.decide([change.pk], DecisionChoices.APPROVED)
        self.assertEqual(response.status_code, 302)

    def test_skipping_warns_about_changes_that_need_it(self):
        change, needed = self.change_with_new_dependency()
        response = self.decide([needed[0].pk], DecisionChoices.SKIPPED, return_url=self.run.get_absolute_url())
        page = self.client.get(response.url)
        self.assertContains(page, 'will be skipped too')

    def test_change_page_names_what_it_needs(self):
        change, needed = self.change_with_new_dependency()
        page = self.client.get(change.get_absolute_url())
        self.assertContains(page, needed[0].label)
        self.assertContains(page, needed[0].get_absolute_url())

    def test_dry_run_failures_are_listed(self):
        change, _ = self.change_with_new_dependency()
        failing = self.run.changes.filter(action=ActionChoices.CREATE).exclude(pk=change.pk).first()
        self.run.dry_run = {
            'counts': {'applied': 1, 'failed': 1}, 'failed': True,
            'items': {change.key: {'outcome': 'applied', 'error': ''},
                      failing.key: {'outcome': 'failed', 'error': 'name: too long'}},
        }
        self.run.save()
        page = self.client.get(self.run.get_absolute_url())
        self.assertContains(page, '?dry_run=failed')
        self.assertContains(page, 'Failed in dry run')
        page = self.client.get(self.run.get_absolute_url() + '?dry_run=failed')
        self.assertContains(page, failing.label)
        self.assertContains(page, 'name: too long')
        self.assertNotContains(page, f'>{change.label}<')
        # "Approve all shown" on that list approves only the failing one.
        self.run.changes.update(decision=DecisionChoices.SKIPPED)
        self.client.post(reverse(URL + 'importrun_decide', args=[self.run.pk]), {
            'f_dry_run': 'failed', 'decision': DecisionChoices.APPROVED, 'scope': 'filtered',
            'dependencies': 'only',
        })
        self.assertEqual(list(self.run.changes.filter(decision=DecisionChoices.APPROVED)
                              .values_list('key', flat=True)), [failing.key])

    def test_not_imported_sections_are_folded(self):
        self.run.data.setdefault('stats', {})['not_imported'] = ['system snmp user', 'log disk setting']
        self.run.save()
        page = self.client.get(self.run.get_absolute_url())
        self.assertContains(page, '<details>')
        self.assertContains(page, '2 configuration sections the importer does not read')

    def test_queue_error_is_shown_not_a_server_error(self):
        with mock.patch.object(ImportRunJob, 'enqueue', side_effect=RuntimeError('duplicate key value')):
            response = self.client.post(reverse(URL + 'importrun_dryrun', args=[self.run.pk]), follow=True)
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, 'NetBox could not queue the job: duplicate key value')
            api = self.client.post(f'/api/plugins/fortigate-importer/runs/{self.run.pk}/dry-run/')
            self.assertEqual(api.status_code, 503)
            self.assertIn('could not queue', api.json()['detail'])

    def test_missing_worker_is_reported(self):
        with mock.patch('netbox_fortigate_importer.jobs.workers_running', return_value=False):
            response = self.client.post(reverse(URL + 'importrun_dryrun', args=[self.run.pk]), follow=True)
        self.assertContains(response, 'No NetBox background worker is running')
        with mock.patch('netbox_fortigate_importer.jobs.workers_running', return_value=False):
            self.assertContains(self.client.get(self.run.get_absolute_url()), 'No NetBox background worker')

    def test_a_crashing_job_tells_the_run(self):
        with mock.patch.object(applier, 'apply', side_effect=RuntimeError('database went away')):
            ImportRunJob.enqueue(instance=self.run, user=self.user, immediate=True, action='apply')
        self.run.refresh_from_db()
        self.assertEqual(self.run.error, 'Apply did not run: database went away')
        self.assertContains(self.client.get(self.run.get_absolute_url()), 'Apply did not run: database went away')

    def test_device_interfaces_missing_from_the_config_are_noted(self):
        Interface.objects.create(device=self.device, name='Ethernet1', type='1000base-t')
        self.client.post(reverse(URL + 'importrun_plan', args=[self.run.pk]))
        self.run.refresh_from_db()
        notes = ' '.join(self.run.summary['notes'])
        self.assertIn('b1 has 1 interfaces that are not in the configuration (Ethernet1)', notes)


class BindPageTest(ViewBase):
    def test_device_choice_uses_radio_buttons(self):
        self.upload(read(BRANCH))
        run = ImportRun.objects.get()
        page = self.client.get(reverse(URL + 'importrun_bind', args=[run.pk]))
        self.assertContains(page, 'class="form-check-input" type="radio" name="mode"', count=2)
        self.assertContains(page, 'value="existing" checked')
        self.assertEqual(run.status, RunStatusChoices.PARSED)


class DeviceTypeInterfacesTest(ViewBase):
    """A new device gets the interfaces of its device type from NetBox."""

    def setUp(self):
        super().setUp()
        for name in ('wan1', 'wan2', 'dmz', 'internal', 'ha'):
            InterfaceTemplate.objects.create(device_type=self.device_type, name=name, type='1000base-t')
        self.upload(read(BRANCH))
        self.run = ImportRun.objects.get()
        self.client.post(reverse(URL + 'importrun_bind', args=[self.run.pk]), {
            'mode': 'new', 'name': 'branch1-fw01', 'site': self.site.pk, 'role': self.role.pk,
        })
        self.run.refresh_from_db()
        self.run.changes.filter(decision=DecisionChoices.PENDING).update(decision=DecisionChoices.APPROVED)

    def test_dry_run_matches_them(self):
        results = applier.apply(self.run, self.user, dry_run=True)
        failed = {k: r['error'] for k, r in results.items() if r['outcome'] == OutcomeChoices.FAILED}
        self.assertEqual(failed, {})
        self.assertEqual(results['interface/wan1']['outcome'], OutcomeChoices.APPLIED)
        self.assertFalse(Device.objects.exists())

    def test_apply_updates_them_and_rollback_removes_all(self):
        applier.apply(self.run, self.user)
        self.run.refresh_from_db()
        self.assertEqual(self.run.status, RunStatusChoices.APPLIED, self.run.error)
        device = self.run.binding.device
        self.assertEqual(device.interfaces.filter(name='wan1').count(), 1)
        wan1 = device.interfaces.get(name='wan1')
        self.assertEqual(self.run.changes.get(key='interface/wan1').object_id, wan1.pk)
        self.assertTrue(wan1.tags.exists(), 'tagged like the objects the import created')
        # Interfaces the config does not have stay as the device type made them.
        self.assertTrue(device.interfaces.filter(name='ha').exists())
        # The next import plans no new interfaces.
        self.upload(read(BRANCH))
        again = ImportRun.objects.latest('pk')
        self.assertFalse(again.changes.filter(section='interface', action=ActionChoices.CREATE,
                                              key__in=['interface/wan1', 'interface/dmz']).exists())

        rollback.rollback(self.run, self.user)
        self.run.refresh_from_db()
        self.assertEqual(self.run.status, RunStatusChoices.ROLLED_BACK, self.run.error)
        self.assertFalse(Device.objects.exists())
        self.assertFalse(Interface.objects.exists())


class JobLogTest(ViewBase):
    def test_dry_run_job_logs_its_own_counts(self):
        device = Device.objects.create(name='b1', site=self.site, device_type=self.device_type, role=self.role)
        FortiGateBinding.objects.create(name='Branch', device=device, serial='FGT60FTK21005678')
        self.upload(read(BRANCH))
        run = ImportRun.objects.get()
        job = ImportRunJob.enqueue(instance=run, user=self.user, immediate=True, action='dry-run')
        job.refresh_from_db()
        run.refresh_from_db()
        messages = ' '.join(entry['message'] for entry in job.log_entries)
        self.assertIn(f'Dry run: {counts_text(run.dry_run["counts"])}', messages)
        self.assertNotIn('nothing to do', messages)

    def test_counts_are_written_out(self):
        self.assertEqual(counts_text({'applied': 3, 'failed': 1, 'skipped': 0}), '3 applied, 1 failed')
        self.assertEqual(counts_text({}), 'nothing to do')


class JobProgressTest(ViewBase):
    def setUp(self):
        super().setUp()
        device = Device.objects.create(name='b1', site=self.site, device_type=self.device_type, role=self.role)
        FortiGateBinding.objects.create(name='Branch', device=device, serial='FGT60FTK21005678')
        self.upload(read(BRANCH))
        self.run = ImportRun.objects.get()
        self.url = reverse(URL + 'importrun_job_status', args=[self.run.pk])

    def test_no_job(self):
        self.assertEqual(self.client.get(self.url).json()['active'], False)
        self.assertNotContains(self.client.get(self.run.get_absolute_url()), 'fgi-job')

    def test_running_job_shows_a_loader_that_polls(self):
        with mock.patch('netbox_fortigate_importer.jobs.workers_running', return_value=True):
            self.client.post(reverse(URL + 'importrun_dryrun', args=[self.run.pk]))
        data = self.client.get(self.url).json()
        self.assertEqual((data['active'], data['status']), (True, 'pending'))
        page = self.client.get(self.run.get_absolute_url())
        self.assertContains(page, 'spinner-border')
        self.assertContains(page, f'data-status-url="{self.url}"')
        self.assertContains(page, 'This page refreshes when it is done.')
        self.run.jobs.update(status='completed')
        self.assertEqual(self.client.get(self.url).json()['active'], False)

    def test_needs_view_permission(self):
        self.client.logout()
        self.assertNotEqual(self.client.get(self.url).status_code, 200)
