"""The web pages: upload, device choice, review, decisions."""
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site

from netbox_fortigate_importer import applier, rollback
from netbox_fortigate_importer.models import (
    ActionChoices,
    DecisionChoices,
    FortiGateBinding,
    ImportRun,
    RunStatusChoices,
)

from .utils import BRANCH, encrypt_backup, read

URL = 'plugins:netbox_fortigate_importer:'


@override_settings(LOGIN_REQUIRED=True, EXEMPT_VIEW_PERMISSIONS=['*'])
class ViewBase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.site = Site.objects.create(name='Branch 1', slug='branch-1')
        cls.manufacturer = Manufacturer.objects.create(name='Fortinet', slug='fortinet')
        cls.device_type = DeviceType.objects.create(manufacturer=cls.manufacturer, model='FortiGate-60F',
                                                    slug='fg-60f')
        cls.role = DeviceRole.objects.create(name='Firewall', slug='firewall')
        cls.user = get_user_model().objects.create(username='admin', is_superuser=True)

    def setUp(self):
        self.client.force_login(self.user)

    def upload(self, content, name='branch1.conf', password=None, fetch=True):
        data = {'file': SimpleUploadedFile(name, content)}
        if password is not None:
            data['password'] = password
        headers = {'HTTP_X_REQUESTED_WITH': 'fetch', 'HTTP_ACCEPT': 'application/json'} if fetch else {}
        return self.client.post(reverse(URL + 'importrun_upload'), data, **headers)


class ViewTest(ViewBase):

    def test_upload_page(self):
        response = self.client.get(reverse(URL + 'importrun_upload'))
        self.assertContains(response, 'fgi-drop')

    def test_upload_unknown_firewall_asks_for_the_device(self):
        response = self.upload(read(BRANCH))
        self.assertEqual(response.status_code, 200, response.content)
        run = ImportRun.objects.get()
        self.assertEqual(response.json()['redirect'], reverse(URL + 'importrun_bind', args=[run.pk]))
        self.assertEqual(run.info['hostname'], 'BRANCH1-FW01')
        self.assertEqual(run.status, RunStatusChoices.PARSED)
        self.assertNotIn('R1ZmZGs0b3BsbWl1eXRyZXdxYXNkZmdoamts', str(run.data), 'secrets are never stored')

        page = self.client.get(reverse(URL + 'importrun_bind', args=[run.pk]))
        self.assertEqual(page.status_code, 200)
        response = self.client.post(reverse(URL + 'importrun_bind', args=[run.pk]), {
            'mode': 'new', 'name': 'branch1-fw01', 'site': self.site.pk, 'role': self.role.pk,
        })
        self.assertRedirects(response, run.get_absolute_url(), fetch_redirect_response=False)
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.PLANNED)
        self.assertEqual(run.binding.serial, 'FGT60FTK21005678')
        # Choosing "a new device" writes nothing to NetBox: the device is a
        # planned change like the others.
        self.assertIsNone(run.binding.device)
        self.assertFalse(Device.objects.exists())
        device_change = run.changes.get(key='device')
        self.assertEqual(device_change.action, ActionChoices.CREATE)
        self.assertEqual(device_change.label, 'Device branch1-fw01')
        # The model's device type exists, so it is reused.
        self.assertEqual(run.changes.get(key='device-type/fortigate-60f').action, ActionChoices.ADOPT)

        run.changes.filter(decision=DecisionChoices.PENDING).update(decision=DecisionChoices.APPROVED)
        applier.apply(run, self.user, dry_run=True)
        self.assertFalse(Device.objects.exists(), 'a dry run writes nothing')
        run.refresh_from_db()
        self.assertIsNone(run.binding.device)

        applier.apply(run, self.user)
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.APPLIED, run.error)
        device = run.binding.device
        self.assertEqual((device.name, device.site, device.role), ('branch1-fw01', self.site, self.role))
        self.assertEqual(device.device_type, self.device_type)
        self.assertEqual(device.serial, 'FGT60FTK21005678')
        self.assertTrue(device.interfaces.filter(name='wan1').exists())

        # Rollback removes the device again; the FortiGate keeps how to create it.
        rollback.rollback(run, self.user)
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.ROLLED_BACK, run.error)
        self.assertFalse(Device.objects.exists())
        binding = FortiGateBinding.objects.get(pk=run.binding_id)
        self.assertIsNone(binding.device)
        self.assertEqual(binding.new_device['site'], self.site.pk)

        # The next import of the same firewall plans the device again.
        self.upload(read(BRANCH))
        again = ImportRun.objects.latest('pk')
        self.assertEqual(again.binding, binding)
        self.assertEqual(again.changes.get(key='device').action, ActionChoices.CREATE)

    def test_new_device_type_is_planned_too(self):
        self.upload(read(BRANCH))
        run = ImportRun.objects.get()
        # A model NetBox has no device type for.
        run.data['info']['model_name'] = 'FortiGate-61F'
        run.save()
        self.client.post(reverse(URL + 'importrun_bind', args=[run.pk]), {
            'mode': 'new', 'site': self.site.pk, 'role': self.role.pk,
        })
        run.refresh_from_db()
        self.assertEqual(DeviceType.objects.count(), 1)
        self.assertEqual(run.changes.get(key='device-type/fortigate-61f').action, ActionChoices.CREATE)
        run.changes.filter(decision=DecisionChoices.PENDING).update(decision=DecisionChoices.APPROVED)
        applier.apply(run, self.user)
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.APPLIED, run.error)
        self.assertEqual(run.binding.device.device_type.model, 'FortiGate-61F')
        self.assertEqual(run.binding.device.device_type.manufacturer, self.manufacturer)
        self.assertEqual(run.binding.device.name, 'BRANCH1-FW01')

    def test_new_device_found_in_netbox_is_linked(self):
        # "A new device" whose name and site NetBox already has: adopted, and
        # the FortiGate is linked to it by the apply, not only by the next plan.
        device = Device.objects.create(name='branch1-fw01', site=self.site, device_type=self.device_type,
                                       role=self.role)
        self.upload(read(BRANCH))
        run = ImportRun.objects.get()
        bind = reverse(URL + 'importrun_bind', args=[run.pk])
        self.client.post(bind, {'mode': 'new', 'name': 'branch1-fw01', 'site': self.site.pk, 'role': self.role.pk})
        run.refresh_from_db()
        self.assertEqual(run.changes.get(key='device').action, ActionChoices.ADOPT)
        run.changes.filter(decision=DecisionChoices.PENDING).update(decision=DecisionChoices.APPROVED)
        applier.apply(run, self.user)
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.APPLIED, run.error)
        self.assertEqual(run.binding.device, device)

        # A linked import can't be moved to another FortiGate.
        other = Device.objects.create(name='other', site=self.site, device_type=self.device_type, role=self.role)
        response = self.client.post(bind, {'mode': 'existing', 'device': other.pk})
        self.assertRedirects(response, run.get_absolute_url(), fetch_redirect_response=False)
        self.assertEqual(ImportRun.objects.get(pk=run.pk).binding.device, device)

    def test_choosing_a_device_of_another_serial_warns(self):
        device = Device.objects.create(name='b1', site=self.site, device_type=self.device_type, role=self.role)
        FortiGateBinding.objects.create(name='Branch', device=device, serial='FGT60FTK21000001')
        self.upload(read(BRANCH))
        run = ImportRun.objects.get()
        response = self.client.post(reverse(URL + 'importrun_bind', args=[run.pk]),
                                    {'mode': 'existing', 'device': device.pk}, follow=True)
        self.assertContains(response, 'This device was FortiGate FGT60FTK21000001')

    def test_change_list_has_pages_and_checkboxes(self):
        device = Device.objects.create(name='b1', site=self.site, device_type=self.device_type, role=self.role)
        FortiGateBinding.objects.create(name='Branch', device=device, serial='FGT60FTK21005678')
        self.upload(read(BRANCH))
        run = ImportRun.objects.get()
        shown = run.changes.exclude(action=ActionChoices.NOOP).count()
        self.assertGreater(shown, 25)
        page = self.client.get(run.get_absolute_url() + '?per_page=25')
        self.assertContains(page, f'Showing 1-25 of {shown}')
        self.assertContains(page, 'page=2')
        self.assertContains(page, 'name="pk"', count=25)
        page = self.client.get(run.get_absolute_url() + '?per_page=25&page=2')
        self.assertContains(page, 'name="pk"', count=min(shown - 25, 25))
        # Without the right to decide there is nothing to select.
        run.status = RunStatusChoices.DISCARDED
        run.save()
        self.assertNotContains(self.client.get(run.get_absolute_url()), 'name="pk"')

    def test_known_firewall_goes_straight_to_the_plan(self):
        device = Device.objects.create(name='b1', site=self.site, device_type=self.device_type, role=self.role)
        FortiGateBinding.objects.create(name='Branch', device=device, serial='FGT60FTK21005678')
        response = self.upload(read(BRANCH))
        run = ImportRun.objects.get()
        self.assertEqual(response.json()['redirect'], run.get_absolute_url())
        self.assertEqual(run.status, RunStatusChoices.PLANNED)
        page = self.client.get(run.get_absolute_url())
        self.assertContains(page, 'Interface wan1')
        self.assertContains(page, 'Dry run')

    def test_encrypted_backup_asks_for_the_password(self):
        content = encrypt_backup(BRANCH.read_text(), 'secret!')
        response = self.upload(content)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response.json()['password_required'])
        self.assertFalse(ImportRun.objects.exists())

        response = self.upload(content, password='wrong')
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response.json()['password_required'])

        response = self.upload(content, password='secret!')
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(ImportRun.objects.get().encrypted)

    def test_format6_encrypted_backup_imports(self):
        # FortiOS 7.4.4 (build 2662) and later: the salt + PBKDF2 layout.
        content = encrypt_backup(BRANCH.read_text(), 'secret!', minor=4, build=2662, fmt=6)
        response = self.upload(content)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response.json()['password_required'])

        response = self.upload(content, password='wrong')
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response.json()['password_required'])

        response = self.upload(content, password='secret!')
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(ImportRun.objects.get().encrypted)

    def test_upload_never_touches_the_disk(self):
        with mock.patch('django.core.files.uploadhandler.TemporaryFileUploadHandler.new_file') as temp:
            with self.settings(FILE_UPLOAD_MAX_MEMORY_SIZE=10):
                self.upload(read(BRANCH))
        temp.assert_not_called()
        self.assertTrue(ImportRun.objects.exists())

    def test_error_reports_hide_the_file_and_password(self):
        import sys

        # Made at run time (the report quotes this test's source lines) and
        # kept off this frame's local variables (the report lists them too).
        import uuid

        from django.test import RequestFactory
        from django.views.debug import ExceptionReporter

        from netbox_fortigate_importer.views import ImportRunUploadView

        self.marks = (uuid.uuid4().hex, uuid.uuid4().hex)
        request = RequestFactory().post(reverse(URL + 'importrun_upload'), {
            'file': SimpleUploadedFile('b.conf', BRANCH.read_text().replace('BRANCH1-FW01', self.marks[1]).encode()),
            'password': self.marks[0],
        })
        request.user = self.user
        request._dont_enforce_csrf_checks = True
        with mock.patch('netbox_fortigate_importer.services.load', side_effect=RuntimeError('boom')):
            try:
                ImportRunUploadView.as_view()(request)
            except RuntimeError:
                report = ExceptionReporter(request, *sys.exc_info()).get_traceback_html()
            else:
                self.fail('the error was not raised')
        self.assertIn('boom', report)
        self.assertNotIn(self.marks[0], report, 'the password')
        self.assertNotIn(self.marks[1], report, 'the configuration text')

    def test_not_a_configuration(self):
        response = self.upload(b'\x00\x01\x02binary', name='photo.jpg')
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response.json()['error'])

    def test_plain_form_post_without_javascript(self):
        response = self.upload(b'nonsense', fetch=False)
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, 'fgi-error', status_code=400)

    def test_review_decisions(self):
        device = Device.objects.create(name='b1', site=self.site, device_type=self.device_type, role=self.role)
        FortiGateBinding.objects.create(name='Branch', device=device, serial='FGT60FTK21005678')
        self.upload(read(BRANCH))
        run = ImportRun.objects.get()
        change = run.changes.get(key='interface/wan1')
        response = self.client.post(reverse(URL + 'importrun_decide', args=[run.pk]), {
            'pk': [change.pk], 'decision': DecisionChoices.SKIPPED, 'scope': 'selected',
        })
        self.assertEqual(response.status_code, 302)
        change.refresh_from_db()
        self.assertEqual(change.decision, DecisionChoices.SKIPPED)
        # Everything shown (here: one section) at once.
        self.client.post(reverse(URL + 'importrun_decide', args=[run.pk]), {
            'f_section': 'interface', 'decision': DecisionChoices.APPROVED, 'scope': 'filtered',
        })
        change.refresh_from_db()
        self.assertEqual(change.decision, DecisionChoices.APPROVED)
        self.assertFalse(run.changes.filter(section='interface').exclude(action=ActionChoices.NOOP)
                         .exclude(decision=DecisionChoices.APPROVED).exists())
        self.assertEqual(self.client.get(change.get_absolute_url()).status_code, 200)

    def test_decisions_clear_the_dry_run_and_stay_on_this_site(self):
        device = Device.objects.create(name='b1', site=self.site, device_type=self.device_type, role=self.role)
        FortiGateBinding.objects.create(name='Branch', device=device, serial='FGT60FTK21005678')
        self.upload(read(BRANCH))
        run = ImportRun.objects.get()
        ImportRun.objects.filter(pk=run.pk).update(dry_run={'counts': {'applied': 1}})
        change = run.changes.get(key='interface/wan1')
        response = self.client.post(reverse(URL + 'importrun_decide', args=[run.pk]), {
            'pk': [change.pk], 'decision': DecisionChoices.SKIPPED, 'scope': 'selected',
            'return_url': 'https://evil.example/',
        })
        self.assertRedirects(response, run.get_absolute_url(), fetch_redirect_response=False)
        run.refresh_from_db()
        self.assertEqual(run.dry_run, {})

    def test_list_and_detail_pages(self):
        device = Device.objects.create(name='b1', site=self.site, device_type=self.device_type, role=self.role)
        binding = FortiGateBinding.objects.create(name='Branch', device=device, serial='FGT60FTK21005678')
        self.upload(read(BRANCH))
        for url in (
            reverse(URL + 'importrun_list'), reverse(URL + 'fortigatebinding_list'),
            binding.get_absolute_url(), reverse(URL + 'fortigatebinding_edit', args=[binding.pk]),
            reverse(URL + 'fortigatebinding_add'), device.get_absolute_url(),
            reverse(URL + 'fortigatebinding_changelog', args=[binding.pk]),
        ):
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)

    def test_binding_options_form(self):
        device = Device.objects.create(name='b1', site=self.site, device_type=self.device_type, role=self.role)
        binding = FortiGateBinding.objects.create(name='Branch', device=device)
        response = self.client.post(reverse(URL + 'fortigatebinding_edit', args=[binding.pk]), {
            'name': 'Branch', 'device': device.pk, 'vrf_per_vdom': 'false', 'default_delete_action': 'unmanage',
            'continue_on_error': '',
        })
        self.assertEqual(response.status_code, 302, getattr(response, 'context', None) and
                         response.context['form'].errors)
        binding.refresh_from_db()
        self.assertEqual(binding.options, {'vrf_per_vdom': False, 'default_delete_action': 'unmanage'})


class APITest(ViewBase):
    def test_upload_plan_and_decide(self):
        device = Device.objects.create(name='b1', site=self.site, device_type=self.device_type, role=self.role)
        url = reverse('plugins-api:netbox_fortigate_importer-api:importrun-upload')
        response = self.client.post(url, {'file': SimpleUploadedFile('b.conf', read(BRANCH)), 'device': device.pk})
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.json()['status']['value'], RunStatusChoices.PLANNED)
        run = ImportRun.objects.get()
        change = run.changes.get(key='interface/wan1')
        detail = reverse('plugins-api:netbox_fortigate_importer-api:plannedchange-detail', args=[change.pk])
        response = self.client.patch(detail, {'decision': 'skipped'}, content_type='application/json')
        self.assertEqual(response.status_code, 200, response.content)
        change.refresh_from_db()
        self.assertEqual(change.decision, DecisionChoices.SKIPPED)
        for name in ('fortigatebinding-list', 'importrun-list', 'plannedchange-list'):
            with self.subTest(name=name):
                response = self.client.get(reverse(f'plugins-api:netbox_fortigate_importer-api:{name}'))
                self.assertEqual(response.status_code, 200)

    def test_encrypted_upload_needs_password(self):
        url = reverse('plugins-api:netbox_fortigate_importer-api:importrun-upload')
        content = encrypt_backup(BRANCH.read_text(), 'pw')
        response = self.client.post(url, {'file': SimpleUploadedFile('b.conf', content)})
        self.assertEqual(response.status_code, 400)
        self.assertTrue(response.json()['password_required'])


    def test_run_actions_need_only_their_own_permission(self):
        from core.models import ObjectType
        from users.models import ObjectPermission

        device = Device.objects.create(name='b1', site=self.site, device_type=self.device_type, role=self.role)
        FortiGateBinding.objects.create(name='Branch', device=device, serial='FGT60FTK21005678')
        self.upload(read(BRANCH))
        run = ImportRun.objects.get()
        user = get_user_model().objects.create(username='operator')
        permission = ObjectPermission.objects.create(name='apply runs', actions=['view', 'apply'])
        permission.object_types.add(ObjectType.objects.get_for_model(ImportRun))
        permission.users.add(user)
        self.client.force_login(user)
        url = reverse('plugins-api:netbox_fortigate_importer-api:importrun-dry-run', args=[run.pk])
        with mock.patch('netbox_fortigate_importer.jobs.ImportRunJob.enqueue') as enqueue:
            enqueue.return_value.pk = 1
            enqueue.return_value.get_absolute_url.return_value = '/'
            response = self.client.post(url)
        self.assertEqual(response.status_code, 202, response.content)
        response = self.client.post(reverse('plugins-api:netbox_fortigate_importer-api:importrun-rollback',
                                            args=[run.pk]))
        self.assertEqual(response.status_code, 403, response.content)


class JobTest(ViewBase):
    def test_dry_run_and_apply_jobs(self):
        from netbox_fortigate_importer.jobs import ImportRunJob

        device = Device.objects.create(name='b1', site=self.site, device_type=self.device_type, role=self.role)
        FortiGateBinding.objects.create(name='Branch', device=device, serial='FGT60FTK21005678')
        self.upload(read(BRANCH))
        run = ImportRun.objects.get()
        ImportRunJob.enqueue(instance=run, user=self.user, immediate=True, action='dry-run')
        run.refresh_from_db()
        self.assertIn('applied', run.dry_run['counts'])
        ImportRunJob.enqueue(instance=run, user=self.user, immediate=True, action='apply')
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.APPLIED)
        self.assertEqual(run.jobs.count(), 2)
