"""Same-file warning, journal entries, the "managed by FortiGate" panel and firewall changes between runs."""
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, override_settings
from django.urls import reverse

from dcim.models import Interface
from extras.models import JournalEntry

from netbox_fortigate_importer import compare, rollback
from netbox_fortigate_importer.models import ImportRun

from .test_apply import ImportTestCase, data_of
from .utils import BRANCH, HQ, encrypt_backup, read

URL = 'plugins:netbox_fortigate_importer:'


class CompareTest(SimpleTestCase):
    def test_firewall_changes(self):
        old = data_of(HQ)
        new = data_of(HQ)
        root = new['vdoms']['root']
        root['policies'][0]['enabled'] = False
        removed = root['addresses'].pop()
        root['static_routes'].append({'seq': 99, 'family': 4, 'dst': '10.99.0.0/16', 'device': 'wan1'})
        new['settings']['dns']['domain'] = 'new.example'
        new['stats']['lines'] += 1

        found = {(s['section'], s['vdom'], e['action'], e['label']): e['fields']
                 for s in compare.compare(old, new) for e in s['entries']}
        policy = root['policies'][0]
        self.assertEqual(found[('Firewall policies', 'root', 'changed', f'#{policy["id"]} {policy["name"]}')],
                         [{'field': 'enabled', 'old': 'yes', 'new': 'no'}])
        self.assertIn(('Addresses', 'root', 'removed', removed['name'] + (' (IPv6)' if removed['family'] == 6 else '')),
                      found)
        self.assertIn(('Static routes', 'root', 'added', '#99 10.99.0.0/16'), found)
        self.assertEqual(found[('Settings', '', 'changed', 'Settings')][0]['field'], 'dns')
        self.assertEqual(len(found), 4, 'stats are not configuration')

        self.assertEqual(compare.compare(old, data_of(HQ)), [])
        self.assertEqual(compare.content_hash(old), compare.content_hash(old | {'stats': new['stats']}))
        self.assertNotEqual(compare.content_hash(old), compare.content_hash(new))


class HistoryTest(ImportTestCase):
    def test_journal_entries_on_apply_and_rollback(self):
        binding, run = self.first_import()
        entry = JournalEntry.objects.get()
        self.assertEqual(entry.assigned_object, binding.device)
        self.assertEqual(entry.kind, 'success')
        self.assertEqual(entry.created_by, self.user)
        self.assertIn(f'import #{run.pk}', entry.comments)
        self.assertIn('created', entry.comments)

        rollback.rollback(run, self.user)
        last = JournalEntry.objects.order_by('pk').last()
        self.assertEqual(JournalEntry.objects.count(), 2, 'rollback keeps the first entry')
        self.assertIn('rolled back', last.comments)

        with self.settings(PLUGINS_CONFIG={'netbox_fortigate_importer': {'journal_entries': False}}):
            run = self.plan(binding, data_of(HQ))
            self.apply(run)
        self.assertEqual(JournalEntry.objects.count(), 2)

    @override_settings(EXEMPT_VIEW_PERMISSIONS=['*'])
    def test_managed_panel_and_firewall_changes(self):
        binding, first = self.first_import()
        self.client.force_login(self.user)
        vlan10 = Interface.objects.get(device=binding.device, name='vlan10')
        page = self.client.get(vlan10.get_absolute_url())
        self.assertContains(page, 'Managed by FortiGate')
        self.assertContains(page, 'interface/vlan10')
        self.assertNotContains(page, 'fgi-edited')
        self.edit_in_netbox(vlan10, description='edited by hand')
        self.assertContains(self.client.get(vlan10.get_absolute_url()), 'fgi-edited')

        page = self.client.get(binding.device.get_absolute_url())
        self.assertContains(page, 'Imported as')
        self.assertContains(page, 'Owned fields')
        self.assertNotContains(page, 'Managed by FortiGate', msg_prefix='one panel on the device')

        data = data_of(HQ)
        data['vdoms']['root']['policies'][0]['enabled'] = False
        second = self.plan(binding, data)
        page = self.client.get(reverse(URL + 'importrun_firewall_changes', args=[second.pk]))
        self.assertContains(page, f'from import #{first.pk} to #{second.pk}')
        self.assertContains(page, 'Firewall policies')
        self.assertContains(page, 'Changed: 1')
        page = self.client.get(reverse(URL + 'importrun_firewall_changes', args=[first.pk]))
        self.assertContains(page, 'first import of this FortiGate')


@override_settings(LOGIN_REQUIRED=True, EXEMPT_VIEW_PERMISSIONS=['*'])
class SameFileTest(ImportTestCase):
    def test_same_configuration_again_is_flagged(self):
        self.client.force_login(self.user)
        url = reverse(URL + 'importrun_upload')
        headers = {'HTTP_X_REQUESTED_WITH': 'fetch', 'HTTP_ACCEPT': 'application/json'}
        self.client.post(url, {'file': SimpleUploadedFile('a.conf', read(BRANCH))}, **headers)
        first = ImportRun.objects.get()
        self.assertNotContains(self.client.get(first.get_absolute_url()), 'Same configuration as import')
        # The same configuration as an encrypted backup: another file, same configuration.
        encrypted = encrypt_backup(BRANCH.read_text(), 'pw')
        response = self.client.post(url, {'file': SimpleUploadedFile('b.conf', encrypted), 'password': 'pw'},
                                    **headers)
        second = ImportRun.objects.exclude(pk=first.pk).get()
        self.assertNotEqual(second.file_sha256, first.file_sha256)
        page = self.client.get(response.json()['redirect'], follow=True)
        self.assertContains(page, f'same configuration as import #{first.pk}')
        self.assertContains(self.client.get(second.get_absolute_url()), f'Same configuration as import #{first.pk}')
