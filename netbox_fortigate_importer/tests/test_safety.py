"""Imports respect NetBox permissions, never take other work with them and never race."""
from core.models import ObjectType
from dcim.models import Device, Interface
from django.contrib.auth import get_user_model
from ipam.models import IPAddress
from users.models import ObjectPermission

from netbox_fortigate_importer import applier, planner, rollback, services
from netbox_fortigate_importer.models import FortiGateBinding, OutcomeChoices, RunStatusChoices

from .test_apply import HQ, ImportTestCase, data_of


class PermissionTest(ImportTestCase):
    def user_with(self, *grants):
        """A user with NetBox permissions: (actions, models or None for all, constraints)."""
        user = get_user_model().objects.create(username=f'user{get_user_model().objects.count()}')
        for actions, models, constraints in grants:
            permission = ObjectPermission.objects.create(name=f'p{ObjectPermission.objects.count()}',
                                                         actions=actions, constraints=constraints)
            types = ObjectType.objects.public() if models is None else \
                [ObjectType.objects.get_for_model(m) for m in models]
            permission.object_types.set(types)
            permission.users.add(user)
        return user

    def test_user_without_permissions_writes_nothing(self):
        from extras.models import Tag

        run = self.plan(self.make_binding(), data_of(HQ))
        with self.assertRaisesMessage(applier.ApplyError, 'may not add tag'):
            applier.apply(run, self.user_with((['view'], None, None)))
        applier.apply(run, self.user_with((['view'], None, None), (['add'], [Tag], None)))
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.PLANNED)
        errors = ' '.join(run.changes.filter(outcome=OutcomeChoices.FAILED).values_list('error', flat=True))
        self.assertIn('may not add VRF', errors)
        self.assertFalse(Interface.objects.exists())

    def test_delete_needs_delete_permission(self):
        binding, _ = self.first_import()
        user = self.user_with((['view', 'add', 'change', 'delete'], None, None))
        ObjectPermission.objects.filter(users=user).first().object_types.remove(
            ObjectType.objects.get_for_model(Interface))
        permission = ObjectPermission.objects.create(name='interfaces', actions=['view', 'add', 'change'])
        permission.object_types.set([ObjectType.objects.get_for_model(Interface)])
        permission.users.add(user)

        data = data_of(HQ)
        data['interfaces'] = [i for i in data['interfaces'] if i['name'] != 'port15']
        run = self.plan(binding, data)
        self.approve_all(run)
        applier.apply(run, user)
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.PLANNED)
        self.assertIn('may not delete', run.changes.get(key='interface/port15').error)
        self.assertTrue(Interface.objects.filter(device=binding.device, name='port15').exists())

    def test_constraints_apply(self):
        binding, _ = self.first_import()
        user = self.user_with((['view', 'add', 'change', 'delete'], None, None))
        ObjectPermission.objects.filter(users=user).first().object_types.remove(
            ObjectType.objects.get_for_model(Interface))
        permission = ObjectPermission.objects.create(name='other site', actions=['view', 'change'],
                                                     constraints={'device__site__slug': 'elsewhere'})
        permission.object_types.set([ObjectType.objects.get_for_model(Interface)])
        permission.users.add(user)

        data = data_of(HQ)
        next(i for i in data['interfaces'] if i['name'] == 'wan1')['description'] = 'New circuit'
        run = self.plan(binding, data)
        self.approve_all(run)
        applier.apply(run, user)
        self.assertIn('may not change', run.changes.get(key='interface/wan1').error)
        self.assertNotEqual(Interface.objects.get(device=binding.device, name='wan1').description, 'New circuit')

    def test_rollback_needs_permissions(self):
        _, run = self.first_import()
        with self.assertRaisesMessage(rollback.RollbackError, 'may not'):
            rollback.rollback(run, self.user_with((['view'], None, None)))
        self.assertTrue(Interface.objects.exists())


class CascadeTest(ImportTestCase):
    def add_ip(self, binding, interface, address):
        port = Interface.objects.get(device=binding.device, name=interface)
        return IPAddress.objects.create(address=address, assigned_object=port)

    def test_rollback_refuses_to_delete_later_work(self):
        binding, run = self.first_import()
        self.add_ip(binding, 'port15', '192.0.2.99/24')
        with self.assertRaisesMessage(rollback.RollbackError, '192.0.2.99/24'):
            rollback.rollback(run, self.user)
        self.assertTrue(IPAddress.objects.filter(address='192.0.2.99/24').exists())
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.APPLIED)

    def test_delete_refuses_to_take_unmanaged_objects(self):
        binding, _ = self.first_import()
        self.add_ip(binding, 'port15', '192.0.2.99/24')
        data = data_of(HQ)
        data['interfaces'] = [i for i in data['interfaces'] if i['name'] != 'port15']
        run = self.plan(binding, data)
        self.approve_all(run)
        self.apply(run)
        self.assertEqual(run.status, RunStatusChoices.PLANNED)
        self.assertIn('192.0.2.99/24', run.changes.get(key='interface/port15').error)
        self.assertTrue(Interface.objects.filter(device=binding.device, name='port15').exists())
        self.assertTrue(IPAddress.objects.filter(address='192.0.2.99/24').exists())


class ConcurrencyTest(ImportTestCase):
    def test_no_replan_or_decisions_while_a_job_is_queued(self):
        from netbox_fortigate_importer.jobs import enqueue

        run = self.plan(self.make_binding(), data_of(HQ))
        job = enqueue(run, self.user, 'apply')
        try:
            with self.assertRaisesMessage(planner.PlanError, 'job queued or running'):
                planner.plan(run)
        finally:
            job.delete()
        planner.plan(run)

    def test_apply_refuses_a_plan_made_again(self):
        run = self.plan(self.make_binding(), data_of(HQ))
        seen = run.planned.isoformat()
        planner.plan(run)
        with self.assertRaisesMessage(applier.ApplyError, 'made again'):
            applier.apply(run, self.user, expected_plan=seen)
        applier.apply(run, self.user, expected_plan=run.planned.isoformat())
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.APPLIED)


class MatchTest(ImportTestCase):
    def test_unique_own_hostname_still_matches(self):
        binding = self.make_binding('HQ-FW01')
        binding.hostname = 'HQ-FW01'
        binding.save()
        self.assertEqual(services.find_binding({'hostname': 'hq-fw01'}), binding)
        binding.serial = 'FG100F001'
        binding.save()
        self.assertEqual(services.find_binding({'hostname': 'HQ-FW01'}), binding)
        # A different serial is a different firewall, whatever its name.
        self.assertIsNone(services.find_binding({'hostname': 'HQ-FW01', 'serial': 'FG100F999'}))

    def test_hostname_matches_only_when_unique(self):
        binding = self.make_binding('FortiGate-VM64')
        binding.serial, binding.hostname = 'FGVM01', 'FortiGate-VM64'
        binding.save()
        self.assertEqual(services.find_binding({'serial': 'FGVM01', 'hostname': 'x'}), binding)
        self.assertIsNone(services.find_binding({'serial': 'FGVM02', 'hostname': 'FortiGate-VM64'}))
        self.assertEqual(services.find_binding({'hostname': 'FortiGate-VM64'}), binding)
        twin = self.make_binding('FortiGate-VM64 B')
        twin.hostname = 'FortiGate-VM64'
        twin.save()
        self.assertIsNone(services.find_binding({'hostname': 'FortiGate-VM64'}), 'two have it: the user chooses')
        # Offered for confirmation only when the serial does not contradict it.
        self.assertIn(binding.device, services.candidate_devices({'hostname': 'FortiGate-VM64'}))
        other = Device.objects.create(name='other', site=self.site, device_type=self.device_type, role=self.role)
        FortiGateBinding.objects.create(name='Other', device=other, hostname='FGT60F', serial='FGT60F001')
        self.assertNotIn(other, services.candidate_devices({'hostname': 'FGT60F', 'serial': 'FGT60F002'}))


class IncompleteConfigTest(ImportTestCase):
    def test_truncated_config_removes_nothing(self):
        binding, _ = self.first_import()
        data = data_of(HQ)
        data['interfaces'] = [i for i in data['interfaces'] if i['name'] != 'port15']
        data['warnings'].append('file ends inside "system interface": it may be truncated')
        run = self.plan(binding, data)
        self.assertFalse(run.changes.filter(action__in=('delete', 'deprecate', 'unmanage')).exists())
        self.assertTrue(any('truncated' in note for note in run.summary['notes']))

    def test_missing_vdom_is_left_alone(self):
        binding, _ = self.first_import()
        data = data_of(HQ)
        data['vdoms'].pop('CUST-A')
        data['interfaces'] = [i for i in data['interfaces'] if i['vdom'] != 'CUST-A']
        data['connected'] = [n for n in data['connected'] if n['vdom'] != 'CUST-A']
        run = self.plan(binding, data)
        self.assertFalse(run.changes.filter(vdom='CUST-A', action__in=('delete', 'deprecate', 'unmanage')).exists())
        self.assertTrue(any('VDOM CUST-A is not in this configuration' in n for n in run.summary['notes']))


class AdoptionTest(ImportTestCase):
    def test_addresses_of_another_firewall_are_not_taken_over(self):
        first = self.make_binding('FW-A')
        second = self.make_binding('FW-B')
        for binding in (first, second):
            binding.options = {'vrf_per_vdom': False}
            binding.save()
        data = data_of(HQ)  # one VDOM: no VRFs, the global address space
        data['interfaces'] = [i for i in data['interfaces'] if i['vdom'] != 'CUST-A']
        data['connected'] = [n for n in data['connected'] if n['vdom'] != 'CUST-A']
        self.apply(self.plan(first, data))
        run = self.plan(second, data)
        # Neither taken over nor duplicated (NetBox refuses duplicates
        # outside VRFs): left out, with a note.
        self.assertFalse(run.changes.filter(key='ip/mgmt/192.168.255.10').exists())
        self.assertTrue(any('192.168.255.10' in n and 'fw-a' in n for n in run.summary['notes']),
                        run.summary['notes'])
        self.apply(run)
        self.assertEqual(run.status, RunStatusChoices.APPLIED, run.error)
        self.assertEqual(IPAddress.objects.get(address='192.168.255.10/24').assigned_object.device.name, 'fw-a')


class ReviewTest(ImportTestCase):
    def test_planning_again_keeps_decisions(self):
        binding, _ = self.first_import()
        data = data_of(HQ)
        next(i for i in data['interfaces'] if i['name'] == 'wan1')['description'] = 'New circuit'
        data['interfaces'] = [i for i in data['interfaces'] if i['name'] != 'port15']
        run = self.plan(binding, data)
        run.changes.filter(key='interface/wan1').update(decision='skipped', decided_by=self.user)
        run.changes.filter(key='interface/port15').update(decision='approved', decided_by=self.user)
        planner.plan(run)
        self.assertEqual(run.changes.get(key='interface/wan1').decision, 'skipped')
        self.assertEqual(run.changes.get(key='interface/port15').decision, 'approved')
        self.assertTrue(any('kept from the previous plan' in n for n in run.summary['notes']))

    def test_reference_like_text_is_written_as_text(self):
        data = data_of(HQ)
        next(i for i in data['interfaces'] if i['name'] == 'port15')['description'] = '$ref:interface/wan1'
        binding = self.make_binding()
        run = self.plan(binding, data)
        self.apply(run)
        self.assertEqual(run.status, RunStatusChoices.APPLIED, run.error)
        self.assertEqual(Interface.objects.get(device=binding.device, name='port15').description,
                         '$ref:interface/wan1')
        self.assertEqual(set(self.plan(binding, data).summary['actions']), {'noop'})


class RecordTest(ImportTestCase):
    def test_failed_deferred_fields_keep_the_object_managed(self):
        from unittest import mock

        binding = self.make_binding()
        binding.options = {'continue_on_error': True}
        binding.save()
        run = self.plan(binding, data_of(HQ))
        original = applier.Applier.write

        def write(self, row, deferred=False):
            if deferred and row.key == 'device':
                raise ValueError('no primary IP today')
            return original(self, row, deferred)

        with mock.patch.object(applier.Applier, 'write', write):
            self.apply(run)
        self.assertEqual(run.status, RunStatusChoices.APPLIED)
        self.assertEqual(run.changes.get(key='device').outcome, OutcomeChoices.FAILED)
        managed = binding.managed_objects.get(key='device')
        self.assertNotIn('primary_ip4', managed.fields)
        # The next plan offers the primary IP again.
        row = self.plan(binding, data_of(HQ)).changes.get(key='device')
        self.assertIn('primary_ip4', [d['field'] for d in row.diff])

    def test_rollback_refuses_without_change_log(self):
        from core.models import ObjectChange

        _, run = self.first_import()
        ObjectChange.objects.filter(request_id=run.apply_request_id).delete()
        with self.assertRaisesMessage(rollback.RollbackError, 'change log no longer has'):
            rollback.rollback(run, self.user)


class AdoptedRemovalTest(ImportTestCase):
    def test_adopted_object_is_kept_when_the_firewall_drops_it(self):
        binding = self.make_binding()
        Interface.objects.create(device=binding.device, name='port15', type='1000base-t')
        self.first_import(binding)
        self.assertTrue(binding.managed_objects.get(key='interface/port15').fields['@meta']['adopted'])
        data = data_of(HQ)
        data['interfaces'] = [i for i in data['interfaces'] if i['name'] != 'port15']
        row = self.plan(binding, data).changes.get(key='interface/port15')
        self.assertEqual(row.action, 'unmanage')
        self.assertIn('existed in NetBox before', row.note)


class TruncationFlagTest(ImportTestCase):
    def test_flag_survives_many_warnings(self):
        from netbox_fortigate_importer.extract import load as load_bytes

        text = 'config system global\nset hostname X\nend\n' + 'bogus\n' * 300 + 'config firewall address\nedit a\n'
        data = load_bytes(text.encode())
        self.assertTrue(data['truncated'])
        self.assertFalse(any('may be truncated' in w for w in data['warnings']))
