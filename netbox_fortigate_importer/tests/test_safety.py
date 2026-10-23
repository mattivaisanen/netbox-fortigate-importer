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
    def test_hostname_alone_does_not_pick_the_firewall(self):
        binding = self.make_binding('FortiGate-VM64')
        binding.serial, binding.hostname = 'FGVM01', 'FortiGate-VM64'
        binding.save()
        self.assertEqual(services.find_binding({'serial': 'FGVM01', 'hostname': 'x'}), binding)
        self.assertIsNone(services.find_binding({'serial': 'FGVM02', 'hostname': 'FortiGate-VM64'}))
        self.assertIsNone(services.find_binding({'hostname': 'FortiGate-VM64'}))
        # Offered for confirmation only when the serial does not contradict it.
        self.assertIn(binding.device, services.candidate_devices({'hostname': 'FortiGate-VM64'}))
        other = Device.objects.create(name='other', site=self.site, device_type=self.device_type, role=self.role)
        FortiGateBinding.objects.create(name='Other', device=other, hostname='FGT60F', serial='FGT60F001')
        self.assertNotIn(other, services.candidate_devices({'hostname': 'FGT60F', 'serial': 'FGT60F002'}))
