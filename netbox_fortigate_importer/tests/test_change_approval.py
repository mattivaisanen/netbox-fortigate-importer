"""With netbox-change-approval installed: imports follow its approvals."""
from unittest import skipUnless

from django.contrib.auth import get_user_model

from dcim.models import Interface

from netbox_fortigate_importer import applier, integrations, rollback
from netbox_fortigate_importer.models import ManagedObject, OutcomeChoices, RunStatusChoices

from .test_apply import HQ, ImportTestCase, data_of, interface


@skipUnless(integrations.has_change_approval(), 'netbox-change-approval is not installed')
class ChangeApprovalTest(ImportTestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        from users.models import Group

        Group.objects.get_or_create(name='Change Approvers')
        cls.engineer = get_user_model().objects.create(username='engineer')
        # May change everything in NetBox, but has no approval bypass.
        from core.models import ObjectType
        from users.models import ObjectPermission

        permission = ObjectPermission.objects.create(name='engineer', actions=['view', 'add', 'change', 'delete'])
        permission.object_types.set(ObjectType.objects.public())
        permission.users.add(cls.engineer)

    def delta_run(self, binding):
        data = data_of(HQ)
        interface(data, 'wan1')['description'] = 'New circuit'
        data['interfaces'] = [i for i in data['interfaces'] if i['name'] != 'port15']
        run = self.plan(binding, data)
        self.approve_all(run)
        applier.apply(run, self.engineer)
        run.refresh_from_db()
        return run

    def test_failed_apply_leaves_nothing_waiting(self):
        from netbox_change_approval.models import ChangeRequest

        from unittest import mock

        binding, _ = self.first_import()
        data = data_of(HQ)
        interface(data, 'wan1')['description'] = 'New circuit'
        interface(data, 'port1')['description'] = 'Fails'
        run = self.plan(binding, data)
        self.approve_all(run)
        original = applier.Applier.write

        def write(self, row, deferred=False):
            if row.key == 'interface/port1':
                raise ValueError('NetBox refuses it')  # the whole apply rolls back
            return original(self, row, deferred)

        with mock.patch.object(applier.Applier, 'write', write):
            applier.apply(run, self.engineer)
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.PLANNED)
        self.assertEqual(run.changes.get(key='interface/port1').outcome, OutcomeChoices.FAILED)
        self.assertEqual(run.changes.get(key='interface/wan1').outcome, OutcomeChoices.SKIPPED)
        self.assertFalse(ChangeRequest.objects.exists())

    def test_rejected_deferred_fields_keep_the_object(self):
        # Only the primary IP waited for approval; the device itself was written.
        from types import SimpleNamespace

        from netbox_change_approval.models import StatusChoices

        from netbox_fortigate_importer.integrations.change_approval import request_saved

        binding, run = self.first_import()
        run.changes.filter(key='device').update(outcome=OutcomeChoices.SUBMITTED, change_request_id=4242)
        request_saved(None, SimpleNamespace(pk=4242, status=StatusChoices.REJECTED))
        self.assertEqual(run.changes.get(key='device').outcome, OutcomeChoices.REJECTED)
        self.assertTrue(ManagedObject.objects.filter(binding=binding, key='device').exists())

    def test_superuser_import_needs_no_approval(self):
        _, run = self.first_import()
        self.assertEqual(run.status, RunStatusChoices.APPLIED)
        self.assertIsNone(run.change_set_id)

    def test_changes_wait_for_approval(self):
        from netbox_change_approval.models import ChangeRequest, ChangeSet, StatusChoices

        binding, _ = self.first_import()
        run = self.delta_run(binding)
        self.assertEqual(run.status, RunStatusChoices.PENDING_APPROVAL, run.error)
        update = run.changes.get(key='interface/wan1')
        delete = run.changes.get(key='interface/port15')
        self.assertEqual((update.outcome, delete.outcome), (OutcomeChoices.SUBMITTED, OutcomeChoices.SUBMITTED))
        self.assertEqual(Interface.objects.get(device=binding.device, name='wan1').description,
                         'Primary uplink to ISP A')
        self.assertTrue(Interface.objects.filter(device=binding.device, name='port15').exists())

        change_set = ChangeSet.objects.get(pk=run.change_set_id)
        self.assertEqual(change_set.status, ChangeSet.SUBMITTED)
        self.assertEqual(change_set.requests().filter(status=StatusChoices.PENDING).count(), 2)

        ChangeRequest.objects.get(pk=update.change_request_id).apply(self.user)
        ChangeRequest.objects.get(pk=delete.change_request_id).apply(self.user)
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.APPLIED)
        self.assertEqual(Interface.objects.get(device=binding.device, name='wan1').description, 'New circuit')
        self.assertFalse(ManagedObject.objects.filter(binding=binding, key='interface/port15').exists())

    def test_rejected_change_is_proposed_again(self):
        from netbox_change_approval.models import ChangeRequest

        binding, _ = self.first_import()
        run = self.delta_run(binding)
        update = run.changes.get(key='interface/wan1')
        ChangeRequest.objects.get(pk=update.change_request_id).reject(self.user, 'not now')
        update.refresh_from_db()
        self.assertEqual(update.outcome, OutcomeChoices.REJECTED)
        data = data_of(HQ)
        interface(data, 'wan1')['description'] = 'New circuit'
        self.assertEqual(self.plan(binding, data).changes.get(key='interface/wan1').action, 'update')

    def test_rollback_withdraws_pending_requests(self):
        from netbox_change_approval.models import ChangeRequest, StatusChoices

        binding, _ = self.first_import()
        run = self.delta_run(binding)
        rollback.rollback(run, self.engineer)
        update = run.changes.get(key='interface/wan1')
        self.assertEqual(ChangeRequest.objects.get(pk=update.change_request_id).status, StatusChoices.RETRACTED)

    def test_dry_run_shows_what_would_wait_for_approval(self):
        from netbox_change_approval.models import ChangeRequest, ChangeSet

        binding, _ = self.first_import()
        data = data_of(HQ)
        interface(data, 'wan1')['description'] = 'New circuit'
        run = self.plan(binding, data)
        self.approve_all(run)
        applier.apply(run, self.engineer, dry_run=True)
        run.refresh_from_db()
        self.assertEqual(run.dry_run['items']['interface/wan1']['outcome'], OutcomeChoices.SUBMITTED)
        self.assertFalse(ChangeSet.objects.exists())
        self.assertFalse(ChangeRequest.objects.exists())

    def test_rollback_keeps_tracking_changes_approved_later(self):
        from netbox_change_approval.models import ChangeRequest

        binding, _ = self.first_import()
        run = self.delta_run(binding)
        update = run.changes.get(key='interface/wan1')
        ChangeRequest.objects.get(pk=update.change_request_id).apply(self.user)
        rollback.rollback(run, self.engineer)
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.ROLLED_BACK)
        self.assertIn('approved', run.error)
        self.assertEqual(Interface.objects.get(device=binding.device, name='wan1').description, 'New circuit')
        managed = ManagedObject.objects.get(binding=binding, key='interface/wan1')
        self.assertEqual(managed.fields['description'], 'New circuit')

    def test_approved_deprecation_stops_managing(self):
        from netbox_change_approval.models import ChangeRequest

        binding, _ = self.first_import()
        binding.options = {'default_delete_action': 'deprecate'}
        binding.save()
        data = data_of(HQ)
        interface(data, 'vlan10')['secondary_ips'] = []
        run = self.plan(binding, data)
        row = run.changes.get(action='deprecate')
        self.approve_all(run)
        applier.apply(run, self.engineer)
        row.refresh_from_db()
        self.assertEqual(row.outcome, OutcomeChoices.SUBMITTED, row.error)
        ChangeRequest.objects.get(pk=row.change_request_id).apply(self.user)
        self.assertFalse(ManagedObject.objects.filter(binding=binding, key=row.key).exists())
