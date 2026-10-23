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
