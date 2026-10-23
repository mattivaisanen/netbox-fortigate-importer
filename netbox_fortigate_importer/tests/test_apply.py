"""Planning, applying, dry runs and rollback against a real NetBox database."""
import copy
import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase

from core.models import ObjectChange
from dcim.models import Device, DeviceRole, DeviceType, Interface, Manufacturer, Site, VirtualDeviceContext
from ipam.models import VLAN, VRF, IPAddress, IPRange, Prefix
from vpn.models import Tunnel, TunnelTermination

from netbox_fortigate_importer import applier, planner, rollback
from netbox_fortigate_importer.extract import load
from netbox_fortigate_importer.models import (
    ActionChoices, DecisionChoices, FortiGateBinding, ImportRun, ManagedObject, OutcomeChoices, RunStatusChoices,
)

from .utils import ALL_FULL_CONFIGS, BRANCH, HQ, read

_DATA = {}


def data_of(path):
    if path not in _DATA:
        _DATA[path] = load(read(path))
    return copy.deepcopy(_DATA[path])


def interface(data, name):
    return next(i for i in data['interfaces'] if i['name'] == name)


class ImportTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.site = Site.objects.create(name='HQ', slug='hq')
        cls.fortinet = Manufacturer.objects.create(name='Fortinet', slug='fortinet')
        cls.device_type = DeviceType.objects.create(manufacturer=cls.fortinet, model='FortiGate-100F', slug='fg-100f')
        cls.role = DeviceRole.objects.create(name='Firewall', slug='firewall')
        cls.user = get_user_model().objects.create(username='importer', is_superuser=True)

    def make_binding(self, name='HQ-FW01', site=None):
        device = Device.objects.create(
            name=name.lower(), site=site or self.site, device_type=self.device_type, role=self.role,
        )
        return FortiGateBinding.objects.create(name=name, device=device)

    def make_run(self, binding, data):
        return ImportRun.objects.create(binding=binding, data=data, created_by=self.user)

    def plan(self, binding, data):
        run = self.make_run(binding, data)
        planner.plan(run)
        run.refresh_from_db()
        return run

    def apply(self, run, dry_run=False):
        results = applier.apply(run, self.user, dry_run=dry_run)
        run.refresh_from_db()
        return results

    def edit_in_netbox(self, obj, **values):
        """Change an object the way a person does: signed in, with a change log entry."""
        from utilities.request import apply_request_processors

        with apply_request_processors(applier.fake_request(self.user, uuid.uuid4())):
            obj.snapshot()
            for name, value in values.items():
                setattr(obj, name, value)
            obj.full_clean()
            obj.save()

    def approve_all(self, run):
        run.changes.filter(decision=DecisionChoices.PENDING).update(decision=DecisionChoices.APPROVED)

    def first_import(self, binding=None, path=HQ):
        binding = binding or self.make_binding()
        run = self.plan(binding, data_of(path))
        self.apply(run)
        return binding, run


class FirstImportTest(ImportTestCase):
    def test_plan_creates_and_needs_no_review(self):
        run = self.plan(self.make_binding(), data_of(HQ))
        self.assertEqual(run.status, RunStatusChoices.PLANNED)
        actions = run.summary['actions']
        adopted = set(run.changes.filter(action=ActionChoices.ADOPT).values_list('key', flat=True))
        self.assertEqual(adopted, {'device', 'manufacturer/fortinet'})
        self.assertGreater(actions['create'], 70)
        self.assertEqual(run.summary['pending'], 0)
        keys = set(run.changes.values_list('key', flat=True))
        for key in ('vdc/root', 'vdc/CUST-A', 'vrf/root', 'vlan/10', 'interface/vlan10', 'ip/mgmt/192.168.255.10',
                    'fhrp/vlan20/20/vip', 'vpn/tunnel/IPsec 198.51.100.20 - 203.0.113.10'):
            self.assertIn(key, keys)
        self.assertEqual(IPAddress.objects.count(), 0, 'planning writes nothing')

    def test_apply_writes_netbox_objects(self):
        binding, run = self.first_import()
        self.assertEqual(run.status, RunStatusChoices.APPLIED, run.error)
        self.assertFalse(run.changes.exclude(outcome=OutcomeChoices.APPLIED).exists())
        device = Device.objects.get(pk=binding.device_id)

        self.assertEqual(device.platform.slug, 'fortios')
        self.assertEqual(device.platform.manufacturer, self.fortinet)
        self.assertEqual(device.serial, 'FG100FTK20001234')
        self.assertEqual(device.local_context_data['fortigate']['firmware'], '7.4.3')
        self.assertEqual(str(device.primary_ip4.address), '192.168.255.10/24')
        self.assertEqual(device.virtual_chassis.name, 'HQ-FW-HA')
        self.assertEqual(device.virtual_chassis.master, device)

        vlan10 = Interface.objects.get(device=device, name='vlan10')
        self.assertEqual(vlan10.parent.name, 'lacp-core')
        self.assertEqual(vlan10.untagged_vlan.vid, 10)
        self.assertEqual(vlan10.label, 'USERS')
        self.assertEqual(list(vlan10.vdcs.values_list('name', flat=True)), ['root'])
        self.assertEqual(vlan10.vrf.name, 'HQ-FW01 root')
        lag = Interface.objects.get(device=device, name='lacp-core')
        self.assertEqual(lag.type, 'lag')
        self.assertEqual(sorted(lag.member_interfaces.values_list('name', flat=True)), ['x1', 'x2'])
        self.assertEqual(sorted(lag.tagged_vlans.values_list('vid', flat=True)), [10, 20, 100])
        self.assertEqual(Interface.objects.get(device=device, name='port1').bridge.name, 'lan')
        self.assertEqual(Interface.objects.get(device=device, name='x1').type, '10gbase-x-sfpp')

        self.assertEqual(VirtualDeviceContext.objects.filter(device=device).count(), 2)
        # The same address in two VDOMs: two IPs, one per VDOM's VRF.
        self.assertEqual(IPAddress.objects.filter(address='10.10.10.1/24').count(), 2)
        self.assertTrue(Prefix.objects.filter(prefix='10.10.10.0/24', vrf__name='HQ-FW01 CUST-A').exists())
        self.assertEqual(IPRange.objects.get().size, 100)
        self.assertEqual(IPAddress.objects.get(address='10.10.10.50/24').status, 'dhcp')
        vip = IPAddress.objects.get(address='10.20.0.1/24')
        self.assertEqual(vip.role, 'vrrp')
        self.assertEqual(vip.assigned_object.group_id, 20)

        tunnel = Tunnel.objects.get()
        self.assertEqual(tunnel.encapsulation, 'ipsec-tunnel')
        self.assertEqual(tunnel.ipsec_profile.ike_policy.proposals.count(), 4)
        termination = TunnelTermination.objects.get()
        self.assertEqual(termination.termination.name, 'to-branch1')
        self.assertEqual(str(termination.outside_ip.address), '203.0.113.10/29')

        self.assertTrue(vlan10.tags.filter(slug='fortigate-import').exists())
        changes = ObjectChange.objects.filter(request_id=run.apply_request_id)
        self.assertGreater(changes.count(), 70)
        self.assertEqual({c.user_id for c in changes}, {self.user.pk})
        self.assertTrue(all(c.message.startswith('FortiGate import') for c in changes))
        self.assertEqual(ManagedObject.objects.filter(binding=binding).count(), run.changes.count())

    def test_same_file_again_changes_nothing(self):
        binding, _ = self.first_import()
        run = self.plan(binding, data_of(HQ))
        self.assertEqual(set(run.summary['actions']), {'noop'})

    def test_existing_interfaces_are_adopted(self):
        binding = self.make_binding()
        Interface.objects.create(device=binding.device, name='port1', type='1000base-t')
        run = self.plan(binding, data_of(HQ))
        change = run.changes.get(key='interface/port1')
        self.assertEqual(change.action, ActionChoices.ADOPT)
        self.assertEqual(change.decision, DecisionChoices.APPROVED, 'only fills in blank fields')
        self.apply(run)
        self.assertEqual(Interface.objects.filter(device=binding.device, name='port1').count(), 1)

    def test_other_configurations_apply_cleanly(self):
        site = Site.objects.create(name='Other', slug='other')
        for index, path in enumerate(ALL_FULL_CONFIGS):
            with self.subTest(path=path.name):
                binding = self.make_binding(name=f'FW{index}', site=site)
                run = self.plan(binding, data_of(path))
                results = self.apply(run, dry_run=True)
                failed = {k: v for k, v in results.items() if v['outcome'] != OutcomeChoices.APPLIED}
                self.assertEqual(failed, {})


class DeltaTest(ImportTestCase):
    def test_firewall_change_is_an_update_to_review(self):
        binding, _ = self.first_import()
        data = data_of(HQ)
        interface(data, 'wan1')['description'] = 'Uplink to ISP A (new circuit)'
        run = self.plan(binding, data)
        change = run.changes.get(key='interface/wan1')
        self.assertEqual(change.action, ActionChoices.UPDATE)
        self.assertEqual(change.decision, DecisionChoices.PENDING)
        self.assertEqual([d['field'] for d in change.diff], ['description'])
        self.approve_all(run)
        self.apply(run)
        self.assertEqual(Interface.objects.get(device=binding.device, name='wan1').description,
                         'Uplink to ISP A (new circuit)')

    def test_netbox_edit_is_kept_when_firewall_unchanged(self):
        binding, _ = self.first_import()
        wan1 = Interface.objects.get(device=binding.device, name='wan1')
        self.edit_in_netbox(wan1, description='Edited in NetBox')
        run = self.plan(binding, data_of(HQ))
        change = run.changes.get(key='interface/wan1')
        self.assertEqual(change.action, ActionChoices.NOOP)
        self.assertTrue(change.diff[0]['netbox_edited'])
        self.apply(run)
        wan1.refresh_from_db()
        self.assertEqual(wan1.description, 'Edited in NetBox')

    def test_both_changed_is_a_conflict(self):
        binding, _ = self.first_import()
        wan1 = Interface.objects.get(device=binding.device, name='wan1')
        self.edit_in_netbox(wan1, description='Edited in NetBox')
        data = data_of(HQ)
        interface(data, 'wan1')['description'] = 'Changed on the firewall'
        interface(data, 'wan1')['mtu'] = 1492
        run = self.plan(binding, data)
        change = run.changes.get(key='interface/wan1')
        self.assertEqual(change.action, ActionChoices.CONFLICT)

        # "Keep NetBox": the firewall's other change is still written.
        change.decision = DecisionChoices.KEEP_NETBOX
        change.save()
        self.apply(run)
        wan1.refresh_from_db()
        self.assertEqual((wan1.description, wan1.mtu), ('Edited in NetBox', 1492))
        # And the next import of the same file does not ask again.
        again = self.plan(binding, data)
        self.assertEqual(again.changes.get(key='interface/wan1').action, ActionChoices.NOOP)

    def test_removed_objects_are_deleted_after_review(self):
        binding, _ = self.first_import()
        data = data_of(HQ)
        data['interfaces'] = [i for i in data['interfaces'] if i['name'] != 'dmz']
        data['connected'] = [n for n in data['connected'] if n['interface'] != 'dmz']
        run = self.plan(binding, data)
        deletes = run.changes.filter(action=ActionChoices.DELETE)
        self.assertEqual(set(deletes.values_list('key', flat=True)),
                         {'interface/dmz', 'ip/dmz/172.16.50.1', 'prefix/vrf/root/172.16.50.0/24'})
        self.assertFalse(deletes.exclude(decision=DecisionChoices.PENDING).exists())
        self.approve_all(run)
        self.apply(run)
        self.assertEqual(run.status, RunStatusChoices.APPLIED, run.error)
        self.assertFalse(Interface.objects.filter(device=binding.device, name='dmz').exists())
        self.assertFalse(IPAddress.objects.filter(address='172.16.50.1/24').exists())
        self.assertFalse(ManagedObject.objects.filter(binding=binding, key='interface/dmz').exists())

    def test_reference_data_is_released_not_deleted(self):
        binding, _ = self.first_import()
        data = data_of(HQ)
        data['vdoms']['root']['ipsec_phase1'] = []
        data['vdoms']['root']['ipsec_phase2'] = []
        run = self.plan(binding, data)
        proposal = run.changes.get(key='vpn/ike-proposal/FortiGate IKE aes256-sha256 DH20 psk 86400s')
        self.assertEqual(proposal.action, ActionChoices.UNMANAGE)
        self.assertEqual(run.changes.get(key='vpn/root/to-branch1/ike-policy').action, ActionChoices.DELETE)

    def test_unmanage_setting(self):
        binding, _ = self.first_import()
        binding.options = {'default_delete_action': 'unmanage'}
        binding.save()
        data = data_of(HQ)
        data['interfaces'] = [i for i in data['interfaces'] if i['name'] != 'port15']
        run = self.plan(binding, data)
        change = run.changes.get(key='interface/port15')
        self.assertEqual((change.action, change.decision), (ActionChoices.UNMANAGE, DecisionChoices.APPROVED))
        self.apply(run)
        self.assertTrue(Interface.objects.filter(device=binding.device, name='port15').exists())

    def test_skipped_change_is_left_alone(self):
        binding, _ = self.first_import()
        data = data_of(HQ)
        interface(data, 'wan1')['description'] = 'New'
        run = self.plan(binding, data)
        run.changes.filter(key='interface/wan1').update(decision=DecisionChoices.SKIPPED)
        self.apply(run)
        self.assertEqual(run.changes.get(key='interface/wan1').outcome, OutcomeChoices.SKIPPED)
        self.assertEqual(Interface.objects.get(device=binding.device, name='wan1').description,
                         'Primary uplink to ISP A')
        # Still proposed next time.
        self.assertEqual(self.plan(binding, data).changes.get(key='interface/wan1').action, ActionChoices.UPDATE)


class SafetyTest(ImportTestCase):
    def test_dry_run_writes_nothing(self):
        binding = self.make_binding()
        run = self.plan(binding, data_of(HQ))
        self.apply(run, dry_run=True)
        self.assertEqual(run.status, RunStatusChoices.PLANNED)
        self.assertGreater(run.dry_run['counts']['applied'], 70)
        self.assertEqual(IPAddress.objects.count(), 0)
        self.assertEqual(ManagedObject.objects.count(), 0)
        self.assertEqual(ObjectChange.objects.count(), 0)

    def test_edit_after_planning_stops_the_apply(self):
        binding, _ = self.first_import()
        data = data_of(HQ)
        interface(data, 'wan1')['description'] = 'New'
        interface(data, 'dmz')['description'] = 'New too'
        run = self.plan(binding, data)
        self.approve_all(run)
        wan1 = Interface.objects.get(device=binding.device, name='wan1')
        self.edit_in_netbox(wan1, description='Someone was faster')
        self.apply(run)
        self.assertEqual(run.status, RunStatusChoices.PLANNED)
        self.assertIn('Nothing was applied', run.error)
        change = run.changes.get(key='interface/wan1')
        self.assertEqual(change.outcome, OutcomeChoices.FAILED)
        self.assertIn('plan again', change.error)
        # All or nothing: the other change was not kept either.
        self.assertEqual(Interface.objects.get(device=binding.device, name='dmz').description, '')

    def test_continue_on_error_keeps_the_rest(self):
        binding, _ = self.first_import()
        binding.options = {'continue_on_error': True}
        binding.save()
        data = data_of(HQ)
        interface(data, 'wan1')['description'] = 'New'
        interface(data, 'dmz')['description'] = 'New too'
        run = self.plan(binding, data)
        self.approve_all(run)
        Interface.objects.filter(device=binding.device, name='wan1').update(description='Someone was faster')
        self.apply(run)
        self.assertEqual(run.status, RunStatusChoices.APPLIED)
        self.assertEqual(Interface.objects.get(device=binding.device, name='dmz').description, 'New too')

    def test_older_plan_cannot_be_applied_after_a_newer_import(self):
        binding = self.make_binding()
        old = self.plan(binding, data_of(HQ))
        new = self.plan(binding, data_of(HQ))
        self.apply(new)
        old.refresh_from_db()
        self.assertEqual(old.status, RunStatusChoices.SUPERSEDED)
        with self.assertRaises(applier.ApplyError):
            applier.apply(old, self.user)


class RollbackTest(ImportTestCase):
    def test_rollback_restores_netbox(self):
        binding, run = self.first_import()
        rollback.rollback(run, self.user)
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.ROLLED_BACK)
        self.assertEqual(IPAddress.objects.count(), 0)
        self.assertEqual(Interface.objects.filter(device=binding.device).count(), 0)
        device = Device.objects.get(pk=binding.device_id)
        self.assertIsNone(device.platform)
        self.assertEqual(device.serial, '')
        self.assertEqual(ManagedObject.objects.filter(binding=binding).count(), 0)
        self.assertTrue(ObjectChange.objects.filter(request_id=run.rollback_request_id).exists())

    def test_rollback_of_a_delta_brings_deleted_objects_back(self):
        binding, _ = self.first_import()
        data = data_of(HQ)
        data['interfaces'] = [i for i in data['interfaces'] if i['name'] != 'port15']
        run = self.plan(binding, data)
        self.approve_all(run)
        self.apply(run)
        self.assertFalse(Interface.objects.filter(device=binding.device, name='port15').exists())
        rollback.rollback(run, self.user)
        self.assertTrue(Interface.objects.filter(device=binding.device, name='port15').exists())
        self.assertTrue(ManagedObject.objects.filter(binding=binding, key='interface/port15').exists())
        self.assertEqual(set(self.plan(binding, data_of(HQ)).summary['actions']), {'noop'})

    def test_rollback_refuses_to_overwrite_later_edits(self):
        binding, run = self.first_import()
        wan1 = Interface.objects.get(device=binding.device, name='wan1')
        self.edit_in_netbox(wan1, description='Later edit')
        with self.assertRaises(rollback.RollbackError):
            rollback.rollback(run, self.user)
        self.assertTrue(IPAddress.objects.exists())


class TwoFirewallsTest(ImportTestCase):
    def test_tunnel_between_two_imported_firewalls_is_one_tunnel(self):
        branch_site = Site.objects.create(name='Branch 1', slug='branch-1')
        self.first_import(self.make_binding('HQ-FW01'), HQ)
        branch, run = self.first_import(self.make_binding('BRANCH1-FW01', site=branch_site), BRANCH)
        self.assertEqual(run.changes.get(key='vpn/tunnel/IPsec 198.51.100.20 - 203.0.113.10').action,
                         ActionChoices.ADOPT)
        tunnel = Tunnel.objects.get()
        self.assertEqual(
            sorted(t.termination.device.name for t in tunnel.terminations.all()), ['branch1-fw01', 'hq-fw01'],
        )

    def test_shared_object_is_released_while_another_firewall_manages_it(self):
        branch_site = Site.objects.create(name='Branch 1', slug='branch-1')
        self.first_import(self.make_binding('HQ-FW01'), HQ)
        branch, _ = self.first_import(self.make_binding('BRANCH1-FW01', site=branch_site), BRANCH)
        data = data_of(BRANCH)
        data['vdoms']['root']['ipsec_phase1'] = []
        data['vdoms']['root']['ipsec_phase2'] = []
        run = self.plan(branch, data)
        change = run.changes.get(key='vpn/tunnel/IPsec 198.51.100.20 - 203.0.113.10')
        self.assertEqual(change.action, ActionChoices.UNMANAGE)
        self.assertIn('HQ-FW01', change.note)


class SettingsTest(ImportTestCase):
    def test_single_vrf_when_vrf_per_vdom_is_off(self):
        binding = self.make_binding()
        binding.options = {'vrf_per_vdom': False}
        binding.save()
        data = data_of(HQ)
        # Without VRFs the two VDOMs' identical subnets would clash; drop CUST-A's.
        data['interfaces'] = [i for i in data['interfaces'] if i['vdom'] != 'CUST-A']
        data['connected'] = [n for n in data['connected'] if n['vdom'] != 'CUST-A']
        run = self.plan(binding, data)
        self.assertFalse(run.changes.filter(key__startswith='vrf/').exists())
        self.apply(run)
        self.assertEqual(run.status, RunStatusChoices.APPLIED, run.error)
        self.assertFalse(VRF.objects.exists())

    def test_no_connected_prefixes(self):
        binding = self.make_binding()
        binding.options = {'create_connected_prefixes': False}
        binding.save()
        run = self.plan(binding, data_of(HQ))
        self.assertFalse(run.changes.filter(key__startswith='prefix/').exists())

    def test_vlans_are_grouped_per_firewall(self):
        binding, _ = self.first_import()
        self.assertEqual(sorted(VLAN.objects.filter(group__slug='hq-fw01-vlans').values_list('vid', flat=True)),
                         [10, 20, 100])
