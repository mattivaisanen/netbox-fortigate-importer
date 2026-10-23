"""With netbox-routing installed: static routes, filters, BGP, OSPF."""
from unittest import skipUnless

from netbox_fortigate_importer import integrations, rollback
from netbox_fortigate_importer.mappers.routing import community_value, prefix_entry_bounds
from netbox_fortigate_importer.models import ActionChoices, OutcomeChoices, RunStatusChoices

from .test_apply import BRANCH, HQ, ImportTestCase, data_of


@skipUnless(integrations.has_routing(), 'netbox-routing is not installed')
class RoutingImportTest(ImportTestCase):
    def models(self):
        from netbox_routing import models

        return models

    def test_helpers(self):
        self.assertEqual(community_value('no-export'), '65535:65281')
        self.assertEqual(community_value('65010:100'), '65010:100')
        self.assertIsNone(community_value('_65010_'))
        # "le 0" on 0.0.0.0/0 is an exact match: no le.
        self.assertEqual(prefix_entry_bounds('0.0.0.0/0', None, 0), (None, None, ''))
        self.assertEqual(prefix_entry_bounds('10.0.0.0/8', 16, 24)[:2], (16, None))

    def test_first_import(self):
        m = self.models()
        binding, run = self.first_import()
        failed = run.changes.exclude(outcome=OutcomeChoices.APPLIED).exclude(error__startswith='rolled back')
        self.assertEqual(list(failed.values_list('key', 'error')), [])
        self.assertEqual(run.status, RunStatusChoices.APPLIED, run.error)
        device = binding.device

        default = m.StaticRoute.objects.get(devices=device, prefix='0.0.0.0/0', vrf__name='HQ-FW01 root')
        self.assertEqual(str(default.next_hop), '203.0.113.9')
        self.assertEqual(default.interface_next_hop, 'wan1')
        self.assertEqual(default.metric, 10)
        sink = m.StaticRoute.objects.get(devices=device, prefix='10.0.0.0/8')
        self.assertEqual((sink.interface_next_hop, sink.metric), ('blackhole', 254))

        rm_in = m.RouteMap.objects.get(name='HQ-FW01 root RM-ISP-IN')
        entry = rm_in.route_map_entries.get(sequence=1)
        self.assertEqual(list(entry.match_prefix_list.values_list('name', flat=True)), ['HQ-FW01 root PL-DEFAULT'])
        self.assertEqual(list(entry.match_aspath.values_list('name', flat=True)), ['HQ-FW01 root AS-ISP-ONLY'])
        self.assertEqual(entry.set, {'local-preference': '200'})
        any_rule = m.PrefixList.objects.get(name='HQ-FW01 root PL-HQ-OUT').prefix_list_entries.get(sequence=2)
        self.assertIsNone(any_rule.assigned_prefix)
        self.assertEqual(m.CommunityListEntry.objects.get().community.community, '65535:65281')
        acl = m.PrefixList.objects.get(name='HQ-FW01 root ACL-MGMT')
        self.assertEqual(str(acl.prefix_list_entries.get().assigned_prefix.prefix), '192.168.255.0/24')

        router = m.BGPRouter.objects.get(asn__asn=65010)
        self.assertEqual(router.assigned_object, device)
        isp = m.BGPPeer.objects.get(peer__address__net_host='203.0.113.9')
        self.assertEqual((isp.name, isp.scope.vrf.name), ('ISP A', 'HQ-FW01 root'))
        # AS 64500 is public and this FortiGate has no RIR for new ASNs: left out, with a note.
        self.assertIsNone(isp.remote_as)
        self.assertIn('AS 64500: set "RIR for new ASNs" on the FortiGate to import it', run.summary['notes'])
        af = m.BGPPeerAddressFamily.objects.get(peer=isp)
        self.assertEqual((af.routemap_in.name, af.routemap_out.name),
                         ('HQ-FW01 root RM-ISP-IN', 'HQ-FW01 root RM-ISP-OUT'))
        branch = m.BGPPeer.objects.get(peer__address__net_host='169.254.10.2')
        self.assertEqual(str(branch.source.address).split('/')[0], '169.254.10.1')

        instance = m.OSPFInstance.objects.get(device=device)
        self.assertEqual(str(instance.router_id), '10.255.255.1')
        vlan20 = m.OSPFInterface.objects.get(interface__device=device, interface__name='vlan20')
        self.assertEqual((vlan20.area.area_id, vlan20.priority, vlan20.authentication),
                         ('0.0.0.0', 100, 'message-digest'))
        self.assertEqual(m.OSPFArea.objects.get(area_id='0.0.0.0').area_type, 'backbone')

    def test_same_import_again_changes_nothing(self):
        binding, _ = self.first_import()
        run = self.plan(binding, data_of(HQ))
        self.assertEqual(list(run.changes.exclude(action=ActionChoices.NOOP).values_list('key', 'action')), [])

    def test_route_change_and_removal(self):
        m = self.models()
        binding, _ = self.first_import()
        data = data_of(HQ)
        routes = data['vdoms']['root']['static_routes']
        routes[0]['gateway'] = '203.0.113.10'
        gone = routes.pop(1)
        run = self.plan(binding, data)
        self.assertEqual(run.changes.get(key='rt/root/static4/1').action, ActionChoices.UPDATE)
        self.assertEqual(run.changes.get(key=f'rt/root/static4/{gone["seq"]}').action, ActionChoices.DELETE)
        self.approve_all(run)
        self.apply(run)
        self.assertEqual(run.status, RunStatusChoices.APPLIED, run.error)
        self.assertEqual(str(m.StaticRoute.objects.get(prefix='0.0.0.0/0', devices=binding.device,
                                                       vrf__name='HQ-FW01 root').next_hop), '203.0.113.10')
        self.assertFalse(m.StaticRoute.objects.filter(prefix='10.0.0.0/8').exists())

    def test_two_firewalls_share_global_objects(self):
        m = self.models()
        self.first_import()
        _, run = self.first_import(self.make_binding('BR1-FW01'), BRANCH)
        self.assertEqual(run.status, RunStatusChoices.APPLIED, run.error)
        self.assertEqual(m.BGPRouter.objects.count(), 2)

    def test_rollback_removes_everything(self):
        m = self.models()
        _, run = self.first_import()
        rollback.rollback(run, self.user)
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.ROLLED_BACK, run.error)
        for model in (m.StaticRoute, m.PrefixList, m.RouteMap, m.BGPRouter, m.BGPPeer, m.OSPFInstance,
                      m.OSPFArea, m.Community, m.CustomPrefix):
            self.assertFalse(model.objects.exists(), model.__name__)

    def test_unreadable_prefix_never_widens_a_list(self):
        data = data_of(HQ)
        rules = next(p for p in data['vdoms']['root']['prefix_lists'] if p['name'] == 'PL-HQ-OUT')['rules']
        rules[0]['prefix'] = None  # a permit: left out
        rules.append({'id': 3, 'action': 'deny', 'prefix': None, 'ge': None, 'le': None})  # deny: denies all
        run = self.plan(self.make_binding(), data)
        keys = set(run.changes.values_list('key', flat=True))
        entries = [k for k in keys if 'prefix-list/PL-HQ-OUT/' in k]
        self.assertEqual(sorted(e.rsplit('/', 1)[1] for e in entries), ['2', '3'])
        deny = run.changes.get(key=next(e for e in entries if e.endswith('/3')))
        self.assertIsNone(deny.proposed['fields']['assigned_prefix_id'])
        self.assertEqual(deny.proposed['fields']['action'], 'deny')
        self.assertTrue(any('cannot be read' in n for n in run.summary['notes']))
