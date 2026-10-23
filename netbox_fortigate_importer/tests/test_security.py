"""With netbox-security installed: addresses, services, zones, policies, NAT."""
from unittest import skipUnless

from netbox_fortigate_importer import integrations, rollback
from netbox_fortigate_importer.mappers.security import expand_ports, range_networks
from netbox_fortigate_importer.models import ActionChoices, OutcomeChoices, RunStatusChoices

from .test_apply import BRANCH, HQ, ImportTestCase, data_of


def vdom(data, name='root'):
    return data['vdoms'][name]


@skipUnless(integrations.has_security(), 'netbox-security is not installed')
class SecurityImportTest(ImportTestCase):
    def models(self):
        from netbox_security import models

        return models

    def test_helpers(self):
        self.assertEqual(range_networks('10.0.0.4', '10.0.0.7'), ['10.0.0.4/30'])
        self.assertEqual(range_networks('10.0.0.1', '10.0.0.2'), ['10.0.0.1/32', '10.0.0.2/32'])
        self.assertEqual(expand_ports([{'low': 80, 'high': 81}]), [80, 81])
        self.assertIsNone(expand_ports([{'low': 1024, 'high': 65535}]))

    def test_first_import(self):
        m = self.models()
        binding, run = self.first_import()
        self.assertEqual(run.status, RunStatusChoices.APPLIED, run.error)
        self.assertEqual(list(run.changes.exclude(outcome=OutcomeChoices.APPLIED).values_list('key', 'error')), [])
        scope = 'HQ-FW01 root'

        users = m.Address.objects.get(name='NET-USERS', identifier=scope)
        self.assertEqual(str(users.assigned_object.prefix), '10.10.10.0/24')
        self.assertEqual(m.Address.objects.get(name='FQDN-UPDATES', identifier=scope).dns_name,
                         'updates.vendor.example')
        # A range that is not one subnet: a set of the subnets covering it.
        dhcp_range = m.AddressSet.objects.get(name='R-DHCP-POOL', identifier=scope)
        self.assertEqual(dhcp_range.addresses.count(), len(range_networks('10.10.10.100', '10.10.10.199')))
        # Nested groups.
        all_sites = m.AddressSet.objects.get(name='GRP-ALL-SITES', identifier=scope)
        self.assertEqual(list(all_sites.address_sets.values_list('name', flat=True)), ['GRP-INTERNAL'])
        # Two VDOMs with the same subnet share one custom prefix.
        self.assertEqual(m.CustomPrefix.objects.filter(prefix='10.10.10.0/24').count(), 1)

        https = m.Application.objects.get(name='HTTPS', identifier=scope)
        self.assertEqual(https.protocol, ['TCP', 'UDP'])
        self.assertEqual(https.destination_ports, [443])
        web = m.ApplicationSet.objects.get(name='WEB', identifier=scope)
        self.assertEqual(sorted(web.applications.values_list('name', flat=True)), ['HTTP', 'HTTPS'])

        inside = m.SecurityZone.objects.get(name='INSIDE', identifier=scope)
        self.assertTrue(inside.allow_intra_zone)
        self.assertEqual(
            sorted(a.assigned_object.name for a in m.SecurityZoneAssignment.objects.filter(zone=inside)),
            ['vlan10', 'vlan20'])

        policy = m.SecurityZonePolicy.objects.get(name='users-to-internet', identifier=scope)
        self.assertEqual((policy.source_zone.name, policy.destination_zone.name), ('INSIDE', 'wan1'))
        self.assertEqual(policy.index, 1)
        self.assertEqual(policy.policy_actions, ['permit', 'log'])
        self.assertEqual(list(policy.source_address.values_list('name', flat=True)), ['GRP-INTERNAL (source)'])
        self.assertEqual(list(policy.destination_address.values_list('name', flat=True)), ['all (destination)'])
        self.assertEqual(list(policy.application_sets.values_list('name', flat=True)), ['WEB'])
        # A policy to a VIP points at the server behind it.
        to_web = m.SecurityZonePolicy.objects.get(name='internet-to-web', identifier=scope)
        target = to_web.destination_address.get().assigned_object
        self.assertEqual(str(target.assigned_object.prefix), '172.16.50.10/32')

        pool = m.NatPool.objects.get(name='HQ-FW01 root POOL-WAN1')
        member = m.NatPoolMember.objects.get(pool=pool)
        self.assertEqual(str(member.prefix.prefix), '203.0.113.12/31')
        dnat = m.NatRule.objects.get(rule_set__name='HQ-FW01 root destination NAT', name='VIP-WEB01-HTTPS')
        self.assertEqual(dnat.destination_ports, [443])
        self.assertEqual(str(dnat.destination_prefixes.get().prefix), '203.0.113.11/32')
        self.assertEqual(m.NatPoolMember.objects.get(pool=dnat.destination_pool).destination_ports, [8443])
        snat = m.NatRule.objects.get(rule_set__name='HQ-FW01 root source NAT', name='Policy 1')
        self.assertEqual(snat.pool, pool)
        cust = m.NatRule.objects.get(rule_set__name='HQ-FW01 CUST-A source NAT', name='Policy 1')
        self.assertEqual(cust.custom_interface, 'interface')
        assignment = m.NatRuleSetAssignment.objects.get(ruleset=dnat.rule_set)
        self.assertEqual(assignment.assigned_object.name, 'root')

    def test_same_import_again_changes_nothing(self):
        binding, _ = self.first_import()
        run = self.plan(binding, data_of(HQ))
        changed = run.changes.exclude(action=ActionChoices.NOOP).values_list('key', 'action')
        self.assertEqual(list(changed), [])

    def test_policy_change_and_removal(self):
        m = self.models()
        binding, _ = self.first_import()
        data = data_of(HQ)
        policies = vdom(data)['policies']
        policies[0]['action'] = 'deny'
        removed = policies.pop(1)
        run = self.plan(binding, data)
        key = 'sec/root/policy/1/INSIDE/wan1'
        self.assertEqual(run.changes.get(key=key).action, ActionChoices.UPDATE)
        gone = run.changes.get(key=f'sec/root/policy/{removed["id"]}/wan1/dmz')
        self.assertEqual(gone.action, ActionChoices.DELETE)
        self.approve_all(run)
        self.apply(run)
        self.assertEqual(run.status, RunStatusChoices.APPLIED, run.error)
        self.assertEqual(m.SecurityZonePolicy.objects.get(name='users-to-internet').policy_actions, ['deny', 'log'])
        self.assertFalse(m.SecurityZonePolicy.objects.filter(name=removed['name']).exists())
        # The later policies moved up one place.
        self.assertEqual(m.SecurityZonePolicy.objects.filter(index=len(policies) + 1).count(), 0)

    def test_two_firewalls_keep_their_own_objects(self):
        m = self.models()
        self.first_import()
        branch = self.make_binding('BR1-FW01')
        _, run = self.first_import(branch, BRANCH)
        self.assertEqual(run.status, RunStatusChoices.APPLIED, run.error)
        self.assertEqual(sorted(m.Address.objects.filter(name='all').values_list('identifier', flat=True)),
                         ['BR1-FW01', 'HQ-FW01 CUST-A', 'HQ-FW01 root'])

    def test_rollback_removes_everything(self):
        m = self.models()
        binding, run = self.first_import()
        rollback.rollback(run, self.user)
        run.refresh_from_db()
        self.assertEqual(run.status, RunStatusChoices.ROLLED_BACK, run.error)
        for model in (m.Address, m.AddressSet, m.AddressList, m.Application, m.SecurityZone,
                      m.SecurityZonePolicy, m.NatPool, m.NatRule, m.CustomPrefix):
            self.assertFalse(model.objects.exists(), model.__name__)
