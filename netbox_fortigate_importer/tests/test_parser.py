"""The CLI parser, decryption and secret removal. No database needed."""
import json

from django.test import SimpleTestCase

from netbox_fortigate_importer.extract import extract, load
from netbox_fortigate_importer.parser import (
    DecryptionError, ParseError, PasswordRequired, UnsupportedEncryption, UnsupportedFormat, parse, read_config_bytes,
)
from netbox_fortigate_importer.parser.cli import tokenize_line
from netbox_fortigate_importer.parser.layout import layout

from .utils import ALL_FULL_CONFIGS, AZURE_100D, BATFISH, BRANCH, HQ, XUTILS_MULTI_VDOM, encrypt_backup, read

#: Text that must never survive parsing (fixtures carry fake secrets).
SECRET_MARKERS = ('ENC ', 'psksecret', 'PRIVATE KEY', 'BEGIN CERTIFICATE', 's3cr3t-community',
                  'R1ZmZGs0b3Bs', 'bm90LWEtcmVhbC1wYXNzd29yZA')


class TokenizerTests(SimpleTestCase):

    def test_quotes_and_joins(self):
        tokens, _, _ = tokenize_line('set member "a b" c"d"e \'f\'')
        self.assertEqual(tokens, ['set', 'member', 'a b', 'cde', 'f'])

    def test_escapes(self):
        tokens, _, _ = tokenize_line(r'set comment "say \"hi\" \\ ok"')
        self.assertEqual(tokens, ['set', 'comment', 'say "hi" \\ ok'])

    def test_multiline_quoted_value(self):
        tokens, pos, repaired = tokenize_line('set buffer "line1\nline2"\nnext\n')
        self.assertFalse(repaired)
        self.assertEqual(tokens, ['set', 'buffer', 'line1\nline2'])
        self.assertEqual(tokenize_line('set buffer "line1\nline2"\nnext\n', pos)[0], ['next'])

    def test_stray_quote_is_closed_at_end_of_line(self):
        result = parse('config firewall policy\nedit 1\nset service ""HTTPS" "HTTP"\nset action accept\nnext\nend\n')
        policy = result.root.tables['firewall policy'].entries['1']
        self.assertEqual(policy.values['action'], ['accept'])
        self.assertIn('unbalanced quote', result.warnings[0])

    def test_scripts_stay_text(self):
        # Multi-line scripts look like CLI commands; they must not be run
        # against the tree (they would add objects that do not exist).
        text = (
            'config system automation-action\n'
            '    edit "add-addr"\n'
            '        set action-type cli-script\n'
            '        set script "config firewall address\n'
            'edit injected\n'
            'set subnet 10.66.0.0 255.255.0.0\n'
            'next\n'
            'end"\n'
            '    next\n'
            'end\n'
            'config system auto-script\n'
            '    edit "backup"\n'
            '        set script "config system global\n'
            'set hostname \\"evil\\"\n'
            'end"\n'
            '    next\n'
            'end\n'
            'config firewall address\n'
            '    edit "real"\n'
            '        set subnet 10.1.0.0 255.255.0.0\n'
            '    next\n'
            'end\n'
        )
        result = parse(text)
        self.assertEqual(result.warnings, [])
        self.assertEqual(list(result.root.tables['firewall address'].entries), ['real'])
        self.assertNotIn('system global', result.root.tables)
        # The scripts themselves are dropped like secrets: they can hold anything.
        action = result.root.tables['system automation-action'].entries['add-addr']
        self.assertEqual(action.get('action-type'), 'cli-script')
        self.assertIsNone(action.get('script'))
        self.assertIsNone(result.root.tables['system auto-script'].entries['backup'].get('script'))

    def test_webhook_tokens_are_dropped(self):
        result = parse('config system automation-action\nedit "slack"\nset action-type webhook\n'
                       'set uri "hooks.slack.com/services/T000/B000/XXXX"\nset http-body "{\\"token\\": 1}"\n'
                       'config http-headers\nedit 1\nset key "Authorization"\nset value "Bearer abc"\nnext\nend\n'
                       'next\nend\n')
        action = result.root.tables['system automation-action'].entries['slack']
        self.assertEqual(action.get('action-type'), 'webhook')
        self.assertEqual(set(action.values), {'action-type'})
        self.assertEqual(action.tables['http-headers'].entries['1'].values, {})
        self.assertEqual(result.secrets_removed, 4)

    def test_batfish_replacemsg_escapes(self):
        """Batfish's own expectation for its odd-quoting fixture."""
        result = parse((BATFISH / 'fortios_replacemsg.conf').read_text())
        buffer = result.root.tables['system replacemsg admin pre_admin-disclaimer-text'].values['buffer']
        self.assertEqual(buffer, ['"npre"\'\'\\nabc\\" "\nlastline'])


class ParserTests(SimpleTestCase):

    def test_all_full_configs_parse_cleanly(self):
        # The fortios-xutils sample has one typo (`set service ""HTTPS" "HTTP"`).
        expected = {XUTILS_MULTI_VDOM.name: ['line 3884: unbalanced quote, closed at the end of the line']}
        for path in ALL_FULL_CONFIGS:
            with self.subTest(path=path.name):
                result = parse(read_config_bytes(read(path)))
                self.assertEqual(result.warnings, expected.get(path.name, []))
                self.assertGreater(len(result.root.tables), 1)

    def test_batfish_snippets_parse(self):
        for path in sorted(BATFISH.glob('*.conf')):
            with self.subTest(path=path.name):
                result = parse(path.read_text())
                self.assertIn('system global', result.root.tables)

    def test_rename_and_move(self):
        result = parse((BATFISH / 'rename.conf').read_text())
        services = result.root.tables['firewall service custom'].entries
        self.assertIn('new_service1', services)
        self.assertNotIn('old_service1', services)
        result = parse((BATFISH / 'policy_move.conf').read_text())
        self.assertEqual(list(result.root.tables['firewall policy'].entries), ['5', '1', '2', '4', '3'])

    def test_crlf_bom_and_prompt(self):
        text = '﻿FGT # show full-configuration\r\nconfig system global\r\n    set hostname "x"\r\nend\r\n'
        result = parse(text)
        self.assertEqual(result.root.tables['system global'].values['hostname'], ['x'])
        self.assertEqual(result.warnings, [])

    def test_truncated_file_warns(self):
        result = parse('config system interface\n    edit "port1"\n        set ip 10.0.0.1 255.0.0.0\n')
        self.assertTrue(any('truncated' in w for w in result.warnings))

    def test_not_a_config(self):
        with self.assertRaises(ParseError):
            parse('hello world\nthis is not a firewall\n')

    def test_unset_and_append(self):
        result = parse('config firewall addrgrp\nedit g\nset member a b\nappend member c\nunselect member a\nnext\n'
                       'edit h\nset comment x\nunset comment\nnext\nend\n')
        groups = result.root.tables['firewall addrgrp'].entries
        self.assertEqual(groups['g'].values['member'], ['b', 'c'])
        self.assertNotIn('comment', groups['h'].values)


class SecretTests(SimpleTestCase):

    def test_no_secret_survives_any_fixture(self):
        for path in ALL_FULL_CONFIGS:
            with self.subTest(path=path.name):
                document = json.dumps(load(read(path)))
                for marker in SECRET_MARKERS:
                    self.assertNotIn(marker, document)

    def test_more_secret_keys(self):
        result = parse('config user krb-keytab\nedit k1\nset principal HTTP/fw\nset keytab "abc123"\nnext\nend\n'
                       'config router rip\nconfig interface\nedit port1\nset auth-string "s3cret"\nnext\nend\nend\n')
        self.assertNotIn('keytab', result.root.tables['user krb-keytab'].entries['k1'].values)
        rip_port = result.root.tables['router rip'].tables['interface'].entries['port1']
        self.assertNotIn('auth-string', rip_port.values)
        self.assertEqual(result.secrets_removed, 2)

    def test_secrets_are_counted_not_kept(self):
        result = parse(read_config_bytes(read(HQ)))
        self.assertGreaterEqual(result.secrets_removed, 8)
        ha = result.root.tables['global'].tables['system ha']
        self.assertNotIn('password', ha.values)
        self.assertEqual(ha.values['group-name'], ['HQ-FW-HA'])
        community = result.root.tables['global'].tables['system snmp community'].entries['1']
        self.assertNotIn('name', community.values)


class FileTests(SimpleTestCase):

    def test_encrypted_round_trip(self):
        text = read(BRANCH).decode()
        data = encrypt_backup(text, 'correct horse')
        with self.assertRaises(PasswordRequired) as ctx:
            read_config_bytes(data)
        self.assertEqual(ctx.exception.header['model'], 'FGT60F')
        with self.assertRaises(DecryptionError):
            read_config_bytes(data, 'wrong')
        self.assertEqual(read_config_bytes(data, 'correct horse'), text)

    def test_gzip(self):
        import gzip

        self.assertEqual(read_config_bytes(gzip.compress(read(BRANCH))), read(BRANCH).decode())

    def test_decompression_limit(self):
        import gzip

        bomb = gzip.compress(b'#' * (2 * 1024 * 1024))
        with self.assertRaisesMessage(UnsupportedFormat, 'larger than 1 MB'):
            read_config_bytes(bomb, max_size=1024 * 1024)
        self.assertEqual(len(read_config_bytes(bomb, max_size=3 * 1024 * 1024)), 2 * 1024 * 1024)
        sealed = encrypt_backup('#' * (2 * 1024 * 1024), 'pw')
        with self.assertRaisesMessage(UnsupportedFormat, 'larger than 1 MB'):
            read_config_bytes(sealed, 'pw', max_size=1024 * 1024)

    def test_damaged_gzip(self):
        import gzip

        with self.assertRaisesMessage(UnsupportedFormat, 'damaged'):
            read_config_bytes(gzip.compress(b'config system global\nend\n')[:-12])

    def test_format6_round_trip(self):
        # The salt + PBKDF2 layout of FortiOS 7.2.9+, 7.4.4+ and 7.6+.
        text = read(BRANCH).decode()
        for major, minor, build in ((7, 4, 2662), (7, 2, 1688), (7, 6, 3401), (8, 0, 100)):
            with self.subTest(version=(major, minor, build)):
                data = encrypt_backup(text, 'pw', major=major, minor=minor, build=build, fmt=6)
                self.assertEqual(read_config_bytes(data, 'pw'), text)
                with self.assertRaises(DecryptionError):
                    read_config_bytes(data, 'wrong')

    def test_both_formats_decrypt_regardless_of_header_version(self):
        # The header's format field picks which layout to try first, but a
        # mismatched version still decrypts because both layouts are tried.
        text = read(BRANCH).decode()
        old = encrypt_backup(text, 'pw', major=7, minor=4, build=2933, fmt=4)
        new = encrypt_backup(text, 'pw', major=7, minor=2, build=1639, fmt=6)
        self.assertEqual(read_config_bytes(old, 'pw'), text)
        self.assertEqual(read_config_bytes(new, 'pw'), text)

    def test_format6_salt_is_per_backup(self):
        text = read(BRANCH).decode()
        a = encrypt_backup(text, 'pw', fmt=6)
        b = encrypt_backup(text, 'pw', fmt=6)
        self.assertNotEqual(a, b)  # random salt and nonce each time
        self.assertEqual(read_config_bytes(a, 'pw'), read_config_bytes(b, 'pw'))

    def test_format6_vector_pins_kdf(self):
        # A frozen format-6 blob (fixed salt and nonce) locks the layout and
        # the PBKDF2 parameters: a change to the salt length, the 4096 rounds
        # or SHA-256 would stop this decrypting.
        blob = bytes.fromhex(
            '234647424b7c367c4647543630467c377c30347c323933337c0a000102030405'
            '060708090a0b0c0d0e0f101112131415161718191a1b819a4e80ea6a1372d5e5'
            '04080f308455f006787759c74f2734f58d7317ead9a2710e48e6393fe6b69cc1'
            'a4a58c81a4c3f82ea6dd651ccb46b3d5512ada7e8bda72a448fdc0fbb5177d8f'
            '47c2f5')
        self.assertEqual(
            read_config_bytes(blob, 'test-pass'),
            'config system global\nset hostname fw\nend\n')

    def test_newer_format_is_named(self):
        # A header format newer than any we know, that neither layout reads.
        import os
        blob = b'#FGBK|9|FG120G|7|06|9999|\n' + os.urandom(80)
        with self.assertRaisesMessage(UnsupportedEncryption, 'newer encrypted format (version 9)'):
            read_config_bytes(blob, 'pw')

    def test_truncated_encrypted(self):
        with self.assertRaises(UnsupportedFormat):
            read_config_bytes(b'#FGBK|4|FGT60F|7|02|1639|\nshort', 'x')

    def test_binary_and_empty(self):
        with self.assertRaises(UnsupportedFormat):
            read_config_bytes(b'')
        with self.assertRaises(UnsupportedFormat):
            read_config_bytes(b'\x89PNG\r\n\x1a\n\x00\x00\x00')


class LayoutTests(SimpleTestCase):

    def test_hq_header_and_vdoms(self):
        config = layout(parse(read_config_bytes(read(HQ))))
        self.assertEqual(config.info.model_name, 'FortiGate-100F')
        self.assertEqual(config.info.version, '7.4.3')
        self.assertTrue(config.info.multi_vdom)
        self.assertEqual(config.info.serial, 'FG100FTK20001234')
        self.assertEqual(config.info.hostname, 'HQ-FW01')
        self.assertEqual(list(config.vdoms), ['root', 'CUST-A'])
        self.assertFalse(config.info.is_vm)

    def test_old_and_vm_headers(self):
        config = layout(parse(read_config_bytes(read(AZURE_100D))))
        self.assertEqual((config.info.model_name, config.info.version), ('FortiGate-100D', '5.4'))
        self.assertEqual(config.info.opmode, 'nat')
        config = layout(parse(read_config_bytes(read(XUTILS_MULTI_VDOM))))
        self.assertTrue(config.info.is_vm)
        self.assertTrue(config.info.multi_vdom)
        self.assertEqual(list(config.vdoms), ['root', 'ro'])

    def test_vdom_only_backup_is_refused(self):
        # A VDOM administrator's backup: VDOMs, but no global part.
        text = ('#config-version=FGT60F-7.4.3-FW-build2573-240201:opmode=0:vdom=1:user=dmzadmin\n'
                'config vdom\nedit dmz\nconfig firewall address\nedit "web"\nset subnet 10.0.0.5 255.255.255.255\n'
                'next\nend\nnext\nend\n')
        with self.assertRaisesMessage(ParseError, 'only VDOM settings (dmz)'):
            layout(parse(text))


class ExtractTests(SimpleTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.hq = load(read(HQ))
        cls.branch = load(read(BRANCH))

    def interface(self, name, document=None):
        return next(i for i in (document or self.hq)['interfaces'] if i['name'] == name)

    def test_interfaces(self):
        self.assertEqual(self.interface('lacp-core')['kind'], 'lag')
        self.assertEqual(self.interface('lacp-core')['members'], ['x1', 'x2'])
        vlan10 = self.interface('vlan10')
        self.assertEqual((vlan10['kind'], vlan10['vlan_id'], vlan10['parent']), ('vlan', 10, 'lacp-core'))
        self.assertEqual(vlan10['ip'], '10.10.10.1/24')
        self.assertEqual(vlan10['secondary_ips'], ['10.10.11.1/24'])
        self.assertEqual(self.interface('vlan100')['vdom'], 'CUST-A')
        self.assertEqual(self.interface('port3')['bridge'], 'lan')
        self.assertEqual(self.interface('to-branch1')['ip'], '169.254.10.1/30')
        self.assertIsNone(self.interface('wan2')['ip'])  # DHCP
        self.assertFalse(self.interface('port15')['enabled'])
        self.assertEqual(self.interface('dmz')['mtu'], 1400)
        self.assertEqual(self.interface('wan1')['ipv6'], ['2001:db8:100::10/64'])
        self.assertEqual(self.interface('vlan20')['vrrp'][0]['address'], '10.20.0.1')
        names = [i['name'] for i in self.hq['interfaces']]
        self.assertNotIn('ssl.root', names)

    def test_ha_and_settings(self):
        self.assertEqual(self.hq['ha']['group_name'], 'HQ-FW-HA')
        self.assertEqual(self.hq['ha']['hbdev'], ['ha1', 'ha2'])
        self.assertIsNone(self.branch['ha'])
        self.assertEqual(self.hq['settings']['dns']['servers'], ['9.9.9.9', '149.112.112.112'])
        self.assertEqual(self.hq['settings']['ntp']['servers'], ['ntp1.corp.example', '192.0.2.123'])

    def test_firewall(self):
        root = self.hq['vdoms']['root']
        addresses = {a['name']: a for a in root['addresses']}
        self.assertEqual(addresses['NET-USERS']['prefix'], '10.10.10.0/24')
        self.assertEqual(addresses['R-DHCP-POOL']['start'], '10.10.10.100')
        self.assertEqual(addresses['FQDN-UPDATES']['fqdn'], 'updates.vendor.example')
        self.assertEqual(addresses['dmz address']['prefix'], '172.16.50.0/24')
        groups = {g['name']: g for g in root['address_groups']}
        self.assertEqual(groups['GRP-ALL-SITES']['members'], ['GRP-INTERNAL', 'NET-BRANCH1'])
        services = {s['name']: s for s in root['services']}
        self.assertEqual(services['TCP-8000-8099']['tcp'][0], {'low': 8000, 'high': 8099, 'src_low': 1024, 'src_high': 65535})
        policies = {p['id']: p for p in root['policies']}
        self.assertEqual(policies[3]['srcintf'], ['INSIDE', 'lan'])
        self.assertFalse(policies[5]['enabled'])
        self.assertEqual(root['vips'][0]['mappedport']['low'], 8443)
        self.assertEqual(root['ip_pools'][0]['start'], '203.0.113.12')

    def test_routing(self):
        root = self.hq['vdoms']['root']
        routes = {r['seq']: r for r in root['static_routes'] if r['family'] == 4}
        self.assertEqual(routes[1]['dst'], '0.0.0.0/0')
        self.assertEqual(routes[1]['gateway'], '203.0.113.9')
        self.assertTrue(routes[2]['blackhole'])
        self.assertFalse(routes[4]['enabled'])
        self.assertEqual(root['bgp']['as'], '65010')
        self.assertEqual(len(root['bgp']['neighbors']), 2)
        self.assertEqual(root['bgp']['redistribute'], {'connected': {'route_map': None}})
        self.assertEqual([a['id'] for a in root['ospf']['areas']], ['0.0.0.0', '0.0.0.10'])
        self.assertEqual(root['prefix_lists'][0]['rules'][1]['prefix'], 'any')
        self.assertEqual(root['route_maps'][1]['rules'][0]['set'], {'local-preference': '200'})

    def test_vpn(self):
        phase1 = self.hq['vdoms']['root']['ipsec_phase1'][0]
        self.assertEqual(phase1['remote_gw'], '198.51.100.20')
        self.assertEqual(phase1['proposals'], [['aes256', 'sha256'], ['aes256gcm', 'prfsha384']]
                         if isinstance(phase1['proposals'][0], list) else [('aes256', 'sha256'), ('aes256gcm', 'prfsha384')])
        self.assertEqual(phase1['dhgroups'], [20, 21])
        phase2 = self.hq['vdoms']['root']['ipsec_phase2'][0]
        self.assertEqual(phase2['src'], {'type': 'subnet', 'value': '10.0.0.0/8'})

    def test_document_is_json(self):
        self.assertEqual(json.loads(json.dumps(self.hq))['info']['hostname'], 'HQ-FW01')

    def test_stats(self):
        self.assertIn('system admin', self.hq['stats']['not_imported'])
        self.assertGreater(self.hq['stats']['lines'], 700)

    def test_extract_accepts_parse_result(self):
        document = extract(parse(read(BRANCH).decode()))
        self.assertEqual(document['info']['model_name'], 'FortiGate-60F')
