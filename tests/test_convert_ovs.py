#!/usr/bin/env python
""" Tests for ofequivalence.convert_ovs """

# Copyright 2019 Richard Sanger, Wand Network Research Group
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest
from tempfile import NamedTemporaryFile
import logging

from ofequivalence.convert_ovs import (rule_from_ovs, actions_from_ovs,
                                       instructions_from_ovs, match_from_ovs,
                                       rule_to_ovs, ruleset_to_ovs, ruleset_from_ovs)
from ofequivalence.rule import Match, Instructions, ActionSet, ActionList, Rule
from .rulesets import REWRITE_RULESET, COVISOR_RULESET, REANNZ_RULESET


log = logging.getLogger("TestLog")

class TestConvertOvS(unittest.TestCase):
    """ Test the conversion from ovs flows to internal Rules """

    def test_exact_match_from_ovs(self):
        """ Test conversion of an exact match from ovs """
        self.assertEqual(match_from_ovs('in_port=1'),
                         Match([("IN_PORT", 1, None)]))
        self.assertEqual(match_from_ovs('metadata=0x3'),
                         Match([("METADATA", 3, None)]))
        self.assertEqual(match_from_ovs('dl_src=00:00:00:00:00:04'),
                         Match([("ETH_SRC", 4, None)]))
        self.assertEqual(match_from_ovs('mpls_bos=1'),
                         Match([("MPLS_BOS", 1, None)]))

    def test_masked_match_from_ovs(self):
        """ Test conversion of arbitrarily masked matches from ovs """
        self.assertEqual(match_from_ovs('nw_dst=192.168.2.0/24'),
                         Match([("IPV4_DST", 0xC0A80200, 0xFFFFFF00)]))
        self.assertEqual(match_from_ovs('nw_dst=192.168.2.0/245.255.255.0'),
                         Match([("IPV4_DST", 0xC0A80200, 0xF5FFFF00)]))
        self.assertEqual(match_from_ovs('dl_src=01:00:00:00:00:00/01:00:00:00:00:00'),
                         Match([("ETH_SRC", 0x010000000000, 0x010000000000)]))
        # TODO IPv6

    def test_convert_instructions(self):
        """ Test converting instructions from ovs """
        inst = Instructions()
        inst.write_metadata = (0x56, 0xff)
        self.assertEqual(instructions_from_ovs("write_metadata:0x56/0xff", {}), inst)

        inst = Instructions()
        inst.goto_table = 6
        self.assertEqual(instructions_from_ovs("goto_table:6", {}), inst)

        inst = Instructions()
        inst.apply_actions = ActionList([('OUTPUT', 1)])
        self.assertEqual(instructions_from_ovs("output:1", {}), inst)

        inst = Instructions()
        inst.write_actions = ActionSet([('OUTPUT', 2)])
        self.assertEqual(instructions_from_ovs("write_actions(output:2)", {}), inst)

    def test_convert_flow1(self):
        """ Test converting OFPFlowMod and OFPFlowStats from ovs """

        expected_insts = Instructions()
        expected_insts.apply_actions.append("POP_VLAN", None)
        expected_insts.apply_actions.append("SET_FIELD", ("ETH_DST", 0x101010101010))
        expected_insts.apply_actions.append("OUTPUT", 7)
        expected_insts.goto_table = 4

        expected = Rule(
            priority=789,
            cookie=0xABCD,
            table=3,
            match=Match([("ETH_TYPE", 0x0800, None),
                         ("IPV4_SRC", 1, None),
                         ("VLAN_VID", 0x1100, None)]),
            instructions=expected_insts
            )

        handcrafted = (
            "priority=789 cookie=0xABCD table=3 eth_type=0x800,ip_src=0.0.0.1,vlan_vid=0x1100 actions=pop_vlan,set_field:10:10:10:10:10:10->eth_dst,output:7,goto_table:4"
        )

        # After going in and out of OVS, ovs-ofctl -O OpenFlowXX dumpflows br0
        ofctl10 = " cookie=0xabcd, duration=30.907s, table=3, n_packets=0, n_bytes=0, priority=789,ip,dl_vlan=256,nw_src=0.0.0.1 actions=strip_vlan,mod_dl_dst:10:10:10:10:10:10,output:7,resubmit(,4)"
        ofctl13 = " cookie=0xabcd, duration=24.104s, table=3, n_packets=0, n_bytes=0, priority=789,ip,dl_vlan=256,nw_src=0.0.0.1 actions=pop_vlan,set_field:10:10:10:10:10:10->eth_dst,output:7,goto_table:4"
        ofctl13_nostats = " cookie=0xabcd, table=3, priority=789,ip,dl_vlan=256,nw_src=0.0.0.1 actions=pop_vlan,set_field:10:10:10:10:10:10->eth_dst,output:7,goto_table:4"
        ofctl15 = " cookie=0xabcd, duration=28.969s, table=3, n_packets=0, n_bytes=0, idle_age=28, priority=789,ip,dl_vlan=256,nw_src=0.0.0.1 actions=pop_vlan,set_field:10:10:10:10:10:10->eth_dst,output:7,goto_table:4"
        # From ovs-appctl bridge/dumpflows
        appctl = "table_id=3, duration=51s, n_packets=0, n_bytes=0, priority=789,ip,dl_vlan=256,nw_src=0.0.0.1,actions=pop_vlan,set_field:10:10:10:10:10:10->eth_dst,output:7,goto_table:4"


        rule_hand = rule_from_ovs(handcrafted, {})
        rule_10 = rule_from_ovs(ofctl10, {})
        rule_13 = rule_from_ovs(ofctl13, {})
        rule_13nostats = rule_from_ovs(ofctl13_nostats, {})
        rule_15 = rule_from_ovs(ofctl15, {})
        rule_appctl = rule_from_ovs(appctl, {})

        self.assertEqual(rule_hand, expected)
        self.assertEqual(rule_10, expected)
        self.assertEqual(rule_13, expected)
        self.assertEqual(rule_13nostats, expected)
        self.assertEqual(rule_15, expected)

        # appctl output doesn't display cookies
        expected.cookie = None
        self.assertEqual(rule_appctl, expected)


    def test_convert_flow2(self):
        """ Test converting OFPFlowMod and OFPFlowStats from ovs """


        match = Match([("IPV4_SRC", 1, None), ("ETH_TYPE", 0x800, None),
                       ("VLAN_VID", 0x1100, None)])
        instructions = Instructions()
        instructions.goto_table = 9
        instructions.clear_actions = True
        instructions.write_actions.append("POP_VLAN", None)
        instructions.write_actions.append("SET_FIELD", ("ETH_DST", 0x101010101010))
        instructions.write_actions.append("OUTPUT", 7)
        instructions.write_metadata = (0x99, 0xff)

        expected = Rule(
            priority=0x8000,
            cookie=0xABCD,
            table=0,
            match=match,
            instructions=instructions)

        # Now for write actions and clear actions etc.
        # Note priority=0x8000 is the default priority and ovs omits it,
        # Similarly table 0 is often omitted
        handcrafted = (
            "priority=0x8000 cookie=0xABCD table=0 eth_type=0x800,ip_src=0.0.0.1,vlan_vid=0x1100 actions=clear_actions,write_actions(pop_vlan,set_field:10:10:10:10:10:10->eth_dst,output:7),write_metadata:0x99/0xff,goto_table:9"
        )

        ofctl11 = " cookie=0xabcd, duration=10.778s, table=0, n_packets=0, n_bytes=0, ip,dl_vlan=256,nw_src=0.0.0.1 actions=clear_actions,write_actions(pop_vlan,mod_dl_dst:10:10:10:10:10:10,output:7),write_metadata:0x99/0xff,goto_table:9"
        # Also the same for of12 to of15
        ofctl13 = " cookie=0xabcd, duration=24.097s, table=0, n_packets=0, n_bytes=0, ip,dl_vlan=256,nw_src=0.0.0.1 actions=clear_actions,write_actions(pop_vlan,set_field:10:10:10:10:10:10->eth_dst,output:7),write_metadata:0x99/0xff,goto_table:9"
        # From ovs-appctl bridge/dumpflows
        appctl = "duration=369s, n_packets=0, n_bytes=0, ip,dl_vlan=256,nw_src=0.0.0.1,actions=clear_actions,write_actions(pop_vlan,set_field:10:10:10:10:10:10->eth_dst,output:7),write_metadata:0x99/0xff,goto_table:9"


        rule_hand = rule_from_ovs(handcrafted, {})
        rule_11 = rule_from_ovs(ofctl11, {})
        rule_13 = rule_from_ovs(ofctl13, {})
        rule_appctl = rule_from_ovs(appctl, {})

        self.assertEqual(rule_hand, expected)
        self.assertEqual(rule_11, expected)
        self.assertEqual(rule_13, expected)

        # appctl output doesn't display cookies
        expected.cookie = None
        self.assertEqual(rule_appctl, expected)

    def test_convert_actions(self):
        """ Test all action conversions work correctly """

        # Now check all the action types, OUTPUT etc
        self.assertEqual(actions_from_ovs("output:6", {}),
                         ActionList([('OUTPUT', 6)]))
        self.assertEqual(actions_from_ovs('group:7', {7: 7}),
                         ActionList([('GROUP', 7)]))
        self.assertEqual(actions_from_ovs("set_queue:8", {}),
                         ActionList([('SET_QUEUE', 8)]))
        # Push/Pop
        self.assertEqual(actions_from_ovs('push_vlan:0x8100', {}),
                         ActionList([('PUSH_VLAN', 0x8100)]))
        self.assertEqual(actions_from_ovs('push_vlan:0x88a8', {}),
                         ActionList([('PUSH_VLAN', 0x88a8)]))
        self.assertEqual(actions_from_ovs('pop_vlan', {}),
                         ActionList([('POP_VLAN', None)]))
        self.assertEqual(actions_from_ovs('strip_vlan', {}),
                         ActionList([('POP_VLAN', None)]))
        self.assertEqual(actions_from_ovs('push_mpls:0x8847', {}),
                         ActionList([('PUSH_MPLS', 0x8847)]))
        self.assertEqual(actions_from_ovs('push_mpls:0x8848', {}),
                         ActionList([('PUSH_MPLS', 0x8848)]))
        self.assertEqual(actions_from_ovs('pop_mpls:0x0800', {}),
                         ActionList([('POP_MPLS', 0x0800)]))
        # PBB not supported by ovs
        #self.assertEqual(actions_from_ovs([OFPActionPushPbb(0x88e7)], 'list'),
        #                 ActionList([('PUSH_PBB', 0x88e7)]))
        #self.assertEqual(actions_from_ovs([OFPActionPopPbb()], 'list'),
        #                 ActionList([('POP_PBB', None)]))

        # SET_FIELD, take this chance to check we can do MAC, IPv4/6 conversion
        # as ovs stores these in their respective format
        self.assertEqual(actions_from_ovs('set_field:100->vlan_vid', {}),
                         ActionList([("SET_FIELD", ('VLAN_VID', 100))]))
        self.assertEqual(actions_from_ovs('set_field:4196->vlan_vid', {}),
                         ActionList([("SET_FIELD", ('VLAN_VID', 100))]))
        self.assertEqual(actions_from_ovs('set_field:10:11:12:13:14:15->eth_dst', {}),
                         ActionList([("SET_FIELD", ('ETH_DST', 0x101112131415))]))
        self.assertEqual(actions_from_ovs('set_field:10:11:12:13:14:15->eth_src', {}),
                         ActionList([("SET_FIELD", ('ETH_SRC', 0x101112131415))]))
        self.assertEqual(actions_from_ovs("set_field:192.168.2.1->ip_dst", {}),
                         ActionList([("SET_FIELD", ('IPV4_DST', 0xc0a80201))]))
        self.assertEqual(actions_from_ovs("set_field:192.168.2.2->ip_src", {}),
                         ActionList([("SET_FIELD", ('IPV4_SRC', 0xc0a80202))]))
        self.assertEqual(actions_from_ovs('set_field:::->ipv6_src', {}),
                         ActionList([("SET_FIELD", ('IPV6_SRC', 0x0))]))
        ipv6_num = 0x20010DB80123456789abcdef000a000a
        self.assertEqual(actions_from_ovs('set_field:2001:db8:123:4567:89ab:cdef:a:a->ipv6_src', {}),
                         ActionList([("SET_FIELD", ('IPV6_SRC', ipv6_num))]))
        ipv6_num = 0x20010DB8000000000000000000000000
        self.assertEqual(actions_from_ovs('set_field:2001:db8::->ipv6_dst', {}),
                         ActionList([("SET_FIELD", ('IPV6_DST', ipv6_num))]))
        # TTL
        #self.assertEqual(actions_from_ovs([OFPActionCopyTtlOut()], 'list'),
        #                 ActionList([('COPY_TTL_OUT', None)]))
        #self.assertEqual(actions_from_ovs([OFPActionCopyTtlIn()], 'list'),
        #                 ActionList([('COPY_TTL_IN', None)]))
        self.assertEqual(actions_from_ovs('set_field:12->mpls_ttl', {}),  # documented as :24 but uses (24)
                         ActionList([('SET_MPLS_TTL', 12)]))
        self.assertEqual(actions_from_ovs('set_mpls_ttl(24)', {}),  # documented as :24 but uses (24)
                         ActionList([('SET_MPLS_TTL', 24)]))
        self.assertEqual(actions_from_ovs('set_mpls_ttl:23', {}),
                         ActionList([('SET_MPLS_TTL', 23)]))
        self.assertEqual(actions_from_ovs('dec_mpls_ttl', {}),
                         ActionList([('DEC_MPLS_TTL', None)]))
        self.assertEqual(actions_from_ovs('mod_nw_ttl:255', {}),
                         ActionList([('SET_NW_TTL', 0xff)]))
        self.assertEqual(actions_from_ovs('set_nw_ttl:255', {}),
                         ActionList([('SET_NW_TTL', 0xff)]))
        self.assertEqual(actions_from_ovs('set_field:255->nw_ttl', {}),
                         ActionList([('SET_NW_TTL', 0xff)]))
        self.assertEqual(actions_from_ovs('dec_ttl', {}),
                         ActionList([('DEC_NW_TTL', None)]))

    def test_rule_to_ovs(self):
        """ Test our conversion to ovs by converting back and forth """
        ofctl13 = " cookie=0xabcd, duration=24.097s, table=0, n_packets=0, n_bytes=0, ip,dl_vlan=256,nw_src=0.0.0.1 actions=clear_actions,write_actions(pop_vlan,set_field:10:10:10:10:10:10->eth_dst,output:7),write_metadata:0x99/0xff,goto_table:9"

        rule = rule_from_ovs(ofctl13, {})
        ovs = rule_to_ovs(rule)
        rule2 = rule_from_ovs(ovs, {})

        self.assertEqual(rule, rule2)

    def test_save_ovs(self):
        """ Test saving and reading from the ovs format """

        with NamedTemporaryFile() as tmp_file:
            ruleset_to_ovs(REWRITE_RULESET, tmp_file.name)
            loaded = ruleset_from_ovs(tmp_file.name)
        self.assertEqual(REWRITE_RULESET, loaded)

        with NamedTemporaryFile() as tmp_file:
            ruleset_to_ovs(COVISOR_RULESET, tmp_file.name)
            loaded = ruleset_from_ovs(tmp_file.name)
        self.assertEqual(COVISOR_RULESET, loaded)

        with NamedTemporaryFile() as tmp_file:
            ruleset_to_ovs(REANNZ_RULESET, tmp_file.name)
            loaded = ruleset_from_ovs(tmp_file.name)
        self.assertEqual(REANNZ_RULESET, loaded)

if __name__ == '__main__':
    unittest.main()
