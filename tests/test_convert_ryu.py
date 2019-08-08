#!/usr/bin/env python
""" Tests for ofequivalence.convert_ryu """

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

from ryu.ofproto.ofproto_v1_3_parser import (
        OFPMatch, OFPInstructionWriteMetadata, OFPInstructionGotoTable,
        OFPInstructionActions, OFPActionOutput, OFPActionSetField, OFPFlowMod,
        OFPFlowStats, OFPActionPopVlan, OFPActionGroup, OFPActionSetQueue,
        OFPActionPushVlan, OFPActionPushPbb, OFPActionPushMpls, OFPActionPopPbb,
        OFPActionPopMpls, OFPActionCopyTtlIn, OFPActionCopyTtlOut,
        OFPActionSetNwTtl, OFPActionSetMplsTtl, OFPActionDecNwTtl,
        OFPActionDecMplsTtl)
from ryu.ofproto.ofproto_v1_3 import (
        OFPIT_APPLY_ACTIONS, OFPIT_WRITE_ACTIONS, OFPIT_CLEAR_ACTIONS,
        OFPFC_ADD)

from ofequivalence.convert_ryu import (
        match_from_ryu, instructions_from_ryu, rule_from_ryu, actions_from_ryu,
        ruleset_to_ryu_json, ruleset_from_ryu, ruleset_to_ryu_pickle,
        ruleset_to_pickle, ruleset_from_pickle)
from ofequivalence.rule import Match, Instructions, ActionSet, ActionList, Rule
from .rulesets import REWRITE_RULESET, COVISOR_RULESET, REANNZ_RULESET


class TestConvertRyu(unittest.TestCase):
    """ Test the conversion from ryu flows to internal Rules """

    def test_exact_match_from_ryu(self):
        """ Test conversion of an exact match from ryu """
        self.assertEqual(match_from_ryu(OFPMatch(in_port=1)),
                         Match([("IN_PORT", 1, None)]))
        self.assertEqual(match_from_ryu(OFPMatch(in_phy_port=2)),
                         Match([("IN_PHY_PORT", 2, None)]))
        self.assertEqual(match_from_ryu(OFPMatch(metadata=3)),
                         Match([("METADATA", 3, None)]))
        self.assertEqual(match_from_ryu(OFPMatch(eth_src=4)),
                         Match([("ETH_SRC", 4, None)]))
        self.assertEqual(match_from_ryu(OFPMatch(mpls_bos=7)),
                         Match([("MPLS_BOS", 7, None)]))

    def test_masked_match_from_ryu(self):
        """ Test conversion of arbitrarily masked matches from ryu """
        self.assertEqual(match_from_ryu(OFPMatch(ipv4_dst=("192.168.2.0", "255.255.255.0"))),
                         Match([("IPV4_DST", 0xC0A80200, 0xFFFFFF00)]))
        self.assertEqual(match_from_ryu(OFPMatch(eth_src=("01:00:00:00:00:00",
                                                          "01:00:00:00:00:00"))),
                         Match([("ETH_SRC", 0x010000000000, 0x010000000000)]))

    def test_convert_instructions(self):
        """ Test converting instructions from ryu """
        ryu_inst = [OFPInstructionWriteMetadata(0x56, 0xff)]
        inst = Instructions()
        inst.write_metadata = (0x56, 0xff)
        self.assertEqual(instructions_from_ryu(ryu_inst), inst)

        ryu_inst = [OFPInstructionGotoTable(6)]
        inst = Instructions()
        inst.goto_table = 6
        self.assertEqual(instructions_from_ryu(ryu_inst), inst)

        output = OFPActionOutput(1)
        ryu_inst = [OFPInstructionActions(OFPIT_APPLY_ACTIONS, [output])]
        inst = Instructions()
        inst.apply_actions = ActionList([('OUTPUT', 1)])
        self.assertEqual(instructions_from_ryu(ryu_inst), inst)

        output = OFPActionOutput(2)
        ryu_inst = [OFPInstructionActions(OFPIT_WRITE_ACTIONS, [output])]
        inst = Instructions()
        inst.write_actions = ActionSet([('OUTPUT', 2)])
        self.assertEqual(instructions_from_ryu(ryu_inst), inst)

    def test_convert_flow(self):
        """ Test converting OFPFlowMod and OFPFlowStats from ryu """
        ryu_match = OFPMatch(ipv4_src=1, eth_type=0x8100, vlan_vid=0x1100)
        ryu_write_actions = OFPInstructionActions(OFPIT_WRITE_ACTIONS, [
            OFPActionPopVlan(),
            OFPActionSetField(eth_dst="10:10:10:10:10:10"),
            OFPActionOutput(7)
            ])
        ryu_instructions = [
            OFPInstructionActions(OFPIT_CLEAR_ACTIONS, []),
            ryu_write_actions,
            OFPInstructionGotoTable(9),
            OFPInstructionWriteMetadata(0x99, 0xff)]
        ryu_flow_mod = OFPFlowMod(
            datapath=None,
            cookie=0xABCD,
            table_id=3,
            command=OFPFC_ADD,
            priority=789,
            match=ryu_match,
            instructions=ryu_instructions)
        ryu_flow_stats = OFPFlowStats(
            cookie=0xABCD,
            table_id=3,
            priority=789,
            match=ryu_match,
            instructions=ryu_instructions)

        match = Match([("IPV4_SRC", 1, None), ("ETH_TYPE", 0x8100, None),
                       ("VLAN_VID", 0x1100, None)])
        instructions = Instructions()
        instructions.goto_table = 9
        instructions.clear_actions = True
        instructions.write_actions.append("POP_VLAN", None)
        instructions.write_actions.append("SET_FIELD", ("ETH_DST", 0x101010101010))
        instructions.write_actions.append("OUTPUT", 7)
        instructions.write_metadata = (0x99, 0xff)

        rule = Rule(
            priority=789,
            cookie=0xABCD,
            table=3,
            match=match,
            instructions=instructions)

        self.assertEqual(rule_from_ryu(ryu_flow_stats), rule)
        self.assertEqual(rule_from_ryu(ryu_flow_mod), rule)

    def test_convert_actions(self):
        """ Test all action conversions work correctly """

        # First check set returns a set
        self.assertIs(type(actions_from_ryu([OFPActionOutput(6)], 'set')),
                      ActionSet)
        # And list a list
        self.assertIs(type(actions_from_ryu([OFPActionOutput(6)], 'list')),
                      ActionList)

        # Now check all the action types, OUTPUT etc
        self.assertEqual(actions_from_ryu([OFPActionOutput(6)], 'list'),
                         ActionList([('OUTPUT', 6)]))
        self.assertEqual(actions_from_ryu([OFPActionGroup(7)], 'list'),
                         ActionList([('GROUP', 7)]))
        self.assertEqual(actions_from_ryu([OFPActionSetQueue(8)], 'list'),
                         ActionList([('SET_QUEUE', 8)]))
        # Push/Pop
        self.assertEqual(actions_from_ryu([OFPActionPushVlan(0x8100)], 'list'),
                         ActionList([('PUSH_VLAN', 0x8100)]))
        self.assertEqual(actions_from_ryu([OFPActionPushVlan(0x88a8)], 'list'),
                         ActionList([('PUSH_VLAN', 0x88a8)]))
        self.assertEqual(actions_from_ryu([OFPActionPopVlan()], 'list'),
                         ActionList([('POP_VLAN', None)]))
        self.assertEqual(actions_from_ryu([OFPActionPushMpls(0x8847)], 'list'),
                         ActionList([('PUSH_MPLS', 0x8847)]))
        self.assertEqual(actions_from_ryu([OFPActionPushMpls(0x8848)], 'list'),
                         ActionList([('PUSH_MPLS', 0x8848)]))
        self.assertEqual(actions_from_ryu([OFPActionPopMpls(0x0800)], 'list'),
                         ActionList([('POP_MPLS', 0x0800)]))
        self.assertEqual(actions_from_ryu([OFPActionPushPbb(0x88e7)], 'list'),
                         ActionList([('PUSH_PBB', 0x88e7)]))
        self.assertEqual(actions_from_ryu([OFPActionPopPbb()], 'list'),
                         ActionList([('POP_PBB', None)]))

        # SET_FIELD, take this chance to check we can do MAC, IPv4/6 conversion
        # as ryu might be using those.
        set_field = OFPActionSetField(vlan_vid=100)
        self.assertEqual(actions_from_ryu([set_field], 'list'),
                         ActionList([("SET_FIELD", ('VLAN_VID', 100))]))
        set_field = OFPActionSetField(eth_dst="10:11:12:13:14:15")
        self.assertEqual(actions_from_ryu([set_field], 'list'),
                         ActionList([("SET_FIELD", ('ETH_DST', 0x101112131415))]))
        set_field = OFPActionSetField(eth_src="10-11-12-13-14-15")
        self.assertEqual(actions_from_ryu([set_field], 'list'),
                         ActionList([("SET_FIELD", ('ETH_SRC', 0x101112131415))]))
        set_field = OFPActionSetField(ipv4_dst="192.168.2.1")
        self.assertEqual(actions_from_ryu([set_field], 'list'),
                         ActionList([("SET_FIELD", ('IPV4_DST', 0xc0a80201))]))
        set_field = OFPActionSetField(ipv4_src="192.168.2.2")
        self.assertEqual(actions_from_ryu([set_field], 'list'),
                         ActionList([("SET_FIELD", ('IPV4_SRC', 0xc0a80202))]))
        set_field = OFPActionSetField(ipv6_src="::")
        self.assertEqual(actions_from_ryu([set_field], 'list'),
                         ActionList([("SET_FIELD", ('IPV6_SRC', 0x0))]))
        set_field = OFPActionSetField(ipv6_src="2001:DB8:0123:4567:89ab:cdef:a:a")
        ipv6_num = 0x20010DB80123456789abcdef000a000a
        self.assertEqual(actions_from_ryu([set_field], 'list'),
                         ActionList([("SET_FIELD", ('IPV6_SRC', ipv6_num))]))
        set_field = OFPActionSetField(ipv6_dst="2001:DB8::")
        ipv6_num = 0x20010DB8000000000000000000000000
        self.assertEqual(actions_from_ryu([set_field], 'list'),
                         ActionList([("SET_FIELD", ('IPV6_DST', ipv6_num))]))
        # TTL
        self.assertEqual(actions_from_ryu([OFPActionCopyTtlOut()], 'list'),
                         ActionList([('COPY_TTL_OUT', None)]))
        self.assertEqual(actions_from_ryu([OFPActionCopyTtlIn()], 'list'),
                         ActionList([('COPY_TTL_IN', None)]))
        self.assertEqual(actions_from_ryu([OFPActionSetMplsTtl(24)], 'list'),
                         ActionList([('SET_MPLS_TTL', 24)]))
        self.assertEqual(actions_from_ryu([OFPActionDecMplsTtl()], 'list'),
                         ActionList([('DEC_MPLS_TTL', None)]))
        self.assertEqual(actions_from_ryu([OFPActionSetNwTtl(0xff)], 'list'),
                         ActionList([('SET_NW_TTL', 0xff)]))
        self.assertEqual(actions_from_ryu([OFPActionDecNwTtl()], 'list'),
                         ActionList([('DEC_NW_TTL', None)]))

    def test_save_ryu_json(self):

        with NamedTemporaryFile() as tmp_file:
            ruleset_to_ryu_json(REWRITE_RULESET, tmp_file.name)
            loaded = ruleset_from_ryu(tmp_file.name)
        self.assertEqual(REWRITE_RULESET, loaded)

        with NamedTemporaryFile() as tmp_file:
            ruleset_to_ryu_json(COVISOR_RULESET, tmp_file.name)
            loaded = ruleset_from_ryu(tmp_file.name)
        self.assertEqual(COVISOR_RULESET, loaded)

        with NamedTemporaryFile() as tmp_file:
            ruleset_to_ryu_json(REANNZ_RULESET, tmp_file.name)
            loaded = ruleset_from_ryu(tmp_file.name)
        self.assertEqual(REANNZ_RULESET, loaded)

    def test_save_ryu_pickle(self):

        with NamedTemporaryFile() as tmp_file:
            ruleset_to_ryu_pickle(REWRITE_RULESET, tmp_file.name)
            loaded = ruleset_from_ryu(tmp_file.name)
        self.assertEqual(REWRITE_RULESET, loaded)

        with NamedTemporaryFile() as tmp_file:
            ruleset_to_ryu_pickle(COVISOR_RULESET, tmp_file.name)
            loaded = ruleset_from_ryu(tmp_file.name)
        self.assertEqual(COVISOR_RULESET, loaded)

        with NamedTemporaryFile() as tmp_file:
            ruleset_to_ryu_pickle(REANNZ_RULESET, tmp_file.name)
            loaded = ruleset_from_ryu(tmp_file.name)
        self.assertEqual(REANNZ_RULESET, loaded)

    def test_save_pickle(self):

        with NamedTemporaryFile() as tmp_file:
            ruleset_to_pickle(REWRITE_RULESET, tmp_file.name)
            loaded = ruleset_from_pickle(tmp_file.name)
        self.assertEqual(REWRITE_RULESET, loaded)

        with NamedTemporaryFile() as tmp_file:
            ruleset_to_pickle(COVISOR_RULESET, tmp_file.name)
            loaded = ruleset_from_pickle(tmp_file.name)
        self.assertEqual(COVISOR_RULESET, loaded)

        with NamedTemporaryFile() as tmp_file:
            ruleset_to_pickle(REANNZ_RULESET, tmp_file.name)
            loaded = ruleset_from_pickle(tmp_file.name)
        self.assertEqual(REANNZ_RULESET, loaded)


if __name__ == '__main__':
    unittest.main()
