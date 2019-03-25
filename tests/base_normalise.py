"""
Rules: Priority ordered (wc, action)
       wc -> A single wildcard
       action -> identical if equal
"""

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

from ofequivalence.rule import (Match, Rule, Instructions,
                                ActionList)
from ofequivalence.ruleset import (to_single_table,)


output1 = Instructions()
output1.apply_actions = ActionList([('OUTPUT', 6)])
goto1 = Instructions()
goto1.goto_table = 1
goto2 = Instructions()
goto2.goto_table = 2

"""
arp  -> drop
ip=1 -> output:1
*    -> drop
"""
data1 = [
    Rule(priority=10,
         match=Match([('ETH_TYPE', 60, None)])),
    Rule(priority=9,
         match=Match([('IPV4_DST', 1, None)]),
         instructions=Instructions(dup=output1)),
    Rule(priority=0)
    ]

"""
ip=1, arp -> drop
ip=1      -> output:1
*         -> drop
"""
data2 = [
    Rule(priority=10,
         match=Match([('IPV4_DST', 1, None),
                      ('ETH_TYPE', 60, None)])),
    Rule(priority=9,
         match=Match([('IPV4_DST', 1, None)]),
         instructions=Instructions(dup=output1)),
    Rule(priority=0)
    ]

"""
ip=0, arp -> drop
ip=1, arp -> drop
ip=0      -> output:1
ip=1      -> output:1
*         -> drop
"""
data3 = [
    Rule(priority=10,
         match=Match([('IPV4_DST', 1, None),
                      ('ETH_TYPE', 60, None)])),
    Rule(priority=10,
         match=Match([('IPV4_DST', 0, None),
                      ('ETH_TYPE', 60, None)])),
    Rule(priority=9,
         match=Match([('IPV4_DST', 1, None)]),
         instructions=Instructions(dup=output1)),
    Rule(priority=9,
         match=Match([('IPV4_DST', 0, None)]),
         instructions=Instructions(dup=output1)),
    Rule(priority=0)
    ]

"""
arp     -> drop
ip=0/31 -> output:1
*       -> drop
"""
data4 = [
    Rule(priority=10,
         match=Match([('ETH_TYPE', 60, None)])),
    Rule(priority=9,
         match=Match([('IPV4_DST', 0, 0xfffffffe)]),
         instructions=Instructions(dup=output1)),
    Rule(priority=0)
    ]

"""
arp,ip=0/31     -> drop
ip=0/31 -> output:1
*       -> drop
"""
data5 = [
    Rule(priority=10,
         match=Match([('IPV4_DST', 0, 0xfffffffe),
                      ('ETH_TYPE', 60, None)])),
    Rule(priority=9,
         match=Match([('IPV4_DST', 0, 0xfffffffe)]),
         instructions=Instructions(dup=output1)),
    Rule(priority=0)
    ]

"""
arp,ip=0/30     -> drop
ip=0/30 -> output:1
*       -> drop
"""
data6 = [
    Rule(priority=10,
         match=Match([('IPV4_DST', 0, 0xfffffffc),
                      ('ETH_TYPE', 60, None)])),
    Rule(priority=9,
         match=Match([('IPV4_DST', 0, 0xfffffffc)]),
         instructions=Instructions(dup=output1)),
    Rule(priority=0)
    ]

"""
arp -> drop
ip=0      -> output:1
ip=1      -> output:1
ip=2      -> output:1
ip=3      -> output:1
*         -> drop
"""
data7 = [
    Rule(priority=10,
         match=Match([('ETH_TYPE', 60, None)])),
    Rule(priority=9,
         match=Match([('IPV4_DST', 3, None)]),
         instructions=Instructions(dup=output1)),
    Rule(priority=9,
         match=Match([('IPV4_DST', 2, None)]),
         instructions=Instructions(dup=output1)),
    Rule(priority=9,
         match=Match([('IPV4_DST', 1, None)]),
         instructions=Instructions(dup=output1)),
    Rule(priority=9,
         match=Match([('IPV4_DST', 0, None)]),
         instructions=Instructions(dup=output1)),
    Rule(priority=0)
    ]

"""
Data one with extra overlapping
arp -> drop
ip=1 -> output:1
ip=1 -> drop
arp -> output:1
*    -> drop
"""
data8 = [
    Rule(priority=10,
         match=Match([('ETH_TYPE', 60, None)])),
    Rule(priority=9,
         match=Match([('IPV4_DST', 1, None)]),
         instructions=Instructions(dup=output1)),
    Rule(priority=8,
         match=Match([('IPV4_DST', 1, None)])),
    Rule(priority=7,
         match=Match([('ETH_TYPE', 60, None)]),
         instructions=Instructions(dup=output1)),
    Rule(priority=0)
    ]


def inst_from_acts(actions):
    inst = Instructions()
    inst.apply_actions = ActionList(actions)
    return inst


class BaseNormalise(object):

    def setUp(self, _normalise):
        global normalise
        global check_equal
        global find_conflicting_paths
        normalise = _normalise.normalise
        check_equal = _normalise.check_equal
        find_conflicting_paths = _normalise.find_conflicting_paths

    def print_norm(self, data):
        for a, b in data.items():
            print(a, "=>", b)

    def test_normalise_1(self):
        n1 = normalise(data1)
        n2 = normalise(data2)
        self.assertTrue(check_equal(n1, n2))

    def test_normalise_2(self):
        n3 = normalise(data3)
        n4 = normalise(data4)
        n5 = normalise(data5)
        self.assertTrue(check_equal(n3, n4))
        self.assertTrue(check_equal(n5, n4))
        self.assertTrue(check_equal(n5, n3))

    def test_normalise_3(self):
        n6 = normalise(data6)
        n7 = normalise(data7)
        self.assertTrue(check_equal(n6, n7))

    def test_overlapping_duplicates(self):
        n1 = normalise(data1)
        n8 = normalise(data8)
        self.assertTrue(check_equal(n1, n8))

    def test_fails(self):
        n1 = normalise(data1)
        n2 = normalise(data2)
        n3 = normalise(data3)
        n4 = normalise(data4)
        n5 = normalise(data5)

        self.assertFalse(check_equal(n1, n3))
        self.assertFalse(check_equal(n2, n4))
        self.assertFalse(check_equal(n5, n1))

    def test_redundant_vlans(self):
        """ Test the push pop combinations are correctly removed """
        PUSH, POP = ('PUSH_VLAN', 0x8100), ('POP_VLAN', None)
        VID1, VID2 = ('SET_FIELD', ('VLAN_VID', 1)), ('SET_FIELD', ('VLAN_VID', 2))
        PCP5, OUT = ('SET_FIELD', ('VLAN_PCP', 5)), ('OUTPUT', 1)
        IP = ('SET_FIELD', ('IPV4_SRC', 1))
        MATCH = Match([('IPV4_DST', 1, None)])

        # Base case
        n1 = normalise([
            Rule(priority=10, match=MATCH,
                 instructions=inst_from_acts([VID1, IP, OUT])),
            Rule(priority=0)
            ])
        # Check that VLAN set fields between PUSH and POP are removed, but not others
        n2 = normalise([
            Rule(priority=10, match=MATCH,
                 instructions=inst_from_acts([VID2, PUSH, IP, PCP5, POP, VID1, OUT])),
            Rule(priority=0)
            ])
        self.assertTrue(check_equal(n1, n2))

        # Check with multiple set fields between
        n3 = normalise([
            Rule(priority=10, match=MATCH,
                 instructions=inst_from_acts([IP, PUSH, VID2, VID2, POP, VID1, OUT])),
            Rule(priority=0)
            ])
        self.assertTrue(check_equal(n1, n3))

        # Check with nested push pop operations
        n4 = normalise([
            Rule(priority=10, match=MATCH,
                 instructions=inst_from_acts([IP, PUSH, PUSH, VID2, POP, VID2, POP, VID1, OUT])),
            Rule(priority=0)
            ])
        self.assertTrue(check_equal(n1, n4))

        # Check we don't remove a pop, push case!!
        # A very strict set of conditions would be needed to remove this:
        # 1). All fields are set after the push, that is VID and PCP,
        #     and we keep the set fields, (or)
        #     - All fields are set back to their original value based on the match
        #       and this becomes a nop
        # 2). We can be sure that the push'd VLAN ethertype is the same
        #      as the original VLAN ethertype
        # For now we don't account for this case as it is too complex
        n5 = normalise([
            Rule(priority=10, match=MATCH,
                 instructions=inst_from_acts([IP, POP, PUSH, VID2, OUT])),
            Rule(priority=0)
            ])

        self.assertFalse(check_equal(n1, n5))

        # We should remove any set fields before the POP
        n6 = normalise([
            Rule(priority=10, match=MATCH,
                 instructions=inst_from_acts([IP, VID1, PCP5, POP, PUSH, VID2, OUT])),
            Rule(priority=0)
            ])
        self.assertTrue(check_equal(n5, n6))

        # Check that a double tagging is correct and doesn't remove set_fields
        # push_vlan, vid: 1, push_vlan, vid: 2
        n7 = normalise([
            Rule(priority=10, match=MATCH,
                 instructions=inst_from_acts([PUSH, VID1, PUSH, VID2, OUT])),
            Rule(priority=0)
            ])

        # != push_vlan, push_vlan, vid:2
        n8 = normalise([
            Rule(priority=10, match=MATCH,
                 instructions=inst_from_acts([PUSH, PUSH, VID2, OUT])),
            Rule(priority=0)
            ])
        self.assertFalse(check_equal(n7, n8))

    def test_redundant_set_field(self):
        """ Check that additional set fields are removed """
        SF1, SF2 = ("SET_FIELD", ("IPV4_DST", 1)), ("SET_FIELD", ("IPV4_DST", 2))
        SF3, SF4 = ("SET_FIELD", ("IPV4_DST", 3)), ("SET_FIELD", ("IPV4_DST", 4))
        OUT = ("OUTPUT", 1)
        n1 = normalise([
            Rule(priority=10,
                 instructions=inst_from_acts([SF2, OUT])),
            Rule(priority=0)
            ])
        n2 = normalise([
            Rule(priority=10,
                 instructions=inst_from_acts([SF1, SF2, OUT])),
            Rule(priority=0)
            ])
        n3 = normalise([
            Rule(priority=10,
                 instructions=inst_from_acts([SF3, SF2, OUT])),
            Rule(priority=0)
            ])
        n4 = normalise([
            Rule(priority=10,
                 instructions=inst_from_acts([SF4, SF3, SF1, SF2, OUT])),
            Rule(priority=0)
            ])
        n5 = normalise([
            Rule(priority=10,
                 instructions=inst_from_acts([SF2, SF2, SF2, SF2, OUT])),
            Rule(priority=0)
            ])
        self.assertTrue(check_equal(n1, n2))
        self.assertTrue(check_equal(n1, n3))
        self.assertTrue(check_equal(n1, n4))
        self.assertTrue(check_equal(n1, n5))

        # Sanity check
        n6 = normalise([
            Rule(priority=10,
                 instructions=inst_from_acts([SF4, SF3, SF1, SF1, OUT])),
            Rule(priority=0)
            ])
        self.assertFalse(check_equal(n1, n6))

    def test_action_independence_single(self):
        """ Test cases where the match cancels a set field """
        SF1, OUT = ('SET_FIELD', ('IPV4_DST', 0x01010101)), ('OUTPUT', 6)
        DEC_TTL = ('DEC_NW_TTL', None)
        # 0.1.1.0/30 -> ip:1.1.1.1, output:1
        n1 = normalise([
            Rule(priority=10,
                 match=Match([('IPV4_DST', 0x01010100, 0xFFFFFFFE)]),
                 instructions=inst_from_acts([SF1, OUT])),
            Rule(priority=0)
            ])
        # 1.1.1.1/32 -> output:1
        # 1.1.1.0/31 -> ip:1.1.1.1, output:1
        n2 = normalise([
            Rule(priority=10,
                 match=Match([('IPV4_DST', 0x01010101, None)]),
                 instructions=inst_from_acts([OUT])),
            Rule(priority=9,
                 match=Match([('IPV4_DST', 0x01010100, 0xFFFFFFFE)]),
                 instructions=inst_from_acts([SF1, OUT])),
            Rule(priority=0)
            ])
        # 1.1.1.0/32 -> ip:1.1.1.1, output1
        # 1.1.1.0/31 -> output:1
        n3 = normalise([
            Rule(priority=10,
                 match=Match([('IPV4_DST', 0x01010100, None)]),
                 instructions=inst_from_acts([SF1, OUT])),
            Rule(priority=9,
                 match=Match([('IPV4_DST', 0x01010100, 0xFFFFFFFE)]),
                 instructions=inst_from_acts([OUT])),
            Rule(priority=0)
            ])
        n4 = normalise([
            Rule(priority=10,
                 match=Match([('IPV4_DST', 0x01010101, None)]),
                 instructions=inst_from_acts([OUT])),
            Rule(priority=9,
                 match=Match([('IPV4_DST', 0x01010100, 0xFFFFFFFE)]),
                 instructions=inst_from_acts([DEC_TTL, SF1, OUT])),
            Rule(priority=0)
            ])
        self.assertTrue(check_equal(n1, n2))
        self.assertFalse(check_equal(n1, n4))
        self.assertTrue(check_equal(n2, n3))
        self.assertTrue(check_equal(n1, n3))

    def test_action_independence_multiple(self):
        """ Testing messy combinations of mutliple set fields

            Combinations of multiple fields, some overlapping some not.
            And alternative values for different outputs.

            Base case:
            dst:0/31 -> dst:1, src:2, output:1, dst:2, src:1, output:2
        """
        DST1, DST2 = ('SET_FIELD', ('IPV4_DST', 0x1)), ('SET_FIELD', ('IPV4_DST', 0x2))
        SRC1, SRC2 = ('SET_FIELD', ('IPV4_SRC', 0x1)), ('SET_FIELD', ('IPV4_SRC', 0x2))
        OUT1, OUT2 = ('OUTPUT', 1), ('OUTPUT', 2)
        n1 = normalise([
            Rule(priority=10,
                 match=Match([('IPV4_DST', 0x0, 0xFFFFFFFE)]),
                 instructions=inst_from_acts([DST1, SRC2, OUT1, DST2, SRC1, OUT2])),
            Rule(priority=0)
            ], match_redundancy=True)
        """
            dst:1, src:2 -> output:1, dst:2, src:1, output:2
            dst:0/31 -> dst:1, src:2, output:1, dst:2, src:1, output:2
        """
        n2 = normalise([
            Rule(priority=10,
                 match=Match([('IPV4_DST', 1, None),
                              ('IPV4_SRC', 2, None)]),
                 instructions=inst_from_acts([OUT1, DST2, SRC1, OUT2])),
            Rule(priority=9,
                 match=Match([('IPV4_DST', 0x0, 0xFFFFFFFE)]),
                 instructions=inst_from_acts([DST1, SRC2, OUT1, DST2, SRC1, OUT2])),
            Rule(priority=0)
            ], match_redundancy=True)
        """
            dst:1 -> src:2, output:1, dst:2, src:1, output:2
            dst:0/31 -> dst:1, src:2, output:1, dst:2, src:1, output:2
        """
        n3 = normalise([
            Rule(priority=10,
                 match=Match([('IPV4_DST', 1, None)]),
                 instructions=inst_from_acts([SRC2, OUT1, DST2, SRC1, OUT2])),
            Rule(priority=9,
                 match=Match([('IPV4_DST', 0x0, 0xFFFFFFFE)]),
                 instructions=inst_from_acts([DST1, SRC2, OUT1, DST2, SRC1, OUT2])),
            Rule(priority=0)
            ], match_redundancy=True)

        self.assertTrue(check_equal(n1, n2))
        self.assertTrue(check_equal(n2, n3))
        self.assertTrue(check_equal(n1, n3))

    def test_find_simple_conflicting_paths(self):
        """ Simple single table conflicting paths test
        Difference test
        ip=1 -> output:1
        *    -> drop

        vs.

        ip=1 -> drop
        *    -> drop

        vs.

        *  -> drop
        """
        ruleset_a = [
            Rule(priority=9, table=0,
                 match=Match([('IPV4_DST', 1, None)]),
                 instructions=Instructions(dup=output1)),
            Rule(priority=0, table=0)
            ]

        ruleset_b = [
            Rule(priority=9, table=0,
                 match=Match([('IPV4_DST', 1, None)])),
            Rule(priority=0, table=0)
            ]

        ruleset_c = [
            Rule(priority=0, table=0)
            ]
        # Expected results
        result_ab = {
            (ruleset_a[0],): frozenset([(ruleset_b[0],)])
        }
        result_ba = {
            (ruleset_b[0],): frozenset([(ruleset_a[0],)])
        }
        result_ac = {
            (ruleset_a[0],): frozenset([(ruleset_c[0],)])
        }
        result_ca = {
            (ruleset_c[0],): frozenset([(ruleset_a[0],)])
        }
        single_a = to_single_table(ruleset_a)
        single_b = to_single_table(ruleset_b)
        single_c = to_single_table(ruleset_c)
        norm_a = normalise(single_a)
        norm_b = normalise(single_b)
        norm_c = normalise(single_c)
        equal_ab, diff_ab = check_equal(norm_a, norm_b, diff=True)
        self.assertFalse(equal_ab)
        equal_ac, diff_ac = check_equal(norm_a, norm_b, diff=True)
        self.assertFalse(equal_ac)
        self.assertTrue(check_equal(norm_b, norm_c))

        paths_ab = find_conflicting_paths(diff_ab, single_a, single_b)
        self.assertEqual(paths_ab, result_ab)
        self.assertNotEqual(paths_ab, result_ba)  # Sanity check

        paths_ba = find_conflicting_paths(diff_ab, single_b, single_a)
        self.assertEqual(paths_ba, result_ba)
        self.assertNotEqual(paths_ba, result_ab)  # Sanity check

        paths_ca = find_conflicting_paths(diff_ac, single_c, single_a)
        self.assertEqual(paths_ca, result_ca)

        paths_ac = find_conflicting_paths(diff_ac, single_a, single_c)
        self.assertEqual(paths_ac, result_ac)

    def test_find_multitable_conflicting_paths(self):
        """ Multitable conflicting paths test

        vlan:1 GT(1)     ip:0/0xFFFFFFFE output1    ip:0
        vlan:2 GT(2)     ip:0 output1 (shadowed)    ip:1
        *                *                          *

        === As single table ===

        vlan:1,ip:0 output1
        vlan:1,ip:1 output1
        vlan:2,ip:0
        vlan:2,ip:1
        *

        vs.

        vlan:1,ip:0
        vlan:1,ip:1 output1
        vlan:2,ip:0 output1
        vlan:2,ip:1
        *
        """
        ruleset_a = [
            Rule(priority=10, table=0,
                 match=Match([('VLAN_VID', 1, None)]),
                 instructions=Instructions(dup=goto1)),
            Rule(priority=10, table=0,
                 match=Match([('VLAN_VID', 2, None)]),
                 instructions=Instructions(dup=goto2)),
            Rule(priority=0, table=0),
            Rule(priority=20, table=1,
                 match=Match([('IPV4_DST', 0, 0xFFFFFFFE)]),
                 instructions=Instructions(dup=output1)),
            Rule(priority=19, table=1,
                 match=Match([('IPV4_DST', 0, None)]),
                 instructions=Instructions(dup=output1)),
            Rule(priority=0, table=1),
            Rule(priority=30, table=2,
                 match=Match([('IPV4_DST', 0, None)]),
                 instructions=Instructions()),
            Rule(priority=30, table=2,
                 match=Match([('IPV4_DST', 1, None)]),
                 instructions=Instructions()),
            Rule(priority=0, table=2)
            ]

        ruleset_b = [
            Rule(priority=14, table=0,
                 match=Match([('VLAN_VID', 1, None), ('IPV4_DST', 0, None)])),
            Rule(priority=14, table=0,
                 match=Match([('VLAN_VID', 1, None), ('IPV4_DST', 1, None)]),
                 instructions=Instructions(dup=output1)),
            Rule(priority=14, table=0,
                 match=Match([('VLAN_VID', 2, None), ('IPV4_DST', 0, None)]),
                 instructions=Instructions(dup=output1)),
            Rule(priority=14, table=0,
                 match=Match([('VLAN_VID', 2, None), ('IPV4_DST', 1, None)])),
            Rule(priority=0, table=0)
            ]

        single_a = to_single_table(ruleset_a)
        single_b = to_single_table(ruleset_b)
        norm_a = normalise(single_a)
        norm_b = normalise(single_b)

        result_ab = {
            (ruleset_a[0], ruleset_a[3]): frozenset([(ruleset_b[0],)]),
            (ruleset_a[1], ruleset_a[6]): frozenset([(ruleset_b[2],)])
        }
        result_ba = {
            (ruleset_b[0],): frozenset([(ruleset_a[0], ruleset_a[3])]),
            (ruleset_b[2],): frozenset([(ruleset_a[1], ruleset_a[6])])
        }

        equal_ab, diff_ab = check_equal(norm_a, norm_b, diff=True)
        self.assertFalse(equal_ab)
        equal_ba, diff_ba = check_equal(norm_b, norm_a, diff=True)
        self.assertFalse(equal_ba)

        paths_ab = find_conflicting_paths(diff_ab, single_a, single_b)
        paths_ba = find_conflicting_paths(diff_ab, single_b, single_a)

        self.assertEqual(paths_ab, result_ab)
        self.assertNotEqual(paths_ab, result_ba)  # Sanity
        self.assertEqual(paths_ba, result_ba)

    def test_find_rewrite_conflicting_paths(self):
        """ Rewritten conflicting paths test

        VLAN_VID=0 SetVLAN(1), goto1      VLAN_VID=0 output:1
        *                                 VLAN_VID=1 drop
                                          *
        vs. single table, note all traffic is different no set
        * output1
        """
        inst_a = Instructions()
        inst_a.goto_table = 1
        inst_a.apply_actions.append("SET_FIELD", ("VLAN_VID", 1))
        # Note: Set VLAN applies the present bit mask so must included it
        ruleset_a = [
            Rule(priority=10, table=0,
                 match=Match([('VLAN_VID', 0x1000 | 0, None)]),
                 instructions=Instructions(dup=inst_a)),
            Rule(priority=0, table=0),
            Rule(priority=20, table=1,
                 match=Match([('VLAN_VID', 0x1000 | 0, None)]),
                 instructions=Instructions(dup=output1)),
            Rule(priority=20, table=1,
                 match=Match([('VLAN_VID', 0x1000 | 1, None)])),
            Rule(priority=0, table=1)
            ]
        ruleset_b = [
            Rule(priority=0, table=0, instructions=Instructions(dup=output1))
            ]
        single_a = to_single_table(ruleset_a)
        single_b = to_single_table(ruleset_b)
        norm_a = normalise(single_a)
        norm_b = normalise(single_b)

        # Make sure the frozensets are made after to_single_table which changes
        # priorities which changes the Rule's hash in the frozenset
        result_ab = {
            (ruleset_a[0], ruleset_a[3]): frozenset([(ruleset_b[0],)]),
            (ruleset_a[1],): frozenset([(ruleset_b[0],)])
            }
        result_ba = {
            (ruleset_b[0],): frozenset([(ruleset_a[0], ruleset_a[3]),
                                        (ruleset_a[1],)])
            }

        equal_ab, diff_ab = check_equal(norm_a, norm_b, diff=True)
        self.assertFalse(equal_ab)

        paths_ab = find_conflicting_paths(diff_ab, single_a, single_b)
        paths_ba = find_conflicting_paths(diff_ab, single_b, single_a)
        self.assertEqual(paths_ab, result_ab)
        self.assertNotEqual(paths_ab, result_ba)  # Sanity check
        self.assertEqual(paths_ba, result_ba)

    def test_find_metadata_conflicting_paths(self):
        """ Metadata rewrite conflicting paths test

        As metadata can be set bitwise it uses a slightly different code
        path to a standard set field.

        * MD=0x10 GT=1      0x10 MD=0x1/0x1 GT=2   0x11 output1
                            *                      *
        vs. single table, note all traffic is different no set
        * drop
        """
        inst_a = Instructions()
        inst_a.goto_table = 1
        inst_a.write_metadata = (0x12, None)
        inst_b = Instructions()
        inst_b.goto_table = 2
        inst_b.write_metadata = (0x1, 0x3)
        # Note: Set VLAN applies the present bit mask so must included it
        ruleset_a = [
            Rule(priority=10, table=0,
                 instructions=inst_a),
            Rule(priority=10, table=1, match=Match([('METADATA', 0x12, None)]),
                 instructions=inst_b),
            Rule(priority=0, table=1),
            Rule(priority=10, table=2, match=Match([('METADATA', 0x11, None)]),
                 instructions=Instructions(dup=output1)),
            Rule(priority=0, table=2),
            ]
        ruleset_b = [
            Rule(priority=0, table=0)
            ]
        single_a = to_single_table(ruleset_a)
        single_b = to_single_table(ruleset_b)
        norm_a = normalise(single_a)
        norm_b = normalise(single_b)

        # Make sure the frozensets are made after to_single_table which changes
        # priorities which changes the Rule's hash in the frozenset
        result_ab = {
            (ruleset_a[0], ruleset_a[1], ruleset_a[3]): frozenset([(ruleset_b[0],)]),
            }
        result_ba = {
            (ruleset_b[0],): frozenset([(ruleset_a[0], ruleset_a[1], ruleset_a[3],)])
            }
        equal_ab, diff_ab = check_equal(norm_a, norm_b, diff=True)
        self.assertFalse(equal_ab)

        paths_ab = find_conflicting_paths(diff_ab, single_a, single_b)
        paths_ba = find_conflicting_paths(diff_ab, single_b, single_a)
        self.assertEqual(paths_ab, result_ab)
        self.assertNotEqual(paths_ab, result_ba)  # Sanity check
        self.assertEqual(paths_ba, result_ba)

    def test_find_vlans_conflicting_paths(self):
        """ VLAN rewrite paths test, check push/pop combinations
            Also due to internals of how this can be structured

        IN_PORT:1,VLAN:1         TCP:80: drop     VLAN:1 output:10
        IN_PORT:2 pushVLAN:2     * ->             VLAN:2 pop output:11
        IN_PORT:3 pushVLAN:1
        IN_PORT:4,VLAN:2
        * drop

        vs. A vlan can do things:

        IN_PORT:1,VLAN:1         VLAN:1 pop output:11
        IN_PORT:2 pushVLAN:2     VLAN:2 output:10
        IN_PORT:3 pushVLAN:1
        IN_PORT:4,VLAN:2
        * drop

        vs. single table, note all traffic is different no set
        * drop
        """
        push_vlan2 = Instructions()
        push_vlan2.goto_table = 1
        push_vlan2.apply_actions.append("PUSH_VLAN", 0x8100)
        push_vlan2.apply_actions.append("SET_FIELD", ("VLAN_VID", 2))
        push_vlan1 = Instructions()
        push_vlan1.goto_table = 1
        push_vlan1.apply_actions.append("PUSH_VLAN", 0x8100)
        push_vlan1.apply_actions.append("SET_FIELD", ("VLAN_VID", 1))
        trunk10 = Instructions()
        trunk10.write_actions.append("OUTPUT", 11)
        access11 = Instructions()
        access11.write_actions.append("POP_VLAN", None)
        access11.write_actions.append("OUTPUT", 11)
        # Note: Set VLAN applies the present bit mask so must included it
        ruleset_a = [
            Rule(priority=10, table=0,
                 match=Match([('IN_PORT', 1, None), ('VLAN_VID', 0x1001, None)]),
                 instructions=goto1),
            Rule(priority=10, table=0,
                 match=Match([('IN_PORT', 2, None)]),
                 instructions=push_vlan2),
            Rule(priority=10, table=0,
                 match=Match([('IN_PORT', 3, None)]),
                 instructions=push_vlan1),
            Rule(priority=10, table=0,
                 match=Match([('IN_PORT', 4, None), ('VLAN_VID', 0x1002, None)]),
                 instructions=goto1),
            Rule(priority=0, table=0),
            Rule(priority=10, table=1, match=Match([('TCP_SRC', 80, None)])),
            Rule(priority=0, table=1, instructions=goto2),
            Rule(priority=10, table=2, match=Match([('VLAN_VID', 0x1001, None)]),
                 instructions=Instructions(dup=trunk10)),
            Rule(priority=10, table=2, match=Match([('VLAN_VID', 0x1002, None)]),
                 instructions=Instructions(dup=access11)),
            Rule(priority=0, table=2),
            ]
        ruleset_b = [
            Rule(priority=10, table=0,
                 match=Match([('IN_PORT', 1, None), ('VLAN_VID', 0x1001, None)]),
                 instructions=goto1),
            Rule(priority=10, table=0,
                 match=Match([('IN_PORT', 2, None)]),
                 instructions=push_vlan2),
            Rule(priority=10, table=0,
                 match=Match([('IN_PORT', 3, None)]),
                 instructions=push_vlan1),
            Rule(priority=10, table=0,
                 match=Match([('IN_PORT', 4, None), ('VLAN_VID', 0x1002, None)]),
                 instructions=goto1),
            Rule(priority=0, table=0),
            Rule(priority=10, table=1, match=Match([('VLAN_VID', 0x1001, None)]),
                 instructions=Instructions(dup=access11)),
            Rule(priority=10, table=1, match=Match([('VLAN_VID', 0x1002, None)]),
                 instructions=Instructions(dup=trunk10)),
            Rule(priority=0, table=1)]
        ruleset_c = [
            Rule(priority=0, table=0)
            ]
        single_a = to_single_table(ruleset_a)
        single_b = to_single_table(ruleset_b)
        single_c = to_single_table(ruleset_c)
        norm_a = normalise(single_a)
        norm_b = normalise(single_b)
        norm_c = normalise(single_c)

        # Make sure the frozensets are made after to_single_table which changes
        # priorities which changes the Rule's hash in the frozenset
        result_ab = {
            (ruleset_a[0], ruleset_a[5]):
                frozenset([(ruleset_b[0], ruleset_b[5])]),
            (ruleset_a[0], ruleset_a[6], ruleset_a[7]):
                frozenset([(ruleset_b[0], ruleset_b[5])]),
            (ruleset_a[1], ruleset_a[5]):
                frozenset([(ruleset_b[1], ruleset_b[6])]),
            (ruleset_a[1], ruleset_a[6], ruleset_a[8]):
                frozenset([(ruleset_b[1], ruleset_b[6])]),
            (ruleset_a[2], ruleset_a[5]):
                frozenset([(ruleset_b[2], ruleset_b[5])]),
            (ruleset_a[2], ruleset_a[6], ruleset_a[7]):
                frozenset([(ruleset_b[2], ruleset_b[5])]),
            (ruleset_a[3], ruleset_a[5]):
                frozenset([(ruleset_b[3], ruleset_b[6])]),
            (ruleset_a[3], ruleset_a[6], ruleset_a[8]):
                frozenset([(ruleset_b[3], ruleset_b[6])]),
            }
        result_ba = {
            (ruleset_b[0], ruleset_b[5]):
                frozenset([(ruleset_a[0], ruleset_a[5]),
                           (ruleset_a[0], ruleset_a[6], ruleset_a[7])]),
            (ruleset_b[1], ruleset_b[6]):
                frozenset([(ruleset_a[1], ruleset_a[5]),
                           (ruleset_a[1], ruleset_a[6], ruleset_a[8])]),
            (ruleset_b[2], ruleset_b[5]):
                frozenset([(ruleset_a[2], ruleset_a[5]),
                           (ruleset_a[2], ruleset_a[6], ruleset_a[7])]),
            (ruleset_b[3], ruleset_b[6]):
                frozenset([(ruleset_a[3], ruleset_a[5]),
                           (ruleset_a[3], ruleset_a[6], ruleset_a[8])]),
            }
        result_ca = {
            (ruleset_c[0],):
                frozenset([(ruleset_a[0], ruleset_a[6], ruleset_a[7]),
                           (ruleset_a[1], ruleset_a[6], ruleset_a[8]),
                           (ruleset_a[2], ruleset_a[6], ruleset_a[7]),
                           (ruleset_a[3], ruleset_a[6], ruleset_a[8])])
            }
        equal_ab, diff_ab = check_equal(norm_a, norm_b, diff=True)
        equal_ca, diff_ca = check_equal(norm_c, norm_a, diff=True)
        self.assertFalse(equal_ab)
        self.assertFalse(equal_ca)

        paths_ab = find_conflicting_paths(diff_ab, single_a, single_b)
        paths_ba = find_conflicting_paths(diff_ab, single_b, single_a)
        paths_ca = find_conflicting_paths(diff_ca, single_c, single_a)
        self.assertEqual(paths_ab, result_ab)
        self.assertNotEqual(paths_ab, result_ba)  # Sanity check
        self.assertEqual(paths_ba, result_ba)
        self.assertEqual(paths_ca, result_ca)
