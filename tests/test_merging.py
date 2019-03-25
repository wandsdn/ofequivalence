#!/usr/bin/env python
"""
Test cases for merging flows and actions
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

import unittest
from ofequivalence.rule import Rule, Match, MergeException


class TestMergingRules(unittest.TestCase):

    def setUp(self):
        self.ipv4_src1 = Match([("IPV4_SRC", 1, None)])
        self.ipv4_src2 = Match([("IPV4_SRC", 2, None)])
        self.ipv4_dst2 = Match([("IPV4_DST", 2, None)])
        self.ipv4_src2_dst2 = Match([("IPV4_SRC", 2, None),
                                     ("IPV4_DST", 2, None)])
        self.ipv4_src1m = Match([("IPV4_SRC", 1, 0x1)])
        self.ipv4_src2m = Match([("IPV4_SRC", 2, 0x2)])
        self.meta_1 = Match([("METADATA", 1, None)])
        self.meta_2m = Match([("METADATA", 2, 0x2)])
        self.vlan_vid_1 = Match([("VLAN_VID", 0x1001, None)])
        self.vlan_vid_2 = Match([("VLAN_VID", 0x1002, None)])
        self.vlan_vid_6 = Match([("VLAN_VID", 0x1006, None)])
        self.vlan_vid1_2 = Match([("VLAN_VID1", 0x1002, None)])

    def test_merging_priorities(self):
        """ Merging priorities is supposed to add priorities.

            Doing this works with merging rules (which have already been
            priority adjusted) to result in the correct priority.
        """
        rule1 = Rule(priority=1)
        rule2 = Rule(priority=2)
        rule100 = Rule(priority=100)
        rule200 = Rule(priority=200)

        self.assertEqual(rule1.merge(rule1).priority, 2)
        self.assertEqual(rule1.merge(rule2).priority, 3)
        self.assertEqual(rule200.merge(rule100).priority, 300)
        self.assertEqual((rule200 + rule100).priority, 300)

    def test_simple_merge_match(self):
        """ Test merging matches works """
        fsrc2 = Rule(priority=0, match=self.ipv4_src2)
        fdst2 = Rule(priority=0, match=self.ipv4_dst2)
        fsrc1 = Rule(priority=0, match=self.ipv4_src1)

        f_expected = Rule(priority=0, match=self.ipv4_src2_dst2)
        # Merge with two different fields
        self.assertEqual(fsrc2.merge(fdst2), f_expected)
        self.assertEqual(fdst2.merge(fsrc2), f_expected)
        self.assertEqual(fsrc2 + fdst2, f_expected)
        self.assertEqual(fdst2 + fsrc2, f_expected)

        # Merge self with self
        self.assertEqual(fsrc2 + fsrc2, fsrc2)

        # Sanity checks
        self.assertNotEqual(fsrc2, fdst2)
        self.assertNotEqual(fsrc2 + fsrc2, fdst2)

        # Exception if match set becomes empty IP:1 intersect IP:2
        self.assertRaises(MergeException, lambda: fsrc2 + fsrc1)
        self.assertRaises(MergeException, lambda: (fdst2 + fsrc1) + fsrc2)

    def test_merge_complex_match(self):
        """ Test merging """
        part1 = Rule(priority=0,
                     match=Match([("IPV4_SRC", 0x12340000, 0xFFFF0000)]))
        part2 = Rule(priority=0,
                     match=Match([("IPV4_SRC", 0x00005678, 0x0000FFFF)]))
        expct = Rule(priority=0,
                     match=Match([("IPV4_SRC", 0x12345678, 0xFFFFFFFF)]))

        self.assertEqual(part1+part2, expct)

    def test_set_and_match(self):
        """ Test the handling of setting a field which is later matched """
        rule1 = Rule(priority=0, match=self.ipv4_src1)
        rule1.instructions.apply_actions.append("SET_FIELD", ("IPV4_SRC", 1))
        rule2 = Rule(priority=0, match=self.ipv4_src2)
        rule2.instructions.apply_actions.append("SET_FIELD", ("IPV4_SRC", 1))
        rule3 = Rule(priority=0, match=self.ipv4_src1)
        rule4 = Rule(priority=0, match=self.ipv4_src2)
        rule5 = Rule(priority=0, match=self.ipv4_src1m)
        rule6 = Rule(priority=0, match=self.ipv4_src2m)
        rule6.instructions.apply_actions.append("SET_FIELD", ("IPV4_SRC", 1))

        """
        Working case, check IPV4_SRC is removed

        Input:
        IPV4_SRC: 2                     +   IPV4_SRC: 1
        Apply(set_field: IPV4_SRC = 1)  +   Apply()

        Expected:
        IPV4_SRC: 2
        Apply(set_field: IPV4_SRC = 1)
        """
        self.assertEqual(rule2 + rule3, rule2)
        # Check setting the field to the same is not removed
        self.assertEqual(rule1 + rule3, rule1)
        # And when masked
        self.assertEqual(rule1 + rule5, rule1)
        self.assertEqual(rule6 + rule5, rule6)

        """
        Error case, check IPV4_SRC is removed

        Input:
        IPV4_SRC: 2                     +   IPV4_SRC: 2
        Apply(set_field: IPV4_SRC = 1)  +   Apply()

        Expected:
        Error, Empty match. As traffic with IPV4_SRC: 1 cannot possibly
        match IPV4_SRC: 2 in the second rule.
        """
        self.assertRaises(MergeException, lambda: rule1 + rule4)
        # And when masked
        self.assertRaises(MergeException, lambda: rule1 + rule6)

    def test_clear_action_sets(self):
        rule1 = Rule(priority=0, match=self.ipv4_src2)
        rule1.instructions.write_actions.append("SET_FIELD", ("IPV4_SRC", 1))
        rule2 = Rule(priority=0, match=self.ipv4_src2)
        rule2.instructions.write_actions.append("SET_FIELD", ("IPV4_SRC", 2))
        rule3 = Rule(priority=0, match=self.ipv4_src2)
        rule3.instructions.write_actions.append("SET_FIELD", ("IPV4_DST", 2))
        rule4 = rule3.copy()
        rule4.instructions.clear_actions = True

        # Check overwrite occurs
        self.assertEqual(rule1 + rule2, rule2)
        self.assertEqual(rule2 + rule1, rule1)

        # Check adding a mix is supported
        expected = rule1.copy()
        expected.instructions.write_actions.append("SET_FIELD",
                                                   ("IPV4_DST", 2))
        self.assertEqual(rule1 + rule3, expected)
        # sanity check
        self.assertNotEqual(rule1, expected)

        # Check Clear works
        self.assertEqual(rule1 + rule4, rule4)

    def test_metadata(self):
        rule1 = Rule(priority=0, match=self.ipv4_src2)
        rule1.instructions.write_metadata = (0xFEFCFDFA, None)
        rule2 = Rule(priority=0, match=self.ipv4_src2)
        rule2.instructions.write_metadata = (0x0000FFFF, None)
        # This is half the match as these are 64 byte
        rule3 = Rule(priority=0, match=self.ipv4_src2)
        rule3.instructions.write_metadata = (0xFEFCFDFA, 0xFFFFFFFF)
        rule4 = Rule(priority=0, match=self.ipv4_src2)
        rule4.instructions.write_metadata = (0x0000FFFF, 0xFFFFFFFF)
        rule5 = Rule(priority=0, match=self.ipv4_src2)
        rule5.instructions.write_metadata = (0xFEFCFDFA00000000, 0xFFFFFFFF00000000)
        rule6 = Rule(priority=0, match=self.ipv4_src2)
        rule6.instructions.write_metadata = (0xFEFCFDFA0000FFFF, 0xFFFFFFFFFFFFFFFF)
        rule7 = Rule(priority=0, match=self.ipv4_src2)
        rule7.instructions.write_metadata = (0x0, 0xFFFFFFFFFFFFFFF0)

        # Test cases
        self.assertEqual(rule1 + rule2, rule2)
        self.assertEqual(rule2 + rule1, rule1)
        self.assertEqual(rule1 + rule4, rule2)
        self.assertEqual(rule1 + rule3, rule1)
        self.assertEqual(rule3 + rule4, rule4)
        self.assertEqual(rule4 + rule5, rule6)
        self.assertEqual(rule5 + rule4, rule6)

        # Now check masking and matching
        # Check an invalid match will fail
        mrule1 = Rule(priority=0, match=self.meta_1)
        self.assertRaises(MergeException, lambda: rule1 + mrule1)

        # Merging partial metadata sets and matches
        #
        # The correct behaviour is to remove matching set values.
        # More correctly one should remove set bits, in the case of
        # metadata the result is a partial metadata match.
        #
        # Match:  *                         + Metadata=(1, None)
        # Action: WriteMeta:(0x0, 0xFF..F0) +
        #
        # Expecting:
        # Match:  Meta=(1,0xF)
        # Action: WriteMeta:(0x0, 0xFF..F0)

        expected = rule7.copy()
        expected.match.append('METADATA', 0x1, 0xF)
        self.assertEqual(rule7 + mrule1, expected)

        # Try a complex case
        d1 = Rule(priority=0, match=Match())
        d1.instructions.write_metadata = (0x10, 0x10)
        d2 = Rule(priority=0, match=Match())
        d2.instructions.write_metadata = (0x1, 0x1)
        d3 = Rule(priority=0,
                  match=Match([('METADATA', 0x10, 0x10)]))
        d3.instructions.write_metadata = (0x100, 0x100)
        d4 = Rule(priority=0,
                  match=Match([('METADATA', 0x111, 0x111)]))

        expected = Rule(priority=0, match=Match())
        expected.instructions.write_metadata = (0x111, 0x111)

        self.assertEqual(d1+d2+d3+d4, expected)
        self.assertEqual((d1+d2)+(d3+d4), expected)
        self.assertEqual(d1+(d2+d3)+d4, expected)
        self.assertEqual(d1+(d2+(d3+d4)), expected)

        # This should fail if table the first is set to 0
        d1.instructions.write_metadata = (0x00, 0x10)
        self.assertRaises(MergeException, lambda: d1+d2+d3+d4)
        self.assertRaises(MergeException, lambda: (d1+d2)+(d3+d4))
        self.assertRaises(MergeException, lambda: d1+(d2+d3)+d4)
        self.assertRaises(MergeException, lambda: d1+(d2+(d3+d4)))

        # Check original metadata match + set's intersection is calcuated
        # correctly
        rule8 = Rule(priority=0, match=Match([("METADATA", 0x1, 0x1)]))
        rule8.instructions.write_metadata = (0x0, 0x2)
        rule9 = Rule(priority=0, match=Match([("METADATA", 0x0, None)]))
        self.assertRaises(MergeException, lambda: rule8+rule9)

        rule10 = Rule(priority=0, match=Match([("METADATA", 0x1, None)]))
        expected = Rule(priority=0,
                        match=Match([("METADATA", 0x1, 0xFFFFFFFFFFFFFFFD)]))
        expected.instructions.write_metadata = (0x0, 0x2)
        self.assertEqual(rule8+rule10, expected)


    def test_pop_vlan(self):
        """
        Test the POP_VLAN, MATCH VLAN_VID case
        """

        # Test single pop, i.e. match 2nd header
        rule1 = Rule(priority=0, match=self.vlan_vid_1)
        rule1.instructions.apply_actions.append("POP_VLAN", None)
        rule2 = Rule(priority=0, match=self.vlan_vid_2)

        expt_m = Match([("VLAN_VID", 0x1001, None),
                        ("VLAN_VID1", 0x1002, None)])
        expt = Rule(priority=0, match=expt_m)
        expt.instructions.apply_actions.append("POP_VLAN", None)
        self.assertEqual(rule1.merge(rule2, False), expt)
        # Merging fails to return a valid openflow rule
        self.assertRaises(MergeException, lambda: rule1.merge(rule2, True))
        self.assertRaises(MergeException, lambda: rule1+rule2)

    def test_double_pop_vlan(self):
        """
        Test double pop case and match 3rd header case
        """
        rule1 = Rule(priority=0, match=self.vlan_vid_1)
        rule1.instructions.apply_actions.append("POP_VLAN", None)
        rule1.instructions.apply_actions.append("POP_VLAN", None)
        rule2 = Rule(priority=0, match=self.vlan_vid_2)

        expt_m = Match([("VLAN_VID", 0x1001, None),
                        ("VLAN_VID2", 0x1002, None)])
        expt = Rule(priority=0, match=expt_m)
        expt.instructions.apply_actions.append("POP_VLAN", None)
        expt.instructions.apply_actions.append("POP_VLAN", None)

        self.assertEqual(rule1.merge(rule2, False), expt)
        # Merging fails to return a valid openflow rule
        self.assertRaises(MergeException, lambda: rule1.merge(rule2, True))
        self.assertRaises(MergeException, lambda: rule1+rule2)

    def test_push_pop_vlan(self):
        """Test push pop combo is ignored

                      rule1                        rule2
        M: VLAN_VID:1                         M: VLAN_VID:1
        A: PUSH_VLAN, VLAN_VID:2, POP_VLAN    A:

        Expected rule1
        Then try combos without rule1 match, and without rule2 match
        """

        rule1 = Rule(priority=0, match=self.vlan_vid_1)
        rule1.instructions.apply_actions.append("PUSH_VLAN", 0x800)
        rule1.instructions.apply_actions.append("SET_FIELD", ('VLAN_VID', 2))
        rule1.instructions.apply_actions.append("POP_VLAN", None)
        rule2 = Rule(priority=0, match=self.vlan_vid_1)
        self.assertEqual(rule1.merge(rule2, False), rule1)
        # Check without rule2 match
        self.assertEqual(rule1.merge(Rule(priority=0), False), rule1)
        # Check without rule1 match
        rule1_nomatch = Rule(priority=0)
        rule1_nomatch.instructions.apply_actions = rule1.instructions.apply_actions.copy()
        self.assertEqual(rule1_nomatch.merge(rule2, False), rule1)
        # The resulting rule is valid openflow
        self.assertEqual(rule1_nomatch.merge(rule2, True), rule1)
        self.assertEqual(rule1_nomatch+rule2, rule1)

    def test_push_vlan(self):
        """ Push and match, later pop """
        rule1 = Rule(priority=0)
        rule1.instructions.apply_actions.append("PUSH_VLAN", 0x800)
        rule1.instructions.apply_actions.append("SET_FIELD", ('VLAN_VID', 6))
        rule2 = Rule(priority=0,
                     match=Match([('VLAN_VID', 0x1006, None),
                                  ('VLAN_VID1', 0x1002, None)]))
        rule2.instructions.apply_actions.append("POP_VLAN", None)
        rule2.instructions.apply_actions.append("OUTPUT", 1)
        expt = Rule(priority=0, match=Match([('VLAN_VID', 0x1002, None)]))
        expt.instructions.apply_actions.append("PUSH_VLAN", 0x800)
        expt.instructions.apply_actions.append("SET_FIELD", ('VLAN_VID', 6))
        expt.instructions.apply_actions.append("POP_VLAN", None)
        expt.instructions.apply_actions.append("OUTPUT", 1)

        self.assertEqual(rule1.merge(rule2, False), expt)
        # The resulting rule is valid openflow
        self.assertEqual(rule1.merge(rule2, True), expt)
        self.assertEqual(rule1+rule2, expt)

    def test_push_pop_vlan_complex(self):
        """ Test complex combinations work associatively
        # rule1
        # M: 1
        # A: SET:2
        # rule2
        # M: *
        # A: Push: 6
        # rule3
        # M: 6
        # A: POP
        # rule4
        # M: 2
        # A: Output:1
        """

        rule1 = Rule(priority=0, match=self.vlan_vid_1)
        rule1.instructions.apply_actions.append("SET_FIELD", ('VLAN_VID', 2))
        rule2 = Rule(priority=0)
        rule2.instructions.apply_actions.append("PUSH_VLAN", 0x800)
        rule2.instructions.apply_actions.append("SET_FIELD", ('VLAN_VID', 6))
        rule3 = Rule(priority=0, match=self.vlan_vid_6)
        rule3.instructions.apply_actions.append("POP_VLAN", None)
        rule4 = Rule(priority=0, match=self.vlan_vid_2)
        rule4.instructions.apply_actions.append("OUTPUT", 1)

        expt = Rule(priority=0, match=self.vlan_vid_1)
        expt.instructions.apply_actions.append("SET_FIELD", ('VLAN_VID', 2))
        expt.instructions.apply_actions.append("PUSH_VLAN", 0x800)
        expt.instructions.apply_actions.append("SET_FIELD", ('VLAN_VID', 6))
        expt.instructions.apply_actions.append("POP_VLAN", None)
        expt.instructions.apply_actions.append("OUTPUT", 1)
        self.assertEqual(rule1.merge(rule2, False).merge(rule3, False).merge(rule4, False),
                         expt)
        self.assertEqual(rule1.merge(rule2.merge(rule3, False).merge(rule4, False), False),
                         expt)
        self.assertEqual(rule1.merge(rule2.merge(rule3.merge(rule4, False), False), False),
                         expt)
        self.assertEqual(rule1.merge(rule2.merge(rule3, False), False).merge(rule4, False),
                         expt)


if __name__ == '__main__':
    unittest.main()
