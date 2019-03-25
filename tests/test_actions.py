#!/usr/bin/env python
""" Tests for the ActionSet and ActionList objects """

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
from random import Random
import ryu.ofproto.ofproto_v1_3 as ofproto
from six import string_types
from ofequivalence.openflow_desc import OpenFlow1_3_5
from ofequivalence.rule import ActionList, ActionSet

G_OF = OpenFlow1_3_5()


class TestActionList(unittest.TestCase):
    """ Tests for the ActionSet and ActionList objects """

    def setUp(self):
        self.acts = {x[6:] for x in dir(ofproto) if x.startswith("OFPAT")}
        self.oxms = {x[11:] for x in dir(ofproto)
                     if x.startswith("OFPXMT_OFB")}
        self.action_list_complex = [("SET_FIELD", ("ETH_SRC", 643)),  # 0
                                    ("SET_FIELD", ("ETH_DST", 1090)),  # 1
                                    ("SET_QUEUE", 1),  # 2
                                    ("OUTPUT", 6),  # 3
                                    ("OUTPUT", 2),  # 4
                                    ("OUTPUT", 1),  # 5
                                    ("GROUP", 4),  # 6
                                    ("SET_FIELD", ("ETH_SRC", 644)),  # 7
                                    ("SET_FIELD", ("ETH_DST", 1080)),  # 8
                                    ("PUSH_VLAN", 0x8100),  # 9
                                    ("SET_FIELD", ("VLAN_VID", 45)),  # 10
                                    ("SET_FIELD", ("VLAN_PCP", 2)),  # 11
                                    ("GROUP", 5),  # 12
                                    ("OUTPUT", 5),  # 13
                                    ("SET_QUEUE", 2),  # 14
                                    ("OUTPUT", 3),  # 15
                                    ("OUTPUT", 4),  # 16
                                    ]
        self.action_list_nonreorderable = [("SET_FIELD", ("ETH_DST", 45)),
                                           ("SET_FIELD", ("ETH_DST", 1)),
                                           ("OUTPUT", 1),
                                           ("SET_FIELD", ("VLAN_VID", 0x100F)),
                                           ("PUSH_VLAN", 0x88a8),
                                           ("SET_FIELD", ("VLAN_VID", 0x1015)),
                                           ("OUTPUT", 5)
                                           ]

    def is_valid_action(self, act):
        if isinstance(act, string_types):
            self.assertIn(act, self.acts)
        else:
            self.assertEqual(act[0], "SET_FIELD")
            self.assertIn(act[1], self.oxms)

    def test_dependencies_exist(self):
        """ Check that all standard fields are included and
            correctly spelt etc.
        """
        acts = set()
        oxms = set()

        # Check that all are valid
        # And build a set of those mapped
        for action, deps in G_OF.action_dependancies.items():
            self.is_valid_action(action)
            if isinstance(action, string_types):
                acts.add(action)
            else:
                oxms.add(action[1])
            for dep_action in deps:
                self.is_valid_action(dep_action)
        acts.add("EXPERIMENTER")
        self.assertSetEqual(acts, self.acts)
        self.assertSetEqual(oxms, self.oxms)

    def test_simple_fully_dep(self):
        """
        Tests some simple cases in which the order
        matters and as the such the same result should
        be expected
        """
        action_list1 = [("SET_FIELD", ("ETH_DST", 45)),
                        ("SET_FIELD", ("ETH_DST", 1))]
        action_list2 = [("SET_FIELD", ("VLAN_VID", 0x100F)),
                        ("PUSH_VLAN", 0x88a8),
                        ("SET_FIELD", ("VLAN_VID", 0x1015))]

        self.assertEqual(action_list1, list(ActionList(action_list1)))
        self.assertEqual(action_list2, list(ActionList(action_list2)))

    def test_simple_fully_dep_reverse(self):
        """
        Reversed to ensure it was not fluke sorting
        """
        action_list1 = [("SET_FIELD", ("ETH_DST", 1)),
                        ("SET_FIELD", ("ETH_DST", 45))]
        action_list2 = [("SET_FIELD", ("VLAN_VID", 0x1015)),
                        ("PUSH_VLAN", 0x88a8),
                        ("SET_FIELD", ("VLAN_VID", 0x100F))]

        self.assertEqual(action_list1, list(ActionList(action_list1)))
        self.assertEqual(action_list2, list(ActionList(action_list2)))

    def test_simple_unordered(self):
        """
        Test on a couple of sets where order does not matter
        """
        import itertools
        action_list1 = [("SET_FIELD", ("ETH_DST", 1)),
                        ("SET_FIELD", ("VLAN_VID", 45)),
                        ("SET_QUEUE", 1),
                        ("PUSH_MPLS", 0x8847)]

        expected = ActionList(action_list1)
        for permuation in itertools.permutations(action_list1):
            res = ActionList(permuation)
            self.assertEqual(expected, res)

    def assertIsBefore(self, first, second, list_):
        self.assertLess(list_.index(first), list_.index(second))

    def test_complex_actions(self):
        """
        Test a huge dependency mess of rules
        """
        action_list1 = self.action_list_complex
        result = ActionList(action_list1)

        # The first 3 can be reordered amongst themselves
        self.assertSetEqual(set(action_list1[0:3]), set(result[0:3]))
        # And the next 4
        self.assertSetEqual(set(action_list1[3:7]), set(result[3:7]))
        # And the next 5
        self.assertSetEqual(set(action_list1[7:12]), set(result[7:12]))
        # However within that the push vlan must become the set vlan
        self.assertIsBefore(("PUSH_VLAN", 0x8100),
                            ("SET_FIELD", ("VLAN_VID", 45)), result)
        self.assertIsBefore(("PUSH_VLAN", 0x8100),
                            ("SET_FIELD", ("VLAN_PCP", 2)), result)
        # The next two can be reordered
        self.assertSetEqual(set(action_list1[12:14]), set(result[12:14]))
        # The SET_QUEUE must be before the final two outputs
        self.assertSetEqual(set(action_list1[14]), set(result[14]))
        # The final 2 can be reordered
        self.assertSetEqual(set(action_list1[15:17]), set(result[15:17]))

    def test_contains(self):
        actions = ActionList(self.action_list_complex)
        self.assertEqual(len(self.action_list_complex), len(actions))
        for action in self.action_list_complex:
            self.assertIn(action, actions)

        self.assertNotIn(("PUSH_MPLS", 0x8847), actions)
        self.assertNotIn(("POP_MPLS", 0x0800), actions)
        self.assertNotIn(("POP_MPLS", 0x0800), actions)
        self.assertNotIn(("OUTPUT", 20), actions)

    def test_index_slice_len(self):
        # These all have dependencies and cannot be interlaced
        action_list = self.action_list_nonreorderable
        actions = ActionList(action_list)

        self.assertEqual(len(action_list), len(actions))
        self.assertEqual(0, len(ActionList()))
        self.assertFalse(ActionList())
        self.assertTrue(actions)

        for i, orig_action in enumerate(action_list):
            # Check the correct item is returned
            self.assertEqual(orig_action, actions[i])
            # Check the correct index is returned
            self.assertEqual(i, actions.index(actions[i]))

        # Now lets check we can do some slicing - note length
        # Note slicing returns normal lists not Actions back
        self.assertListEqual(action_list[:], actions[:])
        self.assertListEqual(action_list[::-1], actions[::-1])
        self.assertListEqual(action_list[2:], actions[2:])
        self.assertListEqual(action_list[3::2], actions[3::2])
        self.assertListEqual(action_list[1:-1], actions[1:-1])
        self.assertListEqual(action_list[1:len(actions)-1],
                             actions[1:len(actions)-1])

    def test_removal(self):
        # Check that removing an object works and that lists are
        # correctly reordered. In the case a something is removed
        # it may require other items to be placed into a higher level
        action_list = self.action_list_complex
        actions = ActionList(action_list)

        # Constant seed used here :)
        random = Random(143)

        # We will remove a random item until the list is empty
        # Checking each time the result matches a new list.
        while actions:
            random_item = actions[random.randint(0, len(actions)-1)]
            actions.remove(random_item)
            action_list.remove(random_item)
            self.assertEqual(actions, ActionList(action_list))

    def _test_add(self, left, right, expected, expected_rev):
        """ Tests that adding using '+' '+=' and copy(add=x) all have the same
            result
        """
        # Check '+'
        res = left + right
        self.assertIsNot(res, left)
        self.assertIsNot(res, right)
        self.assertIsInstance(res, left.__class__)
        self.assertEqual(res, expected)
        res = right + left
        self.assertIsNot(res, left)
        self.assertIsNot(res, right)
        self.assertIsInstance(res, right.__class__)
        self.assertEqual(res, expected_rev)

        # Check copy(add=)
        res = left.copy(add=right)
        self.assertIsNot(res, left)
        self.assertIsNot(res, right)
        self.assertIsInstance(res, left.__class__)
        self.assertEqual(res, expected)
        res = right.copy(add=left)
        self.assertIsNot(res, left)
        self.assertIsNot(res, right)
        self.assertIsInstance(res, right.__class__)
        self.assertEqual(res, expected_rev)

        # Check '+='
        dup_obj = left.copy()
        res = dup_obj
        res += right
        self.assertIs(dup_obj, res)
        self.assertEqual(res, expected)
        dup_obj = right.copy()
        res = dup_obj
        res += left
        self.assertIs(dup_obj, res)
        self.assertEqual(res, expected_rev)

    def test_adding_lists(self):
        # Tests the '+', '+=' and copy(add=) operations for Action Lists
        actions1 = ActionList(self.action_list_complex)
        actions2 = ActionList(self.action_list_nonreorderable)
        # This should be the same as adding the two original lists together
        expected = ActionList(self.action_list_complex +
                              self.action_list_nonreorderable)
        expected_rev = ActionList(self.action_list_nonreorderable +
                                  self.action_list_complex)

        self._test_add(actions1, actions2, expected, expected_rev)

    def test_action_set_ordering(self):
        # Test adding sets together and set and list combos
        actlista = [('OUTPUT', 1),
                    ('SET_FIELD', ('VLAN_VID', 0x1003)),
                    ('SET_FIELD', ('VLAN_PCP', 0x1)),
                    ('PUSH_VLAN', None)]
        actlista_ordered = [('PUSH_VLAN', None),
                            ('SET_FIELD', ('VLAN_VID', 0x1003)),
                            ('SET_FIELD', ('VLAN_PCP', 0x1)),
                            ('OUTPUT', 1)]
        actlistb = [('SET_QUEUE', 5),
                    ('SET_FIELD', ('IPV4_SRC', 12))]
        actlistc = [('SET_FIELD', ('VLAN_PCP', 0x2)),
                    ('PUSH_VLAN', None),
                    ('OUTPUT', 2)]
        actlistc_ordered = [('PUSH_VLAN', None),
                            ('SET_FIELD', ('VLAN_PCP', 0x2)),
                            ('OUTPUT', 2)]
        actlistd = [('OUTPUT', 7)]
        actliste = [('GROUP', 8)]
        actlistf = [('GROUP', 9)]

        seta = ActionSet(actlista)
        setb = ActionSet(actlistb)
        setc = ActionSet(actlistc)
        setd = ActionSet(actlistd)
        sete = ActionSet(actliste)
        setf = ActionSet(actlistf)

        # Sanity check, check ordering is correct
        self.assertEqual(seta, ActionList(actlista_ordered))
        self.assertEqual(setc, ActionList(actlistc_ordered))

        # Now lets add some sets together!

        # Set a and b dont overlap, both orders should be equal
        expected = [('PUSH_VLAN', None),
                    ('SET_FIELD', ('IPV4_SRC', 12)),
                    ('SET_FIELD', ('VLAN_VID', 0x1003)),
                    ('SET_FIELD', ('VLAN_PCP', 0x1)),
                    ('SET_QUEUE', 5),
                    ('OUTPUT', 1)]
        expected = ActionList(expected)

        self._test_add(seta, setb, expected, expected)

        # Set a and c entirely overlap, OUTPUT, VLAN_PCP and QUEUE
        expected = [('PUSH_VLAN', None),
                    ('SET_FIELD', ('VLAN_VID', 0x1003)),
                    ('SET_FIELD', ('VLAN_PCP', 0x2)),
                    ('OUTPUT', 2)]
        expected = ActionList(expected)
        self._test_add(seta, setc, expected, ActionList(actlista_ordered))

        # Check special case with 'GROUP', groups overwrite 'OUTPUT' in the
        # result yet they both can be added

        expected = ActionSet([('GROUP', 8)])
        self._test_add(setd, sete, expected, expected)

        expectedb = ActionSet([('GROUP', 9)])
        self._test_add(sete, setf, expectedb, expected)

    def test_list_add_set(self):
        # Test that adding a set to a list works and a list to a set
        actlista = [('OUTPUT', 1),
                    ('SET_FIELD', ('VLAN_VID', 0x1003)),
                    ('SET_FIELD', ('VLAN_PCP', 0x1)),
                    ('PUSH_VLAN', None)]
        actlista_ordered = [('PUSH_VLAN', None),
                            ('SET_FIELD', ('VLAN_VID', 0x1003)),
                            ('SET_FIELD', ('VLAN_PCP', 0x1)),
                            ('OUTPUT', 1)]
        act_list = self.action_list_nonreorderable
        lista = ActionList(act_list)
        seta = ActionSet(actlista)

        set_add_list = ActionList([("PUSH_VLAN", 0x88a8),
                                   ("SET_FIELD", ("ETH_DST", 1)),
                                   ("SET_FIELD", ("VLAN_VID", 0x1015)),
                                   ('SET_FIELD', ('VLAN_PCP', 0x1)),
                                   ("OUTPUT", 5)])
        list_add_set = ActionList(act_list + actlista_ordered)

        self._test_add(seta, lista, set_add_list, list_add_set)


if __name__ == '__main__':
    unittest.main()
