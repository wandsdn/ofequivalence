#!/usr/bin/env python
""" Tests for the Match class """

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
from ofequivalence.rule import Match


class TestMatch(unittest.TestCase):

    def setUp(self):
        self.empty_match = Match()
        self.fm_full = Match()
        self.fm_full.append('in_port', 1, None)
        self.fm_full.append('vlan_vid', 0x1000, 0x1000)

    def test_empty_length(self):
        self.assertEqual(len(self.empty_match), 0)
        self.assertEqual(self.empty_match.required_mask, 0)

    def test_filled_length(self):
        self.assertEqual(len(self.fm_full), 2)
        self.assertEqual(bin(self.fm_full.required_mask).count('1'),
                         len(self.fm_full))

    def test_empty_iteration(self):
        count = 0
        for _ in self.empty_match:
            count += 1
        self.assertEqual(count, 0)

    def test_not_equal(self):
        self.assertNotEqual(self.empty_match, self.fm_full)
        self.assertEqual(len(set([self.empty_match, self.fm_full])), 2)
        self.assertNotEqual(self.empty_match, 1)
        self.assertNotEqual(self.empty_match, "blah")
        self.assertNotEqual(self.empty_match, object())

    def test_append(self):
        match = Match()
        match.append('in_port', 1, None)
        self.assertEqual(len(match), 1)
        self.assertEqual(bin(match.required_mask).count('1'), len(match))
        match.append('vlan_vid', 0x1000, 0x1000)
        self.assertEqual(len(match), 2)
        self.assertEqual(bin(match.required_mask).count('1'), len(match))

        count = 0
        for _ in match:
            count += 1
        self.assertEqual(count, 2)

        self.assertEqual(match['in_port'][0:2], (1, None))
        self.assertEqual(match['vlan_vid'][0:2], (0x1000, 0x1000))

        # Ensure two uniqually copied versions work
        self.assertEqual(match, self.fm_full)
        self.assertEqual(len(set([match, self.fm_full])), 1)

    def test_duplicate_empty(self):
        new = Match(self.empty_match)
        self.assertEqual(self.empty_match, new)
        # Check this works with sets (only one copy)
        self.assertEqual(len(set([self.empty_match, new])), 1)
        self.assertEqual(len(new), 0)
        self.assertEqual(new.required_mask, 0)

    def test_duplicate_full(self):
        new = Match(self.fm_full)
        self.assertEqual(self.fm_full, new)
        # Check this works with sets (only one copy)
        self.assertEqual(len(set([self.fm_full, new])), 1)
        self.assertEqual(len(new), 2)
        self.assertEqual(bin(new.required_mask).count('1'), len(new))

    def test_delete(self):
        del self.fm_full['in_port']
        self.assertEqual(len(self.fm_full), 1)
        self.assertEqual(bin(self.fm_full.required_mask).count('1'),
                         len(self.fm_full))
        del self.fm_full['vlan_vid']
        self.assertEqual(len(self.fm_full), 0)
        self.assertEqual(bin(self.fm_full.required_mask).count('1'),
                         len(self.fm_full))
        self.assertEqual(self.empty_match, self.fm_full)
        self.assertEqual(len(set([self.empty_match, self.fm_full])), 1)

    def test_special(self):
        # Attempt to a add a bad name and check this works correctly
        # assigning a unique yet constant numbering scheme
        full_mask = self.fm_full.required_mask
        match = Match()
        match.append('bad_field', 0x50, 0xfff0)
        self.fm_full.append('bad_field', 0x40, None)

        self.assertEqual(len(match), 1)
        self.assertEqual(bin(match.required_mask).count('1'), len(match))
        self.assertEqual(len(self.fm_full), 3)
        self.assertEqual(bin(self.fm_full.required_mask).count('1'),
                         len(self.fm_full))

        # Check that the same bit gets set for both
        self.assertEqual(match.required_mask,
                         self.fm_full.required_mask - full_mask)
        self.fm_full.append('bad_field2', 1, 1)
        self.assertEqual(len(self.fm_full), 4)
        self.assertEqual(bin(self.fm_full.required_mask).count('1'),
                         len(self.fm_full))

    def test_normalised(self):
        """ Check masks and values are normalised.
            Such that masked out bits are not set, and that an overlength mask
            is truncated.

            Checking using VLAN_VID as this uses 13bits i.e. fullmask=0x1FFF
        """
        # VLAN_VID uses 13 bits

        # Sanity checks
        self.assertEqual(Match([('VLAN_VID', 0x1, None)]),
                         Match([('VLAN_VID', 0x1, None)]))
        self.assertNotEqual(Match([('VLAN_VID', 0x1, None)]),
                            Match([('VLAN_VID', 0x2, None)]))
        self.assertNotEqual(Match([('VLAN_VID', 0x1, None)]),
                            Match([('VLAN_VID', 0x1, 0xFFF)]))

        # Check a full mask is normalised?
        self.assertEqual(Match([('VLAN_VID', 0x1, None)]),
                         Match([('VLAN_VID', 0x1, 0x1FFF)]))
        self.assertEqual(Match([('VLAN_VID', 0x1, None)]),
                         Match([('VLAN_VID', 0x1, 0xFFFF)]))
        self.assertEqual(Match([('VLAN_VID', 0x1, None)]),
                         Match([('VLAN_VID', 0x1, 0x123123FFFFFF)]))

        # Check that values are normalised
        self.assertEqual(Match([('VLAN_VID', 0x1, 0x1)]),
                         Match([('VLAN_VID', 0x11, 0x1)]))
        # Check both
        self.assertEqual(Match([('VLAN_VID', 0x1051, None)]),
                         Match([('VLAN_VID', 0x1231051, 0xFFFF)]))

    def test_subset(self):
        self.assertTrue(Match([('VLAN_VID', 0x1, None)]).issubset(
                        Match([('VLAN_VID', 0x1, None)])))
        self.assertFalse(Match([('VLAN_VID', 0x2, None)]).issubset(
            Match([('VLAN_VID', 0x1, None)])))
        self.assertFalse(Match([('VLAN_VID', 0x1, None)]).issubset(
            Match([('VLAN_VID', 0x1, None), ('IN_PORT', 0x1, None)])))
        self.assertTrue(Match([('VLAN_VID', 0x1, None), ('IN_PORT', 0x1, None)]).issubset(
            Match([('VLAN_VID', 0x1, None)])))


if __name__ == '__main__':
    unittest.main()
