""" Test that a BDD is working how we expect it to. """

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

import random
from ofequivalence.rule import Match
from ofequivalence.openflow_desc import OpenFlow1_3_5


class BaseBDD(object):

    def setUp(self, _bdd):
        global wc_to_BDD
        global BDD
        global IS_DIFFERING
        global BDD_to_wcs
        wc_to_BDD = _bdd.wc_to_BDD
        BDD = _bdd.BDD
        BDD_to_wcs = _bdd.BDD_to_wcs

        self.IN_PORT0 = Match([('IN_PORT', 0, None)]).get_wildcard()
        self.IN_PORT1 = Match([('IN_PORT', 1, None)]).get_wildcard()
        self.IN_PORT0_ETH_SRC1 = Match([
            ('IN_PORT', 0, None), ('ETH_SRC', 1, None)]).get_wildcard()
        self.IN_PORT0_ETH_DST1 = Match([
            ('IN_PORT', 0, None), ('ETH_DST', 1, None)]).get_wildcard()
        self.IN_PORT0_ETH_DST1_ETH_SRC1 = Match([
            ('IN_PORT', 0, None), ('ETH_DST', 1, None),
            ('ETH_SRC', 1, None)]).get_wildcard()
        self.IN_PORT0_ETH_SRC1 = Match([
            ('IN_PORT', 0, None), ('ETH_SRC', 1, None)]).get_wildcard()
        self.IN_PORT0_ETH_DST2 = Match([
            ('IN_PORT', 0, None), ('ETH_DST', 2, None)]).get_wildcard()
        self.IN_PORT0_ETH_DST2_ETH_SRC1 = Match([
            ('IN_PORT', 0, None), ('ETH_DST', 2, None),
            ('ETH_SRC', 1, None)]).get_wildcard()
        self.zero_bdd = BDD()
        self.zero_bdd2 = BDD()
        self.DIFF = _bdd.IS_DIFFERING_TUPLE
        self.OF = OpenFlow1_3_5()

    def test_stress_meld_16(self):
        """ Check that we can combine 0-15 to create a /4 mask """
        TA = "A"
        a = Match([('IN_PORT', 0, 0x1f)])
        u_bdd = wc_to_BDD(a.get_wildcard(), TA, TA)
        rng = [4, 14, 9, 2, 5, 10, 7, 8, 12, 13, 3, 6, 15, 1, 11]
        for i in rng:
            m = Match([('IN_PORT', i, 0x1f)])
            m_bdd = wc_to_BDD(m.get_wildcard(), TA, TA)
            n_bdd = u_bdd + m_bdd
            # Check the result of the opposite works, as these are
            # non-overlapping sections
            self.assertEqual(n_bdd, (m_bdd + u_bdd))
            u_bdd = n_bdd
        r = Match([('IN_PORT', 0, 0x10)])
        r_bdd = wc_to_BDD(r.get_wildcard(), TA, TA)
        # The 16 exact matches, should have combined into a single range
        self.assertEqual(u_bdd, r_bdd)

    def test_stress_meld_66535(self):
        """ Check that we can combine 0-66535 to create a /16 mask """
        TA = "A"
        a = Match([('IN_PORT', 0, 0x1ffff)])
        u_bdd = wc_to_BDD(a.get_wildcard(), TA, TA)
        rng = range(1, 65536)
        random.seed(0)
        random.shuffle(list(rng))
        for i in rng:
            m = Match([('IN_PORT', i, 0x1ffff)])
            m_bdd = wc_to_BDD(m.get_wildcard(), TA, TA)
            n_bdd = u_bdd + m_bdd
            # Check the result of the opposite works, as these are
            # non-overlapping sections
            self.assertEqual(n_bdd, (m_bdd + u_bdd))
            u_bdd = n_bdd
        r = Match([('IN_PORT', 0, 0x10000)])
        r_bdd = wc_to_BDD(r.get_wildcard(), TA, TA)
        # The 16 exact matches, should have combined into a single range
        self.assertEqual(u_bdd, r_bdd)

    def test_comparing_bdd(self):
        """ Check that comparing BDD's for equality works """
        TA = "A"
        TB = "B"
        bdd_a = wc_to_BDD(self.IN_PORT0, TA, TA)
        bdd_a2 = wc_to_BDD(self.IN_PORT0, TA, TA)
        bdd_a_diff = wc_to_BDD(self.IN_PORT1, TA, TA)

        bdd_b = wc_to_BDD(self.IN_PORT0, TB, TB)
        bdd_b2 = wc_to_BDD(self.IN_PORT0, TB, TB)

        self.assertEqual(bdd_a, bdd_a)
        self.assertEqual(bdd_a2, bdd_a2)
        self.assertIsNot(bdd_a, bdd_a2)  # Sanity
        self.assertEqual(bdd_a, bdd_a2)
        self.assertEqual(bdd_b, bdd_b2)
        self.assertNotEqual(bdd_a_diff, bdd_a)
        self.assertNotEqual(bdd_a, bdd_a_diff)
        self.assertNotEqual(bdd_a, bdd_b)
        self.assertNotEqual(bdd_b, bdd_a)

        # Check combinations of empty (None) BDD's
        self.assertEqual(self.zero_bdd, self.zero_bdd)
        self.assertIsNot(self.zero_bdd, self.zero_bdd2)  # Sanity
        self.assertEqual(self.zero_bdd, self.zero_bdd2)
        self.assertNotEqual(self.zero_bdd, bdd_a)
        self.assertNotEqual(bdd_a, self.zero_bdd)

    def test_meld_overlapping(self):
        """ Check that A is preferred, and only the non-overlapping portion of
            B is added. """
        TA = "A"
        TB = "B"
        bdd_a = wc_to_BDD(self.IN_PORT0, TA, TA)
        bdd_b = wc_to_BDD(self.IN_PORT0, TB, TB)

        bdd_e = bdd_a + bdd_b
        self.assertEqual(bdd_a, bdd_e)
        self.assertNotEqual(bdd_b, bdd_e)

        bdd_c = wc_to_BDD(self.IN_PORT0_ETH_DST1, TA, TA)
        bdd_c_diff = wc_to_BDD(self.IN_PORT0_ETH_DST1, *self.DIFF)
        bdd_d = wc_to_BDD(self.IN_PORT0, TB, TB)

        # Adding d + c = d
        self.assertEqual(bdd_d + bdd_c, bdd_d)

        # Adding c+d = c + (d not in c)
        bdd_r = bdd_c + bdd_d
        # Check the intersection is correct
        self.assertEqual(bdd_r.intersection(bdd_c), bdd_c)
        # Check the difference is bdd_c's space with bdd_d
        self.assertEqual(bdd_r.difference(bdd_d), bdd_c_diff)

    def test_difference(self):
        """ Difference should return packet-space in A, which is either not
            present in B or results in a difference action.
            We return a special IS_DIFFERING when found, otherwise None.
            In the case of an empty space in A not matching empty in B we
            report this as a difference (XXX this might be the wrong thing to
            do).
        """
        TA = "A"
        TB = "B"
        TC = "C"
        TD = "D"
        bdd_a = wc_to_BDD(self.IN_PORT0, TA, TA)
        bdd_b = wc_to_BDD(self.IN_PORT0, TB, TB)
        bdd_diff = wc_to_BDD(Match().get_wildcard(), *self.DIFF)
        port0_diff = wc_to_BDD(self.IN_PORT0, *self.DIFF)

        # The difference between the same is empty
        self.assertEqual(bdd_a.difference(bdd_a), self.zero_bdd)
        self.assertEqual(bdd_b.difference(bdd_b), self.zero_bdd)
        self.assertEqual(self.zero_bdd.difference(self.zero_bdd),
                         self.zero_bdd)

        # The difference between a and b in the whole IN_PORT0 path
        # So we expect IN_PORT0 -> IS_DIFFERING back
        self.assertEqual(bdd_a.difference(bdd_b), port0_diff)
        # Difference is not symmetrical
        self.assertEqual(bdd_a.difference(self.zero_bdd), port0_diff)

        # Difference is not symmetrical
        # XXX Think more about this case, this might be the wrong behaviour
        # then again our solver code probably wont hit it.
        self.assertEqual(self.zero_bdd.difference(bdd_a), bdd_diff)

        # Lets merge up some rule combinations with small differences and see
        # if they are detected
        # Lets Always compare to this:
        # 1) in_port:0,eth_dst:1,eth_src:1 -> A
        # 2) in_port:0,eth_dst:2,eth_src:1 -> B
        # 3) in_port:0,eth_dst:1 -> C
        # 4) in_port:0 -> D

        bdd_comp_to = (wc_to_BDD(self.IN_PORT0_ETH_DST1_ETH_SRC1, TA, TA) +
                       wc_to_BDD(self.IN_PORT0_ETH_DST2_ETH_SRC1, TB, TB) +
                       wc_to_BDD(self.IN_PORT0_ETH_DST1, TC, TC) +
                       wc_to_BDD(self.IN_PORT0, TD, TD))
        # Lets change 1) A -> B, we expect A -> DIFF as a result
        bdd_test = (wc_to_BDD(self.IN_PORT0_ETH_DST1_ETH_SRC1, TB, TB) +
                    wc_to_BDD(self.IN_PORT0_ETH_DST2_ETH_SRC1, TB, TB) +
                    wc_to_BDD(self.IN_PORT0_ETH_DST1, TC, TC) +
                    wc_to_BDD(self.IN_PORT0, TD, TD))
        self.assertEqual(bdd_test.difference(bdd_comp_to),
                         wc_to_BDD(self.IN_PORT0_ETH_DST1_ETH_SRC1, *self.DIFF)
                         )

        # Lets try BOTH 1 and 2 and 3 to -> D i.e. in_port 0 -> D
        bdd_test = wc_to_BDD(self.IN_PORT0, TD, TD)
        expt_diff = (wc_to_BDD(self.IN_PORT0_ETH_DST1_ETH_SRC1, *self.DIFF) +
                     wc_to_BDD(self.IN_PORT0_ETH_DST2_ETH_SRC1, *self.DIFF) +
                     wc_to_BDD(self.IN_PORT0_ETH_DST1, *self.DIFF))
        self.assertEqual(bdd_test.difference(bdd_comp_to), expt_diff)

    def test_subtract(self):
        """ Subtract should return packet-space in A, which is either not
            present in B or results in a difference action.
            In this case A is returned, otherwise None.
        """
        TA = "A"
        TB = "B"
        TC = "C"
        TD = "D"
        bdd_a = wc_to_BDD(self.IN_PORT0, TA, TA)
        bdd_b = wc_to_BDD(self.IN_PORT0, TB, TB)

        # The difference between the same is empty
        self.assertEqual(bdd_a.subtract(bdd_a), self.zero_bdd)
        self.assertEqual(bdd_b.subtract(bdd_b), self.zero_bdd)
        self.assertEqual(self.zero_bdd.subtract(self.zero_bdd),
                         self.zero_bdd)

        # The difference between a and b in the whole IN_PORT0 path
        # So we expect left side back
        self.assertEqual(bdd_a.subtract(bdd_b), bdd_a)
        self.assertEqual(bdd_b.subtract(bdd_a), bdd_b)
        # Difference is not symmetrical
        self.assertEqual(bdd_a.subtract(self.zero_bdd), bdd_a)

        # Difference is not symmetrical
        self.assertEqual(self.zero_bdd.subtract(bdd_a), self.zero_bdd)

        # Lets merge up some rule combinations with small differences and see
        # if they are detected
        # Lets Always compare to this:
        # 1) in_port:0,eth_dst:1,eth_src:1 -> A
        # 2) in_port:0,eth_dst:2,eth_src:1 -> B
        # 3) in_port:0,eth_dst:1 -> C
        # 4) in_port:0 -> D

        bdd_comp_to = (wc_to_BDD(self.IN_PORT0_ETH_DST1_ETH_SRC1, TA, TA) +
                       wc_to_BDD(self.IN_PORT0_ETH_DST2_ETH_SRC1, TB, TB) +
                       wc_to_BDD(self.IN_PORT0_ETH_DST1, TC, TC) +
                       wc_to_BDD(self.IN_PORT0, TD, TD))
        # Lets change 1) A -> B, we expect A -> DIFF as a result
        bdd_test = (wc_to_BDD(self.IN_PORT0_ETH_DST1_ETH_SRC1, TB, TB) +
                    wc_to_BDD(self.IN_PORT0_ETH_DST2_ETH_SRC1, TB, TB) +
                    wc_to_BDD(self.IN_PORT0_ETH_DST1, TC, TC) +
                    wc_to_BDD(self.IN_PORT0, TD, TD))
        # A vs B
        self.assertEqual(bdd_comp_to.subtract(bdd_test),
                         wc_to_BDD(self.IN_PORT0_ETH_DST1_ETH_SRC1, TA, TA)
                         )
        self.assertEqual(bdd_test.subtract(bdd_comp_to),
                         wc_to_BDD(self.IN_PORT0_ETH_DST1_ETH_SRC1, TB, TB)
                         )

        # Lets try BOTH 1 and 2 and 3 to -> D i.e. in_port 0 -> D
        bdd_test = wc_to_BDD(self.IN_PORT0, TD, TD)
        expt_diff = (wc_to_BDD(self.IN_PORT0_ETH_DST1_ETH_SRC1, TA, TA) +
                     wc_to_BDD(self.IN_PORT0_ETH_DST2_ETH_SRC1, TB, TB) +
                     wc_to_BDD(self.IN_PORT0_ETH_DST1, TC, TC))
        self.assertEqual(bdd_comp_to.subtract(bdd_test), expt_diff)
        expt_diff = (wc_to_BDD(self.IN_PORT0_ETH_DST1_ETH_SRC1, TD, TD) +
                     wc_to_BDD(self.IN_PORT0_ETH_DST2_ETH_SRC1, TD, TD) +
                     wc_to_BDD(self.IN_PORT0_ETH_DST1, TD, TD))
        self.assertEqual(bdd_test.subtract(bdd_comp_to), expt_diff)

    def test_intersection(self):
        """ Intersection should return packet-space in both A and B that
            results in the same action (i.e. has the same termination node)
            otherwise None for that space.
        """
        TA = "A"
        TB = "B"
        bdd_a = wc_to_BDD(self.IN_PORT0_ETH_DST1, TA, TA)
        bdd_b = wc_to_BDD(self.IN_PORT0_ETH_SRC1, TA, TA)

        # Intersect in_port=0 eth_dst=1 with in_port=0 eth_src=1
        # Expecting in_port=0 eth_src=0 eth_dst=0
        # Order should not matter, so we check both orders
        bdd_e = wc_to_BDD(self.IN_PORT0_ETH_DST1_ETH_SRC1, TA, TA)

        self.assertEqual(bdd_a.intersection(bdd_b), bdd_e)
        self.assertEqual(bdd_b.intersection(bdd_a), bdd_e)

        bdd_c = wc_to_BDD(self.IN_PORT0_ETH_SRC1, TB, TB)
        self.assertEqual(bdd_c.intersection(bdd_a), self.zero_bdd)
        self.assertEqual(bdd_a.intersection(bdd_c), self.zero_bdd)

        # Check some zero cases
        self.assertEqual(self.zero_bdd.intersection(self.zero_bdd),
                         self.zero_bdd)
        self.assertEqual(bdd_a.intersection(self.zero_bdd), self.zero_bdd)
        self.assertEqual(self.zero_bdd.intersection(bdd_a), self.zero_bdd)

        # Test the cache, by using the input DST_2 we expect to hit the cache
        # for half the results
        bdd_a2 = wc_to_BDD(self.IN_PORT0_ETH_DST2, TA, TA)
        bdd_b2 = wc_to_BDD(self.IN_PORT0_ETH_SRC1, TA, TA)
        bdd_e2 = wc_to_BDD(self.IN_PORT0_ETH_DST2_ETH_SRC1, TA, TA)

        self.assertEqual(bdd_a2.intersection(bdd_b2), bdd_e2)
        self.assertEqual(bdd_b2.intersection(bdd_a2), bdd_e2)

    def test_BDD_len(self):
        """ DEBUG Feature: this helps ensure the walk code works too """
        TA = "A"
        self.assertEqual(len(self.zero_bdd), 0)
        # Length should equal bits + 1 for termination node
        # IN_PORT = 32 ETH_DST = 48
        bdd_a = wc_to_BDD(self.IN_PORT0_ETH_DST1, TA, TA)
        bdd_b = wc_to_BDD(self.IN_PORT0, TA, TA)
        self.assertEqual(len(bdd_a), 32+48+1)
        self.assertEqual(len(bdd_b), 32+1)

    def test_bit_order(self):
        """ Matches within a field will be prefix matching.
            As such ensure that we are encoding the MSB in the highest node.

            This will result in smaller tables, and faster build times.
        """

        # Adding 0101/4 -> A and 1000/2 -> B
        #      *
        #   0/   \1
        #   *     *
        #    \1 0/
        #     *  B
        #   0/
        #   *
        #    \1
        #     A
        # Total of 7 nodes inc. terminals
        # We expect this ordering
        a = Match([("IPV4_SRC", 0x5, 0xF)])
        b = Match([("IPV4_SRC", 0x8, 0xC)])
        TA = "A"
        TB = "B"
        bdd_a = wc_to_BDD(a.get_wildcard(), TA, TA)
        bdd_b = wc_to_BDD(b.get_wildcard(), TB, TB)

        res = bdd_a + bdd_b
        self.assertEqual(len(res), 7)
        print(len(res))

        # Adding the opposite 1010/4 -> A and 0001/1100
        # Results in 8 nodes.
        a = Match([("IPV4_SRC", 0xA, 0xF)])
        b = Match([("IPV4_SRC", 0x1, 0x3)])
        TA = "A"
        TB = "B"
        bdd_a = wc_to_BDD(a.get_wildcard(), TA, TA)
        bdd_b = wc_to_BDD(b.get_wildcard(), TB, TB)

        res = bdd_a + bdd_b
        self.assertEqual(len(res), 8)
        print(len(res))

    def test_conversion_to_from_BDD(self):
        a = Match([("IPV4_SRC", 0x5, 0xF)])
        TA = "A"
        bdd_a = wc_to_BDD(a.get_wildcard(), TA, TA)
        res = list(BDD_to_wcs(bdd_a))
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0][0], a.get_wildcard())

        # Check the first and last fields for off by 1 issues
        # Purposely checking 0xF on the ends as this ensures no off by one
        # error missing a bit

        # Check this first field
        a = Match([(self.OF.ordered_oxm_fields[0],
                    0xF445FA82FF38F92F, None)])
        TA = "A"
        bdd_a = wc_to_BDD(a.get_wildcard(), TA, TA)
        res = list(BDD_to_wcs(bdd_a))
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0][0], a.get_wildcard())

        # Check the last field
        a = Match([(self.OF.ordered_oxm_fields[-1],
                    0xF445FA82FF38F92F, None)])
        TA = "A"
        bdd_a = wc_to_BDD(a.get_wildcard(), TA, TA)
        res = list(BDD_to_wcs(bdd_a))
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0][0], a.get_wildcard())
