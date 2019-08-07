#!/usr/bin/env python
""" Test for the ofequivalence.ruleset implementation """

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
import warnings
from itertools import groupby
from ofequivalence.rule import Rule, Match, Instructions, ActionList, ActionSet
from ofequivalence.ruleset import (to_single_table, MAX_PRIORITY, compress_ruleset,
                                   select_compressed_ruleset, sort_key_ruleset_priority)
from ofequivalence.normalisebdd import check_equal, normalise
from ofequivalence import ruleset_deps_direct
from .rulesets import (ORDERED_COMPRESS1, POORLY_ORDERED_COMPRESS1,
                       ORDERED_COMPRESS2, POORLY_ORDERED_COMPRESS2)

# Lets use the example rulesets from the paper
def build_inst(apply_actions=None, write_actions=None, goto_table=None,
               clear_actions=None):
    inst = Instructions()
    if clear_actions:
        inst.clear_actions = True
    if apply_actions:
        inst.apply_actions = ActionList(apply_actions)
    if write_actions:
        inst.write_actions = ActionSet(write_actions)
    if goto_table:
        inst.goto_table = goto_table
    return inst


def priority_scale(first, second):
    """ This is how we scale priorities for a two table pipeline,
        if this changes we will need to update this code.
    """
    return first * (MAX_PRIORITY) + second


FORWARD_DROP = [
    Rule(priority=10, table=0, match=Match([("IPV4_DST", 0x1, 0x3)]),
         instructions=build_inst(write_actions=[("OUTPUT", 1)],
                                 goto_table=1)),
    Rule(priority=9, table=0, match=Match([("IPV4_DST", 0x2, 0x7)]),
         instructions=build_inst(write_actions=[("OUTPUT", 2)],
                                 goto_table=1)),
    Rule(priority=0, table=0, match=Match()),

    Rule(priority=100, table=1, match=Match([("IPV4_DST", 0x8, 0x8)]),
         instructions=build_inst(clear_actions=True)),
    Rule(priority=0, table=1, match=Match()),
    ]

# The expected single table
FORWARD_DROP_SINGLE = [
    Rule(priority=priority_scale(10, 100), table=0,  # A + D
         match=Match([("IPV4_DST", 0x9, 0xb)]),
         instructions=build_inst(clear_actions=True)),
    Rule(priority=priority_scale(10, 0), table=0,  # A + E
         match=Match([("IPV4_DST", 0x1, 0x3)]),
         instructions=build_inst(write_actions=[("OUTPUT", 1)])),
    Rule(priority=priority_scale(9, 100), table=0,  # B + D
         match=Match([("IPV4_DST", 0xa, 0xf)]),
         instructions=build_inst(clear_actions=True)),
    Rule(priority=priority_scale(9, 0), table=0,  # B + E
         match=Match([("IPV4_DST", 0x2, 0x7)]),
         instructions=build_inst(write_actions=[("OUTPUT", 2)])),
    Rule(priority=0, table=0, match=Match())  # C
    ]

DROP_FORWARD = [
    Rule(priority=100, table=0, match=Match([("IPV4_DST", 0x8, 0x8)])),
    Rule(priority=0, table=0, match=Match(),
         instructions=build_inst(goto_table=1)),

    Rule(priority=10, table=1, match=Match([("IPV4_DST", 0x2, 0x7)]),
         instructions=build_inst(apply_actions=[("OUTPUT", 2)])),
    Rule(priority=10, table=1, match=Match([("IPV4_DST", 0x1, 0x7)]),
         instructions=build_inst(apply_actions=[("OUTPUT", 1)])),
    Rule(priority=10, table=1, match=Match([("IPV4_DST", 0x5, 0x7)]),
         instructions=build_inst(apply_actions=[("OUTPUT", 1)])),
    Rule(priority=0, table=1, match=Match()),
    ]

DROP_FORWARD_SINGLE = [
    Rule(priority=priority_scale(100, 0), table=0,  # A
         match=Match([("IPV4_DST", 0x8, 0x8)])),
    Rule(priority=priority_scale(0, 10), table=0,  # B + C
         match=Match([("IPV4_DST", 0x2, 0x7)]),
         instructions=build_inst(apply_actions=[("OUTPUT", 2)])),
    Rule(priority=priority_scale(0, 10), table=0,  # B +D
         match=Match([("IPV4_DST", 0x1, 0x7)]),
         instructions=build_inst(apply_actions=[("OUTPUT", 1)])),
    Rule(priority=priority_scale(0, 10), table=0,  # B + E
         match=Match([("IPV4_DST", 0x5, 0x7)]),
         instructions=build_inst(apply_actions=[("OUTPUT", 1)])),
    Rule(priority=priority_scale(0, 0), table=0, match=Match()),  # B + F
    ]


def sanity_check_groups(ruleset, min_groups, rule2group):
    """ Ensure that all inter-group dependencies are correct """
    # Check the mapping is correct
    for rule in ruleset:
        assert rule in rule2group
        assert rule in min_groups[rule2group[rule]]
    # Check the groups are still valid
    for group, options in min_groups.items():
        assert group is options[0]
        expected = {rule2group[x] for x in set(group.parents + group.children)}
        for opt in options[1:]:
            this = {rule2group[x] for x in set(opt.parents + opt.children)}
            assert expected == this

class TestRuleset(unittest.TestCase):

    def test_to_single_table(self):
        ruleset1 = to_single_table(FORWARD_DROP)
        self.assertListEqual(ruleset1, FORWARD_DROP_SINGLE)

        ruleset2 = to_single_table(DROP_FORWARD)
        self.assertListEqual(ruleset2, DROP_FORWARD_SINGLE)

        # Already in normalise test, but we can do it again here
        # with the examples from the paper
        norm1 = normalise(ruleset1)
        norm2 = normalise(ruleset2)
        check_equal(norm1, norm2)
        check_equal(norm2, norm1)

    def test_compression_fully_covered(self):
        # Sanity check that the old dependency ordering fails
        # We expect direct dependencies to fail
        sane_deps = ruleset_deps_direct.build_ruleset_deps(POORLY_ORDERED_COMPRESS1)
        sane_rules, _map = compress_ruleset(POORLY_ORDERED_COMPRESS1, deps=sane_deps)
        self.assertEqual(len(sane_rules), 4)

        if sane_rules[0].match['TCP_SRC'] == sane_rules[2].match['TCP_SRC']:
            warnings.warn("The compression test might not work anymore")

        good, _map = compress_ruleset(ORDERED_COMPRESS1)
        poor, _map = compress_ruleset(POORLY_ORDERED_COMPRESS1)
        self.assertEqual(len(good), 4)
        self.assertEqual(len(poor), 4)
        self.assertEqual(good[0].match['TCP_DST'], good[1].match['TCP_DST'])
        self.assertEqual(good[0].match['TCP_SRC'], good[2].match['TCP_SRC'])
        self.assertEqual(len(good[3].match), 0)
        self.assertEqual(poor[0].match['TCP_DST'], poor[1].match['TCP_DST'])
        self.assertEqual(poor[0].match['TCP_SRC'], poor[2].match['TCP_SRC'])
        self.assertEqual(len(poor[3].match), 0)

    def test_compression_bad_choices(self):
        good, _map = compress_ruleset(ORDERED_COMPRESS2)
        poor, _map = compress_ruleset(POORLY_ORDERED_COMPRESS2)
        self.assertEqual(len(good), 8)
        self.assertEqual(len(poor), 8)

        groups = {}
        rule2group = {}
        # The groups might not quite end up like, so make them the original
        for _, v in groupby(POORLY_ORDERED_COMPRESS2, sort_key_ruleset_priority):
            l = list(v)
            groups[l[0]] = l
            for i in l:
                rule2group[i] = l[0]

        sanity_check_groups(POORLY_ORDERED_COMPRESS2, groups, rule2group)

        select_compressed_ruleset(POORLY_ORDERED_COMPRESS2, groups=groups,
                                  rule2group=rule2group)
        self.assertEqual(len(groups), 8)

    @unittest.skip("Not distributed with library")
    def test_big_ruleset(self):
        """ Just to see if we hit an error """
        from ofequivalence.convert_ryu import ruleset_from_ryu

        rules = ruleset_from_ryu("../tools/2017-6-4-faucet-redcables/ovs-redcables-30000.pickle.bz2")
        compress_ruleset(rules)


if __name__ == '__main__':
    unittest.main()
