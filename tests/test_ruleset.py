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
from ofequivalence.rule import Rule, Match, Instructions, ActionList, ActionSet
from ofequivalence.ruleset import to_single_table, MAX_PRIORITY
from ofequivalence.normalisebdd import check_equal, normalise

Rule.__repr__ = Rule.__str__
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


if __name__ == '__main__':
    unittest.main()
