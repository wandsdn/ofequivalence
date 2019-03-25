#!/usr/bin/env python
""" Tests for building a DAG using the CacheFlow algorithm
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
import random

from ryu.ofproto.ofproto_v1_3_parser import OFPMatch

from ofequivalence.rule import Rule
from ofequivalence.convert_ryu import match_from_ryu
from ofequivalence.ruleset import build_DAG

R2M = match_from_ryu
COVISOR_RULESET = [
    Rule(priority=5, match=R2M(OFPMatch(
        ipv4_src=("1.0.0.0", "255.255.255.0"), ipv4_dst="2.0.0.1"))),
    Rule(priority=4, match=R2M(OFPMatch(
        ipv4_src=("1.0.0.0", "255.255.255.0"), ipv4_dst="2.0.0.2"))),
    Rule(priority=3, match=R2M(OFPMatch(
        ipv4_src=("1.0.0.0", "255.255.255.0")))),
    Rule(priority=2, match=R2M(OFPMatch(ipv4_dst="2.0.0.1"))),
    Rule(priority=1, match=R2M(OFPMatch(ipv4_dst="2.0.0.2"))),
    Rule(priority=0)
    ]

REANNZ_RULESET = [
    Rule(priority=32800, match=R2M(OFPMatch(tcp_dst=179))),
    Rule(priority=32800, match=R2M(OFPMatch(tcp_dst=646))),
    Rule(priority=16640, match=R2M(OFPMatch(
        ipv4_dst=("111.221.69.0", "255.255.255.0")))),
    Rule(priority=16640, match=R2M(OFPMatch(
        ipv4_dst=("111.221.66.0", "255.255.255.0")))),
    Rule(priority=16630, match=R2M(OFPMatch(
        ipv4_dst=("111.221.78.0", "255.255.254.0")))),
    Rule(priority=16610, match=R2M(OFPMatch(
        ipv4_dst=("111.221.64.0", "255.225.248.0")))),
    Rule(priority=16610, match=R2M(OFPMatch(
        ipv4_dst=("111.221.112.0", "255.225.248.0")))),
    Rule(priority=16580, match=R2M(OFPMatch(
        ipv4_dst=("111.221.64.0", "255.225.192.0")))),
    ]

for x in COVISOR_RULESET:
    x.table = 0
for x in REANNZ_RULESET:
    x.table = 0

EXPECTED_REANNZ_RESULTS = set(
    [(REANNZ_RULESET[0], REANNZ_RULESET[2]),
     (REANNZ_RULESET[0], REANNZ_RULESET[3]),
     (REANNZ_RULESET[0], REANNZ_RULESET[4]),
     (REANNZ_RULESET[0], REANNZ_RULESET[5]),
     (REANNZ_RULESET[0], REANNZ_RULESET[6]),
     (REANNZ_RULESET[0], REANNZ_RULESET[7]),
     (REANNZ_RULESET[1], REANNZ_RULESET[2]),
     (REANNZ_RULESET[1], REANNZ_RULESET[3]),
     (REANNZ_RULESET[1], REANNZ_RULESET[4]),
     (REANNZ_RULESET[1], REANNZ_RULESET[5]),
     (REANNZ_RULESET[1], REANNZ_RULESET[6]),
     (REANNZ_RULESET[1], REANNZ_RULESET[7]),
     (REANNZ_RULESET[2], REANNZ_RULESET[5]),
     (REANNZ_RULESET[3], REANNZ_RULESET[5]),
     (REANNZ_RULESET[4], REANNZ_RULESET[7]),
     (REANNZ_RULESET[5], REANNZ_RULESET[7]),
     (REANNZ_RULESET[6], REANNZ_RULESET[7]),
     ])

EXPECTED_COVISOR_RESULTS = set(
    [(COVISOR_RULESET[0], COVISOR_RULESET[2]),
     (COVISOR_RULESET[1], COVISOR_RULESET[2]),
     (COVISOR_RULESET[2], COVISOR_RULESET[3]),
     (COVISOR_RULESET[2], COVISOR_RULESET[4]),
     (COVISOR_RULESET[2], COVISOR_RULESET[5]),
     # ^ Not shown in paper but I'm sure this is a thing!!! ^
     (COVISOR_RULESET[3], COVISOR_RULESET[5]),
     (COVISOR_RULESET[4], COVISOR_RULESET[5]),
     ])


class TestBuildingDAG(unittest.TestCase):

    def test_reannz_ruleset(self):
        res = build_DAG(REANNZ_RULESET)
        self.assertSetEqual(set(res[0]), EXPECTED_REANNZ_RESULTS)

    def test_covisor_ruleset(self):
        res = build_DAG(COVISOR_RULESET)
        self.assertSetEqual(set(res[0]), EXPECTED_COVISOR_RESULTS)

    def test_random_reannz_ruleset(self):
        shuffled = list(REANNZ_RULESET)
        random.shuffle(shuffled)
        res = build_DAG(shuffled)
        self.assertSetEqual(set(res[0]), EXPECTED_REANNZ_RESULTS)

    def test_random_covisor_ruleset(self):
        shuffled = list(COVISOR_RULESET)
        random.shuffle(shuffled)
        res = build_DAG(shuffled)
        self.assertSetEqual(set(res[0]), EXPECTED_COVISOR_RESULTS)


if __name__ == '__main__':
    unittest.main()
