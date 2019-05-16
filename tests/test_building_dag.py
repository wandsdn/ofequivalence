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
from os.path import join, dirname

from ryu.ofproto.ofproto_v1_3_parser import OFPMatch

from ofequivalence.rule import Rule
from ofequivalence.convert_fib import ruleset_from_fib
from ofequivalence.convert_ryu import match_from_ryu
from ofequivalence.ruleset import (build_DAG, build_DAG_incremental,
                                   add_parents_hs, build_DAG_prefix)

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
    Rule(priority=0)
    ]

""" Based on the REANNZ_RULESET which hits process_affected_edges with
    multiple edges per child, when added in this order. """
REANNZ_OVERLAP = [
    Rule(priority=32800, match=R2M(OFPMatch(tcp_dst=179))),
    Rule(priority=32800, match=R2M(OFPMatch(tcp_dst=646))),
    Rule(priority=16640, match=R2M(OFPMatch(
        ipv4_dst=("111.221.69.0", "255.255.255.0")))),
    Rule(priority=16640, match=R2M(OFPMatch(
        ipv4_dst=("111.221.66.0", "255.255.255.0")))),
    Rule(priority=16800, match=R2M(OFPMatch(
        ipv4_dst=("111.221.64.0", "255.255.248.0")))),
    Rule(priority=0)
    ]

REANNZ_OVERLAP2 = [
    Rule(priority=32800, match=R2M(OFPMatch(tcp_dst=179))),
    Rule(priority=32800, match=R2M(OFPMatch(tcp_dst=646))),
    Rule(priority=16640, match=R2M(OFPMatch(
        ipv4_dst=("111.221.69.0", "255.255.255.0")))),
    Rule(priority=16640, match=R2M(OFPMatch(
        ipv4_dst=("111.221.66.0", "255.255.255.0")))),
    Rule(priority=16800, match=R2M(OFPMatch(
        ipv4_src=("111.221.64.0", "255.255.248.0")))),
    Rule(priority=0)
    ]

for x in COVISOR_RULESET:
    x.table = 0
for x in REANNZ_RULESET:
    x.table = 0
for x in REANNZ_OVERLAP:
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
     (REANNZ_RULESET[0], REANNZ_RULESET[8]),
     (REANNZ_RULESET[1], REANNZ_RULESET[8]),
     (REANNZ_RULESET[7], REANNZ_RULESET[8]),
     ])

EXPECTED_REANNZ_OVERLAP_RESULTS = set(
    [(REANNZ_OVERLAP[0], REANNZ_OVERLAP[4]),
     (REANNZ_OVERLAP[0], REANNZ_OVERLAP[5]),
     (REANNZ_OVERLAP[1], REANNZ_OVERLAP[4]),
     (REANNZ_OVERLAP[1], REANNZ_OVERLAP[5]),
     (REANNZ_OVERLAP[4], REANNZ_OVERLAP[2]),
     (REANNZ_OVERLAP[4], REANNZ_OVERLAP[3]),
     (REANNZ_OVERLAP[4], REANNZ_OVERLAP[5]),
     (REANNZ_OVERLAP[2], REANNZ_OVERLAP[5]),
     (REANNZ_OVERLAP[3], REANNZ_OVERLAP[5]),
     ])

EXPECTED_REANNZ_OVERLAP2_RESULTS = set(
    [(REANNZ_OVERLAP2[0], REANNZ_OVERLAP2[4]),
     (REANNZ_OVERLAP2[0], REANNZ_OVERLAP2[5]),
     (REANNZ_OVERLAP2[0], REANNZ_OVERLAP2[2]),
     (REANNZ_OVERLAP2[0], REANNZ_OVERLAP2[3]),
     (REANNZ_OVERLAP2[1], REANNZ_OVERLAP2[4]),
     (REANNZ_OVERLAP2[1], REANNZ_OVERLAP2[5]),
     (REANNZ_OVERLAP2[1], REANNZ_OVERLAP2[2]),
     (REANNZ_OVERLAP2[1], REANNZ_OVERLAP2[3]),
     (REANNZ_OVERLAP2[4], REANNZ_OVERLAP2[2]),
     (REANNZ_OVERLAP2[4], REANNZ_OVERLAP2[3]),
     (REANNZ_OVERLAP2[4], REANNZ_OVERLAP2[5]),
     (REANNZ_OVERLAP2[2], REANNZ_OVERLAP2[5]),
     (REANNZ_OVERLAP2[3], REANNZ_OVERLAP2[5]),
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

FIB_RULESET = ruleset_from_fib(join(dirname(__file__), "./fib_1000.dat"))

class TestBuildingDAG(unittest.TestCase):

    def check_dag(self, ruleset, expected):
        res_bdd = build_DAG(ruleset)
        res_hs = build_DAG(ruleset, add_parents_hs)
        res_bdd_inc = build_DAG_incremental(ruleset)
        self.assertSetEqual(set(res_bdd), expected)
        self.assertSetEqual(set(res_hs), expected)
        self.assertSetEqual(set(res_bdd_inc), expected)
        self.assertDictEqual(res_bdd, res_bdd_inc)

    def test_reannz_ruleset(self):
        self.check_dag(REANNZ_RULESET, EXPECTED_REANNZ_RESULTS)

    def test_reannz_overlap(self):
        self.check_dag(REANNZ_OVERLAP, EXPECTED_REANNZ_OVERLAP_RESULTS)

    def test_reannz_overlap2(self):
        self.check_dag(REANNZ_OVERLAP2, EXPECTED_REANNZ_OVERLAP2_RESULTS)

    def test_covisor_ruleset(self):
        self.check_dag(COVISOR_RULESET, EXPECTED_COVISOR_RESULTS)

    def test_random_reannz_ruleset(self):
        shuffled = list(REANNZ_RULESET)
        random.shuffle(shuffled)
        self.check_dag(shuffled, EXPECTED_REANNZ_RESULTS)

    def test_random_reannz_overlap(self):
        shuffled = list(REANNZ_OVERLAP)
        random.shuffle(shuffled)
        self.check_dag(shuffled, EXPECTED_REANNZ_OVERLAP_RESULTS)

    def test_random_reannz_overlap2(self):
        shuffled = list(REANNZ_OVERLAP2)
        random.shuffle(shuffled)
        self.check_dag(shuffled, EXPECTED_REANNZ_OVERLAP2_RESULTS)

    def test_random_covisor_ruleset(self):
        shuffled = list(COVISOR_RULESET)
        random.shuffle(shuffled)
        self.check_dag(shuffled, EXPECTED_COVISOR_RESULTS)

    def test_fib_ruleset(self):
        res_bdd = build_DAG(FIB_RULESET)
        res_bdd_inc = build_DAG_incremental(FIB_RULESET)
        res_bdd_prefix = build_DAG_prefix(FIB_RULESET)
        self.assertDictEqual(res_bdd, res_bdd_inc)
        self.assertDictEqual(res_bdd, res_bdd_prefix)


if __name__ == '__main__':
    unittest.main()
