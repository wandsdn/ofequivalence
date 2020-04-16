""" Rulesets used by the test-suite """

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
from os.path import join, dirname

from ryu.ofproto.ofproto_v1_3_parser import OFPMatch

from ofequivalence.rule import Rule, Instructions
from ofequivalence.convert_fib import ruleset_from_fib
from ofequivalence.convert_ryu import match_from_ryu

def direct(deps):
    """ Return the set of direct dependencies """
    return {(a, b) for a, b, c in deps if c is False}

def indirect(deps):
    """ Return the set of indirect and direct dependencies """
    return {(a, b) for a, b, c in deps}

def I(goto=None, set_tcp=None):
    """ Short hand to generate instructions """
    i = Instructions()
    i.goto_table = goto
    if set_tcp is not None:
        i.apply_actions.append('SET_FIELD', ('TCP_DST', set_tcp))
    return i


R2M = match_from_ryu
COVISOR_RULESET = [
    Rule(priority=5, match=R2M(OFPMatch(                               # 0
        ipv4_src=("1.0.0.0", "255.255.255.0"), ipv4_dst="2.0.0.1"))),
    Rule(priority=4, match=R2M(OFPMatch(                               # 1
        ipv4_src=("1.0.0.0", "255.255.255.0"), ipv4_dst="2.0.0.2"))),
    Rule(priority=3, match=R2M(OFPMatch(                               # 2
        ipv4_src=("1.0.0.0", "255.255.255.0")))),
    Rule(priority=2, match=R2M(OFPMatch(ipv4_dst="2.0.0.1"))),         # 3
    Rule(priority=1, match=R2M(OFPMatch(ipv4_dst="2.0.0.2"))),         # 4
    Rule(priority=0)                                                   # 5
    ]

REANNZ_RULESET = [
    Rule(priority=32800, match=R2M(OFPMatch(tcp_dst=179))),            # 0
    Rule(priority=32800, match=R2M(OFPMatch(tcp_dst=646))),            # 1
    Rule(priority=16640, match=R2M(OFPMatch(                           # 2
        ipv4_dst=("111.221.69.0", "255.255.255.0")))),
    Rule(priority=16640, match=R2M(OFPMatch(                           # 3
        ipv4_dst=("111.221.66.0", "255.255.255.0")))),
    Rule(priority=16630, match=R2M(OFPMatch(                           # 4
        ipv4_dst=("111.221.78.0", "255.255.254.0")))),
    Rule(priority=16610, match=R2M(OFPMatch(                           # 5
        ipv4_dst=("111.221.64.0", "255.225.248.0")))),
    Rule(priority=16610, match=R2M(OFPMatch(                           # 6
        ipv4_dst=("111.221.112.0", "255.225.248.0")))),
    Rule(priority=16580, match=R2M(OFPMatch(                           # 7
        ipv4_dst=("111.221.64.0", "255.225.192.0")))),
    Rule(priority=0)                                                   # 8
    ]

""" Based on the REANNZ_RULESET which hits process_affected_edges with
    multiple edges per child, when added in this order. """
REANNZ_OVERLAP = [
    Rule(priority=32800, match=R2M(OFPMatch(tcp_dst=179))),           # 0
    Rule(priority=32800, match=R2M(OFPMatch(tcp_dst=646))),           # 1
    Rule(priority=16640, match=R2M(OFPMatch(                          # 2
        ipv4_dst=("111.221.69.0", "255.255.255.0")))),
    Rule(priority=16640, match=R2M(OFPMatch(                          # 3
        ipv4_dst=("111.221.66.0", "255.255.255.0")))),
    Rule(priority=16800, match=R2M(OFPMatch(                          # 4
        ipv4_dst=("111.221.64.0", "255.255.248.0")))),
    Rule(priority=0)                                                  # 5
    ]

REANNZ_OVERLAP2 = [
    Rule(priority=32800, match=R2M(OFPMatch(tcp_dst=179))),           # 0
    Rule(priority=32800, match=R2M(OFPMatch(tcp_dst=646))),           # 1
    Rule(priority=16640, match=R2M(OFPMatch(                          # 2
        ipv4_dst=("111.221.69.0", "255.255.255.0")))),
    Rule(priority=16640, match=R2M(OFPMatch(                          # 3
        ipv4_dst=("111.221.66.0", "255.255.255.0")))),
    Rule(priority=16800, match=R2M(OFPMatch(                          # 4
        ipv4_src=("111.221.64.0", "255.255.248.0")))),
    Rule(priority=0)                                                  # 5
    ]

# A multi-table multi-overlapping ruleset
REWRITE_RULESET = [
    # Table 0
    Rule(table=0, priority=100, match=R2M(OFPMatch(tcp_dst=80)),  #0
         instructions=I(goto=1, set_tcp=81)),
    Rule(table=0, priority=100, match=R2M(OFPMatch(tcp_dst=81)),  #1
         instructions=I(goto=1, set_tcp=82)),
    Rule(table=0, priority=100, match=R2M(OFPMatch(tcp_dst=82)),  #2
         instructions=I(goto=1, set_tcp=83)),
    Rule(table=0, priority=0),                                    #3

    # Table 1
    Rule(table=1, priority=100, match=R2M(OFPMatch(tcp_dst=80)),  #4
         instructions=I(goto=2, set_tcp=81)),
    Rule(table=1, priority=100, match=R2M(OFPMatch(tcp_dst=81)),  #5
         instructions=I(goto=2, set_tcp=82)),
    Rule(table=1, priority=100, match=R2M(OFPMatch(tcp_dst=82)),  #6
         instructions=I(goto=2, set_tcp=83)),
    Rule(table=1, priority=0),                                    #7

    # Table 2
    Rule(table=2, priority=100, match=R2M(OFPMatch(tcp_dst=80)),  #8
         instructions=I(goto=3, set_tcp=81)),
    Rule(table=2, priority=100, match=R2M(OFPMatch(tcp_dst=81)),  #9
         instructions=I(goto=3, set_tcp=82)),
    Rule(table=2, priority=100, match=R2M(OFPMatch(tcp_dst=82)),  #10
         instructions=I(goto=3, set_tcp=83)),
    Rule(table=2, priority=0),                                    #11

    # Table 3
    Rule(table=3, priority=0),                                    #12
        ]

for x in COVISOR_RULESET:
    x.table = 0
    x.cookie = 0
for x in REANNZ_RULESET:
    x.table = 0
    x.cookie = 0
for x in REANNZ_OVERLAP:
    x.table = 0
    x.cookie = 0
for x in REANNZ_OVERLAP2:
    x.table = 0
    x.cookie = 0
for x in REWRITE_RULESET:
    x.cookie = 0

# (RuleA, RuleB, indirect?)

REANNZ_DEPS = set(
    [(REANNZ_RULESET[0], REANNZ_RULESET[2], False),
     (REANNZ_RULESET[0], REANNZ_RULESET[3], False),
     (REANNZ_RULESET[0], REANNZ_RULESET[4], False),
     (REANNZ_RULESET[0], REANNZ_RULESET[5], False),
     (REANNZ_RULESET[0], REANNZ_RULESET[6], False),
     (REANNZ_RULESET[0], REANNZ_RULESET[7], False),
     (REANNZ_RULESET[0], REANNZ_RULESET[8], False),
     (REANNZ_RULESET[1], REANNZ_RULESET[2], False),
     (REANNZ_RULESET[1], REANNZ_RULESET[3], False),
     (REANNZ_RULESET[1], REANNZ_RULESET[4], False),
     (REANNZ_RULESET[1], REANNZ_RULESET[5], False),
     (REANNZ_RULESET[1], REANNZ_RULESET[6], False),
     (REANNZ_RULESET[1], REANNZ_RULESET[7], False),
     (REANNZ_RULESET[1], REANNZ_RULESET[8], False),
     (REANNZ_RULESET[2], REANNZ_RULESET[5], False),
     (REANNZ_RULESET[2], REANNZ_RULESET[7], True),
     (REANNZ_RULESET[2], REANNZ_RULESET[8], True),
     (REANNZ_RULESET[3], REANNZ_RULESET[5], False),
     (REANNZ_RULESET[3], REANNZ_RULESET[7], True),
     (REANNZ_RULESET[3], REANNZ_RULESET[8], True),
     (REANNZ_RULESET[4], REANNZ_RULESET[7], False),
     (REANNZ_RULESET[4], REANNZ_RULESET[8], True),
     (REANNZ_RULESET[5], REANNZ_RULESET[7], False),
     (REANNZ_RULESET[5], REANNZ_RULESET[8], True),
     (REANNZ_RULESET[6], REANNZ_RULESET[7], False),
     (REANNZ_RULESET[6], REANNZ_RULESET[8], True),
     (REANNZ_RULESET[7], REANNZ_RULESET[8], False),
     ])


DIRECT_REANNZ_DEPS = direct(REANNZ_DEPS)
INDIRECT_REANNZ_DEPS = indirect(REANNZ_DEPS)

REANNZ_OVERLAP_DEPS = set(
    [(REANNZ_OVERLAP[0], REANNZ_OVERLAP[4], False),
     (REANNZ_OVERLAP[0], REANNZ_OVERLAP[2], True),
     (REANNZ_OVERLAP[0], REANNZ_OVERLAP[3], True),
     (REANNZ_OVERLAP[0], REANNZ_OVERLAP[5], False),
     (REANNZ_OVERLAP[1], REANNZ_OVERLAP[4], False),
     (REANNZ_OVERLAP[1], REANNZ_OVERLAP[2], True),
     (REANNZ_OVERLAP[1], REANNZ_OVERLAP[3], True),
     (REANNZ_OVERLAP[1], REANNZ_OVERLAP[5], False),
     (REANNZ_OVERLAP[4], REANNZ_OVERLAP[2], False),
     (REANNZ_OVERLAP[4], REANNZ_OVERLAP[3], False),
     (REANNZ_OVERLAP[4], REANNZ_OVERLAP[5], False),
     (REANNZ_OVERLAP[2], REANNZ_OVERLAP[5], False),
     (REANNZ_OVERLAP[3], REANNZ_OVERLAP[5], False),
     ])

DIRECT_REANNZ_OVERLAP_DEPS = direct(REANNZ_OVERLAP_DEPS)
INDIRECT_REANNZ_OVERLAP_DEPS = indirect(REANNZ_OVERLAP_DEPS)

REANNZ_OVERLAP2_DEPS = set(
    [(REANNZ_OVERLAP2[0], REANNZ_OVERLAP2[4], False),
     (REANNZ_OVERLAP2[0], REANNZ_OVERLAP2[5], False),
     (REANNZ_OVERLAP2[0], REANNZ_OVERLAP2[2], False),
     (REANNZ_OVERLAP2[0], REANNZ_OVERLAP2[3], False),
     (REANNZ_OVERLAP2[1], REANNZ_OVERLAP2[4], False),
     (REANNZ_OVERLAP2[1], REANNZ_OVERLAP2[5], False),
     (REANNZ_OVERLAP2[1], REANNZ_OVERLAP2[2], False),
     (REANNZ_OVERLAP2[1], REANNZ_OVERLAP2[3], False),
     (REANNZ_OVERLAP2[4], REANNZ_OVERLAP2[2], False),
     (REANNZ_OVERLAP2[4], REANNZ_OVERLAP2[3], False),
     (REANNZ_OVERLAP2[4], REANNZ_OVERLAP2[5], False),
     (REANNZ_OVERLAP2[2], REANNZ_OVERLAP2[5], False),
     (REANNZ_OVERLAP2[3], REANNZ_OVERLAP2[5], False),
     ])

DIRECT_REANNZ_OVERLAP2_DEPS = direct(REANNZ_OVERLAP2_DEPS)
INDIRECT_REANNZ_OVERLAP2_DEPS = indirect(REANNZ_OVERLAP2_DEPS)

COVISOR_DEPS = set(
    [(COVISOR_RULESET[0], COVISOR_RULESET[2], False),
     (COVISOR_RULESET[0], COVISOR_RULESET[3], True),
     (COVISOR_RULESET[0], COVISOR_RULESET[5], True),
     (COVISOR_RULESET[1], COVISOR_RULESET[2], False),
     (COVISOR_RULESET[1], COVISOR_RULESET[4], True),
     (COVISOR_RULESET[1], COVISOR_RULESET[5], True),
     (COVISOR_RULESET[2], COVISOR_RULESET[3], False),
     (COVISOR_RULESET[2], COVISOR_RULESET[4], False),
     (COVISOR_RULESET[2], COVISOR_RULESET[5], False),
     # ^ Not shown in paper but I'm sure this is a thing!!! ^
     (COVISOR_RULESET[3], COVISOR_RULESET[5], False),
     (COVISOR_RULESET[4], COVISOR_RULESET[5], False),
     ])

DIRECT_COVISOR_DEPS = direct(COVISOR_DEPS)
INDIRECT_COVISOR_DEPS = indirect(COVISOR_DEPS)

REWRITE_DEPS = set(
    [(REWRITE_RULESET[0], REWRITE_RULESET[3], False),
     (REWRITE_RULESET[0], REWRITE_RULESET[5], False),
     (REWRITE_RULESET[0], REWRITE_RULESET[7], True),
     (REWRITE_RULESET[0], REWRITE_RULESET[10], True),
     (REWRITE_RULESET[0], REWRITE_RULESET[11], True),
     (REWRITE_RULESET[0], REWRITE_RULESET[12], True),
     (REWRITE_RULESET[1], REWRITE_RULESET[3], False),
     (REWRITE_RULESET[1], REWRITE_RULESET[6], False),
     (REWRITE_RULESET[1], REWRITE_RULESET[7], True),
     (REWRITE_RULESET[1], REWRITE_RULESET[11], True),
     (REWRITE_RULESET[2], REWRITE_RULESET[3], False),
     (REWRITE_RULESET[2], REWRITE_RULESET[7], False),
     (REWRITE_RULESET[4], REWRITE_RULESET[7], False),
     (REWRITE_RULESET[4], REWRITE_RULESET[9], False),  # Not reachable
     (REWRITE_RULESET[4], REWRITE_RULESET[11], True),
     (REWRITE_RULESET[4], REWRITE_RULESET[12], True),
     (REWRITE_RULESET[5], REWRITE_RULESET[7], False),
     (REWRITE_RULESET[5], REWRITE_RULESET[10], False),
     (REWRITE_RULESET[5], REWRITE_RULESET[11], True),
     (REWRITE_RULESET[5], REWRITE_RULESET[12], True),
     (REWRITE_RULESET[6], REWRITE_RULESET[7], False),
     (REWRITE_RULESET[6], REWRITE_RULESET[11], False),
     (REWRITE_RULESET[8], REWRITE_RULESET[11], False),
     (REWRITE_RULESET[8], REWRITE_RULESET[12], False),  # Not reachable
     (REWRITE_RULESET[9], REWRITE_RULESET[11], False),
     (REWRITE_RULESET[9], REWRITE_RULESET[12], False),  # Not reachable
     (REWRITE_RULESET[10], REWRITE_RULESET[11], False),
     (REWRITE_RULESET[10], REWRITE_RULESET[12], False),
    ])

DIRECT_REWRITE_DEPS = direct(REWRITE_DEPS)
INDIRECT_REWRITE_DEPS = indirect(REWRITE_DEPS)

FIB_RULESET = ruleset_from_fib(join(dirname(__file__), "./fib_1000.dat"))


ORDERED_COMPRESS1 = [
    Rule(table=0, priority=120, match=R2M(OFPMatch(tcp_src=1, tcp_dst=100))),   # 0
    Rule(table=0, priority=120, match=R2M(OFPMatch(tcp_src=1, tcp_dst=200))),   # 1
    Rule(table=0, priority=120, match=R2M(OFPMatch(tcp_src=2, tcp_dst=100))),   # 2
    Rule(table=0, priority=120, match=R2M(OFPMatch(tcp_src=2, tcp_dst=200))),   # 3
    Rule(table=0, priority=110, match=R2M(OFPMatch(tcp_dst=100))),              # 4
    Rule(table=0, priority=110, match=R2M(OFPMatch(tcp_dst=200))),              # 5
    Rule(table=0, priority=100, match=R2M(OFPMatch(tcp_src=1))),                # 6
    Rule(table=0, priority=100, match=R2M(OFPMatch(tcp_src=2))),                # 7
    Rule(table=0, priority=0),                                                  # 8
        ]

# Shows why indirect dependencies need to be considered
# A common pattern from compressing to a single table
#
# As rules 0-3 only have direct dependencies to 4 and 5 (fully shadowed)
# Any value for 6 and 7 can be picked, yet the same tcp_src or dst should
# be picked so that the dependencies are maintained when rule-fitting
#
# For rule-fitting as 0-3 can be placed in different tables to 6, 7
# this can incorrectly introduce a dependency
POORLY_ORDERED_COMPRESS1 = list(ORDERED_COMPRESS1)
POORLY_ORDERED_COMPRESS1[6], POORLY_ORDERED_COMPRESS1[7] = (
        POORLY_ORDERED_COMPRESS1[7], POORLY_ORDERED_COMPRESS1[6])


ORDERED_COMPRESS2 = [
    Rule(table=0, priority=120, match=R2M(OFPMatch(tcp_src=1)),               # 0
         instructions=I(goto=1)),
    Rule(table=0, priority=120, match=R2M(OFPMatch(tcp_src=2)),               # 1
         instructions=I(goto=1)),
    Rule(table=0, priority=100, match=R2M(OFPMatch(tcp_dst=100)),             # 2
         instructions=I(goto=1)),
    Rule(table=0, priority=100, match=R2M(OFPMatch(tcp_dst=200)),             # 3
         instructions=I(goto=1)),
    Rule(table=0, priority=0),                                                # 4

    # Table 1
    Rule(table=1, priority=120, match=R2M(OFPMatch(tcp_src=1, tcp_dst=100)),  # 5
         instructions=I(goto=2)),
    Rule(table=1, priority=120, match=R2M(OFPMatch(tcp_src=2, tcp_dst=200)),  # 6
         instructions=I(goto=2)),
    Rule(table=1, priority=0),                                                # 7

    # Table 2
    Rule(table=2, priority=120, match=R2M(OFPMatch(tcp_src=1))),              # 8
    Rule(table=2, priority=120, match=R2M(OFPMatch(tcp_src=2))),              # 9
    Rule(table=2, priority=100, match=R2M(OFPMatch(tcp_dst=100))),            # 10
    Rule(table=2, priority=100, match=R2M(OFPMatch(tcp_dst=200))),            # 11
    Rule(table=2, priority=0),                                                # 12
        ]

# Assuming compression first selects rules from table 0 or 2
# It can select a incompatible pair, not in rules 5-6
POORLY_ORDERED_COMPRESS2 = list(ORDERED_COMPRESS2)
POORLY_ORDERED_COMPRESS2[2], POORLY_ORDERED_COMPRESS2[3] = (
        POORLY_ORDERED_COMPRESS2[3], POORLY_ORDERED_COMPRESS2[2])
POORLY_ORDERED_COMPRESS2[10], POORLY_ORDERED_COMPRESS2[11] = (
        POORLY_ORDERED_COMPRESS2[11], POORLY_ORDERED_COMPRESS2[10])
