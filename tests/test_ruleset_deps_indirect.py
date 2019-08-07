#!/usr/bin/env python
""" Tests for building a dependency graph for a ruleset, used for compression
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

from ofequivalence.ruleset_deps_indirect import (
    build_table_deps, build_ruleset_deps,
    build_prefix_table_deps)
from .rulesets import (REANNZ_RULESET, INDIRECT_REANNZ_DEPS,
                       REANNZ_OVERLAP, INDIRECT_REANNZ_OVERLAP_DEPS,
                       REANNZ_OVERLAP2, INDIRECT_REANNZ_OVERLAP2_DEPS,
                       COVISOR_RULESET, INDIRECT_COVISOR_DEPS,
                       REWRITE_RULESET, INDIRECT_REWRITE_DEPS,
                       FIB_RULESET)


class TestBuildingDepsIndirect(unittest.TestCase):

    def check_dag(self, ruleset, expected):
        res_bdd = build_table_deps(ruleset, use_bdd=True)
        res_hs = build_table_deps(ruleset, use_bdd=False)
        res_ruleset = build_ruleset_deps(ruleset)
        self.assertSetEqual(set(res_bdd), expected)
        self.assertSetEqual(set(res_hs), expected)
        self.assertSetEqual(set(res_ruleset), expected)

    def test_reannz_ruleset(self):
        self.check_dag(REANNZ_RULESET, INDIRECT_REANNZ_DEPS)

    def test_reannz_overlap(self):
        self.check_dag(REANNZ_OVERLAP, INDIRECT_REANNZ_OVERLAP_DEPS)

    def test_reannz_overlap2(self):
        self.check_dag(REANNZ_OVERLAP2, INDIRECT_REANNZ_OVERLAP2_DEPS)

    def test_covisor_ruleset(self):
        self.check_dag(COVISOR_RULESET, INDIRECT_COVISOR_DEPS)

    def test_random_reannz_ruleset(self):
        shuffled = list(REANNZ_RULESET)
        random.shuffle(shuffled)
        self.check_dag(shuffled, INDIRECT_REANNZ_DEPS)

    def test_random_reannz_overlap(self):
        shuffled = list(REANNZ_OVERLAP)
        random.shuffle(shuffled)
        self.check_dag(shuffled, INDIRECT_REANNZ_OVERLAP_DEPS)

    def test_random_reannz_overlap2(self):
        shuffled = list(REANNZ_OVERLAP2)
        random.shuffle(shuffled)
        self.check_dag(shuffled, INDIRECT_REANNZ_OVERLAP2_DEPS)

    def test_random_covisor_ruleset(self):
        shuffled = list(COVISOR_RULESET)
        random.shuffle(shuffled)
        self.check_dag(shuffled, INDIRECT_COVISOR_DEPS)

    def test_rewrite_ruleset(self):
        deps = build_ruleset_deps(REWRITE_RULESET, use_bdd=False)
        deps_bdd = build_ruleset_deps(REWRITE_RULESET, use_bdd=True)

        self.assertSetEqual(set(deps), INDIRECT_REWRITE_DEPS)
        self.assertSetEqual(set(deps_bdd), INDIRECT_REWRITE_DEPS)

    def test_fib_ruleset(self):
        res = build_table_deps(FIB_RULESET)
        res_prefix = set(build_prefix_table_deps(FIB_RULESET))
        res_ruleset = set(build_ruleset_deps(FIB_RULESET))

        self.assertSetEqual(res, res_prefix)
        self.assertSetEqual(res, res_ruleset)


if __name__ == '__main__':
    unittest.main()
