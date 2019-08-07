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

from ofequivalence.ruleset_deps_direct import (build_table_deps, build_ruleset_deps,
                                               build_prefix_table_deps,
                                               build_table_deps_incremental)
from .rulesets import (REANNZ_RULESET, DIRECT_REANNZ_DEPS,
                       REANNZ_OVERLAP, DIRECT_REANNZ_OVERLAP_DEPS,
                       REANNZ_OVERLAP2, DIRECT_REANNZ_OVERLAP2_DEPS,
                       COVISOR_RULESET, DIRECT_COVISOR_DEPS,
                       REWRITE_RULESET, DIRECT_REWRITE_DEPS,
                       FIB_RULESET)


class TestBuildingDepsDirect(unittest.TestCase):

    def check_dag(self, ruleset, expected):
        res_bdd = build_table_deps(ruleset, use_bdd=True)
        res_hs = build_table_deps(ruleset, use_bdd=False)
        res_bdd_inc = build_table_deps_incremental(ruleset)
        self.assertSetEqual(set(res_bdd), expected)
        self.assertSetEqual(set(res_hs), expected)
        self.assertSetEqual(set(res_bdd_inc), expected)
        self.assertDictEqual(res_bdd, res_bdd_inc)

    def test_reannz_ruleset(self):
        self.check_dag(REANNZ_RULESET, DIRECT_REANNZ_DEPS)

    def test_reannz_overlap(self):
        self.check_dag(REANNZ_OVERLAP, DIRECT_REANNZ_OVERLAP_DEPS)

    def test_reannz_overlap2(self):
        self.check_dag(REANNZ_OVERLAP2, DIRECT_REANNZ_OVERLAP2_DEPS)

    def test_covisor_ruleset(self):
        self.check_dag(COVISOR_RULESET, DIRECT_COVISOR_DEPS)

    def test_random_reannz_ruleset(self):
        shuffled = list(REANNZ_RULESET)
        random.shuffle(shuffled)
        self.check_dag(shuffled, DIRECT_REANNZ_DEPS)

    def test_random_reannz_overlap(self):
        shuffled = list(REANNZ_OVERLAP)
        random.shuffle(shuffled)
        self.check_dag(shuffled, DIRECT_REANNZ_OVERLAP_DEPS)

    def test_random_reannz_overlap2(self):
        shuffled = list(REANNZ_OVERLAP2)
        random.shuffle(shuffled)
        self.check_dag(shuffled, DIRECT_REANNZ_OVERLAP2_DEPS)

    def test_random_covisor_ruleset(self):
        shuffled = list(COVISOR_RULESET)
        random.shuffle(shuffled)
        self.check_dag(shuffled, DIRECT_COVISOR_DEPS)

    def test_rewrite_ruleset(self):
        deps = build_ruleset_deps(REWRITE_RULESET, use_bdd=False)
        deps_bdd = build_ruleset_deps(REWRITE_RULESET, use_bdd=True)

        self.assertSetEqual(set(deps), DIRECT_REWRITE_DEPS)
        self.assertSetEqual(set(deps_bdd), DIRECT_REWRITE_DEPS)

    def test_fib_ruleset(self):
        res_bdd = build_table_deps(FIB_RULESET, use_bdd=True)
        res_bdd_inc = build_table_deps_incremental(FIB_RULESET)
        res_bdd_prefix = build_prefix_table_deps(FIB_RULESET, use_bdd=True)
        self.assertDictEqual(res_bdd, res_bdd_inc)
        self.assertDictEqual(res_bdd, res_bdd_prefix)


if __name__ == '__main__':
    unittest.main()
