#!/usr/bin/env python
""" Tests for the UniqueRules wrapper """

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
from ofequivalence.rule import Rule, UniqueRules


class TestUniqueRules(unittest.TestCase):

    def test_simple(self):
        a = Rule(priority=0)
        b = Rule(priority=0)
        c = Rule(priority=1)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

        with UniqueRules():
            self.assertNotEqual(a, b)
            self.assertNotEqual(a, c)

        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_hash_sanity(self):
        rules = [Rule(priority=0), Rule(priority=1), Rule(priority=3),
                 Rule(priority=5), Rule(priority=10), Rule(priority=18)]
        as_set = set(rules)
        as_dict = dict(zip(rules, range(6)))

        with UniqueRules():
            unique_set = set(rules)
            unique_dict = dict(zip(rules, range(6)))

        # Sanity check everything will be hashed wrong, almost certain to fail
        self.assertNotEqual(as_set, unique_set)
        self.assertNotEqual(as_dict, unique_dict)

    def test_rewrite_hash(self):
        rules = [Rule(priority=0), Rule(priority=1), Rule(priority=3),
                 Rule(priority=5), Rule(priority=10), Rule(priority=18)]
        as_set = set(rules)
        as_dict = dict(zip(rules, range(6)))

        unique_set = set()
        unique_dict = dict()
        with UniqueRules(unique_set, unique_dict):
            unique_set.update(rules)
            unique_dict.update(zip(rules, range(6)))

        # Sanity check everything will be hashed wrong, almost certain to fail
        self.assertEqual(as_set, unique_set)
        self.assertEqual(as_dict, unique_dict)

if __name__ == '__main__':
    unittest.main()
