#!/usr/bin/env python

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
from unittest import expectedFailure
from ofequivalence import normaliseheaderspace
from .base_normalise import BaseNormalise

class TestNormaliseHeaderSpace(BaseNormalise, unittest.TestCase):
    def setUp(self):
        BaseNormalise.setUp(self, normaliseheaderspace)

    # Expected failures, because headerspace cannot always detect equivalence
    test_normalise_2 = expectedFailure(BaseNormalise.test_normalise_2)
    test_normalise_3 = expectedFailure(BaseNormalise.test_normalise_3)
    test_action_independence_multiple = (
        expectedFailure(BaseNormalise.test_action_independence_multiple))
    test_action_independence_single = (
        expectedFailure(BaseNormalise.test_action_independence_single))
    test_find_metadata_conflicting_paths = (
        expectedFailure(BaseNormalise.test_find_metadata_conflicting_paths))
    test_find_multitable_conflicting_paths = (
        expectedFailure(BaseNormalise.test_find_multitable_conflicting_paths))
    test_find_rewrite_conflicting_paths = (
        expectedFailure(BaseNormalise.test_find_rewrite_conflicting_paths))
    test_find_simple_conflicting_paths = (
        expectedFailure(BaseNormalise.test_find_simple_conflicting_paths))
    test_find_vlans_conflicting_paths = (
        expectedFailure(BaseNormalise.test_find_vlans_conflicting_paths))

if __name__ == '__main__':
    unittest.main()
