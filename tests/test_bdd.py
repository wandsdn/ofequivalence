#!/usr/bin/env python
""" Test for the pure python ofequivalence.bdd implementation """

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
from ofequivalence import bdd
from .base_bdd import BaseBDD


class TestBdd(BaseBDD, unittest.TestCase):
    def setUp(self):
        BaseBDD.setUp(self, bdd)


if __name__ == '__main__':
    unittest.main()
