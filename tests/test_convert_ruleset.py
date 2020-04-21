#!/usr/bin/env python
""" Tests for ofequivalence.convert_ruleset """

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

from __future__ import print_function
from subprocess import Popen, PIPE
import unittest
import gzip
import bz2
from tempfile import NamedTemporaryFile

from ofequivalence.convert_ruleset import load_ruleset, save_ruleset
from .rulesets import REWRITE_RULESET


class TestConvertRuleset(unittest.TestCase):
    """ We already assume the ruleset that comes back is correct

        Really this checks loading and saving rulesets, lots of quirks
        involved in this with reading from unseekable input (like pipes),
        compressed input, and unicode issues.
    """

    def _do_test(self, out_format, in_format):
        with NamedTemporaryFile() as tmp_f:
            save_ruleset(REWRITE_RULESET, tmp_f.name, out_format)
            self._test_load(tmp_f.name, in_format)

        with NamedTemporaryFile(suffix='gz') as tmp_f:
            save_ruleset(REWRITE_RULESET, tmp_f.name, out_format)
            a = load_ruleset(tmp_f.name, 'auto')
            b = load_ruleset(tmp_f.name, in_format)
            self.assertEqual(a, b)
            self.assertEqual(REWRITE_RULESET, a)

        with NamedTemporaryFile(suffix='bz2') as tmp_f:
            save_ruleset(REWRITE_RULESET, tmp_f.name, out_format)
            a = load_ruleset(tmp_f.name, 'auto')
            b = load_ruleset(tmp_f.name, in_format)
            self.assertEqual(a, b)
            self.assertEqual(REWRITE_RULESET, a)


    def _test_load(self, f_name, in_format):
        a = load_ruleset(f_name, 'auto')
        b = load_ruleset(f_name, in_format)

        # Test reading from a pre opened file handle
        with open(f_name, 'rb') as tmp_f:
            c = load_ruleset(tmp_f, 'auto')

        # Test reading from a non-seekable file handle
        proc = Popen(['cat', f_name], stdout=PIPE)
        d = load_ruleset(proc.stdout, in_format)
        proc.stdout.close()
        proc.wait()


        with NamedTemporaryFile(suffix='gz') as f_out:
            with open(f_name, 'rb') as f_in:
                with gzip.open(f_out.name, 'wb') as f_handle:
                    f_handle.write(f_in.read())
                e = load_ruleset(f_name, 'auto')
                f = load_ruleset(f_name, in_format)

        with NamedTemporaryFile(suffix='bz2') as f_out:
            with open(f_name, 'rb') as f_in:
                with bz2.BZ2File(f_out.name, 'wb') as f_handle:
                    f_handle.write(f_in.read())
                g = load_ruleset(f_name, 'auto')
                h = load_ruleset(f_name, in_format)

        with NamedTemporaryFile(suffix='gz') as f_out:
            with open(f_name, 'rb') as f_in:
                with gzip.open(f_out.name, 'wb') as f_handle:
                    f_handle.write(f_in.read())
                e = load_ruleset(f_name, 'auto')
                f = load_ruleset(f_name, in_format)

        with NamedTemporaryFile(suffix='bz2') as f_out:
            with open(f_name, 'rb') as f_in:
                with bz2.BZ2File(f_out.name, 'wb') as f_handle:
                    f_handle.write(f_in.read())
                g = load_ruleset(f_name, 'auto')
                h = load_ruleset(f_name, in_format)

        self.assertEqual(a, b)
        self.assertEqual(c, d)
        self.assertEqual(d, e)
        self.assertEqual(e, f)
        self.assertEqual(d, g)
        self.assertEqual(g, h)

    def test_save_load_ryu_json(self):
        self._do_test('ryu_json', 'ryu_json')

    def test_save_load_ryu_pickle(self):
        self._do_test('ryu_pickle', 'pickle')

    def test_save_load_pickle(self):
        self._do_test('pickle', 'pickle')

    def test_save_load_ovs(self):
        self._do_test('ovs', 'ovs')

    def test_load_fib(self):
        self._test_load("tests/fib_1000.dat", 'fib')

    def test_text(self):
        with NamedTemporaryFile('w') as tmp_f:
            save_ruleset(REWRITE_RULESET, tmp_f.name, 'text')
            save_ruleset(REWRITE_RULESET, tmp_f, 'text')
