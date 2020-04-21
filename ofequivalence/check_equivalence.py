#!/usr/bin/env python
""" A script to test the equivalence of OpenFlow 1.3 rulesets.
    This also prints out timing information, for each step.
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

from __future__ import print_function
import argparse
import sys

try:
    from tqdm import tqdm
    tqdm.monitor_interval = 0
except ImportError:
    pass

from .openflow_desc import OpenFlow1_3_5
from .ruleset import to_single_table
from . import cuddbdd
from .normalisebdd import (find_conflicting_paths, normalise_naive,
                           normalise_divide_and_conquer, check_equal)
from .convert_ruleset import INPUT_FORMATS, load_ruleset
from .utils import Timer

OF = OpenFlow1_3_5()


def reverse_fields(ruleset):
    """ Reverse the byte ordering of fields.

        This updates the byte ordering of fields matched and fields set.
        This excludes VLAN_VID matches as the 13bit has a special meaning.

        This exists solely to force and test bad node orderings.

        ruleset: A list of Rules, updated in-place
    """
    for rule in ruleset:
        # Reverse matches
        for field, (value, mask, _) in rule.match.iteritems():
            if field == "VLAN_VID":
                continue
            bits = OF.oxm_fields[field].bits
            new_value = int(bin(value)[2:].zfill(bits)[::-1], 2)
            assert new_value & ((2**bits)-1) == new_value
            new_mask = mask
            if mask:
                new_mask = int(bin(value)[2:].zfill(bits)[::-1], 2)
                assert new_mask & ((2**bits)-1) == new_mask
            rule.match.append(field, new_value, new_mask)
        new_actions = rule.instructions.apply_actions.__class__()
        for action in rule.instructions.apply_actions:
            if action[0] == "SET_FIELD" and action[1][0] != "VLAN_VID":
                bits = OF.oxm_fields[action[1][0]].bits
                reverse = int(bin(action[1][1])[2:].zfill(bits)[::-1], 2)
                assert reverse & ((2**bits)-1) == reverse
                new_actions.append("SET_FIELD", (action[1][0], reverse))
            else:
                new_actions.append(*action)
        rule.instructions.apply_actions = new_actions


def main():
    """ Arguments """
    parser = argparse.ArgumentParser(
        description="Check for forwarding equivalence between two or more rulesets")
    parser.add_argument('rulesets', nargs='*', metavar="ruleset",
                        help="the rulesets to check equivalence of. "
                             "This automatically detects the ruleset format. "
                             "Available formats are listed in the formats section below.")
    parser.add_argument('-d', '--divide-conquer', action="store_true",
                        help="use the faster divide-and-conquer method for"
                             " building the MTBDD")
    parser.add_argument('-r', '--reverse', action="store_true",
                        help="reverse field bit ordering, which can force a"
                             " inefficient ordering within the MTBDD.")
    parser.add_argument('-D', '--difference', action="store_true",
                        help="print the difference between the first and each"
                             " differing ruleset.")
    parser.add_argument('-v', '--verbose', action="store_true",
                        help="print additional stats from CUDD")

    format_parser = parser.add_argument_group(
        title="formats",
        description="Optional arguments to specify the format of the ruleset."
                    " Useful if reading from a pipe or stdin (denoted by -)"
                    " where automatic detection cannot seek back in the file.")

    for _format in INPUT_FORMATS:
        _help = "load a ruleset from the " + _format + " format."
        if _format == "auto":
            _help += " This is the default behaviour which tries all known formats."
        format_parser.add_argument("--" + _format, action="append", default=[],
                                   metavar="RULESET",
                                   help=_help)

    args = parser.parse_args()

    canonical_rulesets = []
    rulesets = {}
    single_tables = {}
    if args.rulesets:
        for f_name in args.rulesets:
            with Timer("Loading file: " + f_name):
                ruleset = load_ruleset(f_name, "auto")
                rulesets[f_name] = ruleset

    for _format in INPUT_FORMATS:
        for f_name in getattr(args, _format, []):
            with Timer("Loading " + _format + " file: " + f_name):
                ruleset = load_ruleset(f_name, _format)
                rulesets[f_name] = ruleset

    if not rulesets:
        print("Please pass at least one ruleset", file=sys.stderr)
        parser.print_usage()
        exit(-1)

    for f_name, ruleset in rulesets.items():
        print("Processing ruleset: " + f_name)
        print("Input rules: " + str(len(ruleset)))
        with Timer("Sorting"):
            ruleset = sorted([x for x in ruleset],
                             key=lambda f: (f.table, -f.priority))

        if args.reverse:
            with Timer("Reverse"):
                reverse_fields(ruleset)

        with Timer("to_single"):
            single_table = to_single_table(ruleset)
            single_tables[f_name] = single_table
        print("Single-table size: " + str(len(single_table)))

        if args.divide_conquer:
            with Timer("Normalise Divide & Conquer"):
                norm = normalise_divide_and_conquer(single_table)
        else:
            with Timer("Normalise Naive"):
                norm = normalise_naive(single_table)

        print("Unique nodes in BDD:", len(norm))
        if args.verbose:
            cuddbdd._cudd.print_info()
            print("Max memory:", cuddbdd._cudd.max_memory())
        canonical_rulesets.append((f_name, norm))

    if len(rulesets) <= 1:
        exit(0)

    print("Equivalent rulesets are printed on the same line")

    group_equal = []
    while canonical_rulesets:
        original = canonical_rulesets[0]
        equals = []
        n_ruleset = []
        # Group all those equal
        for other in canonical_rulesets[1:]:
            if check_equal(original[1], other[1], check_match_redundancy=False):
                equals.append(other)
            else:
                n_ruleset.append(other)

        group_equal.append([original] + equals)
        print(" == ".join([f_name for f_name, _ in group_equal[-1]]))
        canonical_rulesets = n_ruleset

    if args.difference:
        for first, second in zip(group_equal, group_equal[1:]):
            print("Difference between", first[0][0], "and", second[0][0])
            diff = first[0][1].difference(second[0][1])
            sbs = find_conflicting_paths(diff,
                                         single_tables[first[0][0]],
                                         single_tables[second[0][0]])
            for path, paths in sbs.items():
                print(format_path(path))
                for rpath in paths:
                    print('\n'.join(["\t" + l for l in format_path(rpath).split('\n')]))


def format_path(path):
    """ Attempt to pretty print paths """
    build = ""
    for rule in path:
        if not build:
            build += str(rule) + '\n'
        else:
            string = str(rule)
            lines = string.split('\n')
            halfway = len(lines) / 2
            build += "\n".join([('\t--> ' + line if i == halfway else '\t' + line) for i, line in enumerate(lines)])
            build += "\n"
    return build


if __name__ == "__main__":
    main()
