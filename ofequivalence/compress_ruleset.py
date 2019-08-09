#!/usr/bin/python
"""
A script to run the compression algorithm on a ruleset.

Outputs timing information, the compression achieved and will write the
resulting ruleset to a file.

Run compress_ruleset.py -h to see the full usage
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
from sys import stderr, stdout
from pprint import pprint
import argparse

import six

from .convert_ryu import (ruleset_from_ryu, ruleset_to_ryu_json,
                          ruleset_to_ryu_pickle, ruleset_to_pickle)
from .convert_fib import ruleset_from_fib
from .ruleset import (compress_ruleset, sort_ruleset,
                      to_single_table)
from .utils import nullcontext, Timer
from . import ruleset_deps_direct
from . import ruleset_deps_indirect

def main():
    parser = argparse.ArgumentParser(
        description='Runs the compression algorithm and prints the output'
        )

    parser.add_argument('filein', help='A pickled ryu stats file')
    parser.add_argument('-f', '--fib', action='store_true',
                        help="Loads a FIB, and enables optimisations")
    parser.add_argument('-s', '--single', action='store_true',
                        help="Convert the ruleset to single table first")
    parser.add_argument('-t', '--time', action='store_true',
                        help="Print timing information")
    parser.add_argument('--direct', action='store_true',
                        help="Consider only direct method dependencies")
    parser.add_argument('--bdd', action='store_true', default=None,
                        help="Force the use of BDDs in calculations, unsupported with some combinations")
    parser.add_argument('--headerspace', action='store_true', default=None,
                        help="Force the use of headerspace in calculations, unsupported with some combinations")
    parser.add_argument('--output', default=None,
                        help="Save the compressed ruleset to a file")
    parser.add_argument('--type', default=None,
                        choices=["text", "ryu_json", "ryu_pickle", "pickle"],
                        help="The file type of the compressed ruleset")

    args = parser.parse_args()

    extra = {}
    if args.bdd:
        extra = {'use_bdd': True}
    if args.headerspace:
        extra = {'use_bdd': False}

    if not args.time:
        global Timer
        Timer = nullcontext

    if args.direct:
        build_ruleset_deps = ruleset_deps_direct.build_ruleset_deps
        build_prefix_table_deps = ruleset_deps_direct.build_prefix_table_deps
    else:
        build_ruleset_deps = ruleset_deps_indirect.build_ruleset_deps
        build_prefix_table_deps = ruleset_deps_indirect.build_prefix_table_deps

    with Timer("Loading ruleset", file=stderr):
        if args.fib:
            ruleset = ruleset_from_fib(args.filein)
        else:
            ruleset = ruleset_from_ryu(args.filein)

    print("Original ruleset size: ", len(ruleset), file=stderr)

    if args.single:
        with Timer("To single table", file=stderr):
            ruleset = to_single_table(ruleset, openflow=False)
        print("Single table size:", len(ruleset), file=stderr)

    with Timer("Sorting", file=stderr):
        ruleset = sort_ruleset(ruleset)

    with Timer("Building DAG", file=stderr):
        if args.fib:
            deps = build_ruleset_deps(ruleset, build_table=build_prefix_table_deps, **extra)
        else:
            deps = build_ruleset_deps(ruleset, **extra)

    with Timer("Compressing ruleset", file=stderr):
        compressed_ruleset, _groups = compress_ruleset(ruleset, deps=deps)

    print("Compressed {} rules down to {}".format(len(ruleset), len(compressed_ruleset)),
          file=stderr)

    out_func = None
    if args.type is None and args.output is not None:
        if args.output == "-":
            args.type = "text"
        else:
            args.type = "ryu_json"

    if args.type is not None and args.output is None:
        args.output = "-"

    if args.type == "text":
        out_func = print_ruleset
    if args.type == "ryu_json":
        out_func = ruleset_to_ryu_json
    if args.type == "ryu_pickle":
        out_func = ruleset_to_ryu_pickle
    if args.type == "pickle":
        out_func = ruleset_to_pickle
    if out_func:
        if args.output == "-":
            if six.PY3 and args.type in ['ryu_pickle', 'pickle']:
                # Needs the bytes version
                file = stdout.buffer
            else:
                file = stdout
        else:
            file = args.output
        out_func(ruleset, file)

    if not args.single:
        min_single = to_single_table(compressed_ruleset)
        print("Size as single table {}".format(len(min_single)), file=stderr)

def print_ruleset(ruleset, file):
    """ Print a human-readable ruleset """
    try:
        pprint(ruleset, stream=file)
    except AttributeError:
        with open(file, 'w') as f_out:
            pprint(ruleset, stream=f_out)


if __name__ == "__main__":
    main()
