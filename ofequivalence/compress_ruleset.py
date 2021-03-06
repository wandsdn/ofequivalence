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
from sys import stderr
import argparse

from .convert_ruleset import (INPUT_FORMATS, OUTPUT_FORMATS, load_ruleset,
                              save_ruleset)
from .ruleset import (compress_ruleset, sort_ruleset,
                      to_single_table)
from .utils import nullcontext, Timer
from . import ruleset_deps_direct
from . import ruleset_deps_indirect

def main():
    parser = argparse.ArgumentParser(
        description='Runs the compression algorithm and prints the output'
        )

    parser.add_argument('filein', help='the input ruleset')
    parser.add_argument('--input-format', choices=INPUT_FORMATS, default="auto",
                        help="the input format, 'auto' by default."
                             " If 'fib', applies optimisations to compression.")
    parser.add_argument('-s', '--single', action='store_true',
                        help="first convert the ruleset to a single table")
    parser.add_argument('-t', '--time', action='store_true',
                        help="print timing information")
    parser.add_argument('--direct', action='store_true',
                        help="consider only direct method dependencies")
    parser.add_argument('--bdd', action='store_true', default=None,
                        help="force the use of BDDs in calculations, "
                             "unsupported with some combinations")
    parser.add_argument('--headerspace', action='store_true', default=None,
                        help="force the use of headerspace in calculations,"
                             " unsupported with some combinations")
    parser.add_argument('--output', default=None,
                        help="save the compressed ruleset to a file")
    parser.add_argument('--output-format', default="text",
                        choices=OUTPUT_FORMATS,
                        help="the output file type of the compressed ruleset. "
                             "Default: text")

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
        ruleset = load_ruleset(args.filein, args.input_format)

    print("Original ruleset size: ", len(ruleset), file=stderr)

    if args.single:
        with Timer("To single table", file=stderr):
            ruleset = to_single_table(ruleset, openflow=False)
        print("Single table size:", len(ruleset), file=stderr)

    with Timer("Sorting", file=stderr):
        ruleset = sort_ruleset(ruleset)

    with Timer("Building DAG", file=stderr):
        if args.input_format == "fib":
            deps = build_ruleset_deps(ruleset, build_table=build_prefix_table_deps, **extra)
        else:
            deps = build_ruleset_deps(ruleset, **extra)

    with Timer("Compressing ruleset", file=stderr):
        compressed_ruleset, _groups = compress_ruleset(ruleset, deps=deps)

    print("Compressed {} rules down to {}".format(len(ruleset), len(compressed_ruleset)),
          file=stderr)

    if args.output is not None:
        save_ruleset(ruleset, args.output, args.output_format)

    if not args.single:
        min_single = to_single_table(compressed_ruleset)
        print("Size as single table {}".format(len(min_single)), file=stderr)


if __name__ == "__main__":
    main()
