#!/usr/bin/python
"""
A library for loading and saving rulesets in a generic manner.

Additionally a script to convert a ruleset to a different format.

Run convert_ruleset.py -h to see the full usage
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
from pprint import pprint

import six

from .utils import as_file_handle
from .convert_fib import ruleset_from_fib
from .convert_ryu import (ruleset_to_ryu_json,
                          ruleset_to_ryu_pickle, ruleset_to_pickle,
                          ruleset_from_pickle, ruleset_from_ryu_json)

# Note currently ryu on input includes both ryu_json and ryu_pickle
INPUT_FORMATS = ("auto", "ryu_pickle", "ryu_json", "pickle", "fib")
OUTPUT_FORMATS = ("ryu_json", "ryu_pickle", "pickle", "text")

_input_load_fn = {
    "ryu_json": ruleset_from_ryu_json,
    "pickle": ruleset_from_pickle,
    "ryu_pickle": ruleset_from_pickle,
    "fib": ruleset_from_fib
    }


def ruleset_from_auto(source):
    """ Automatically load a ruleset from any format

        Automatically uncompresses files in either gzip or bzip2 format based
        on the file extension if source is a filepath.


        source: A file path or file handle
        return: A ruleset or an exception

        NOTE: Requires the file to be seekable and will likely throw an exception otherwise
              unless we guess the format correctly on our first attempt.
    """
    file_name = ''
    if hasattr(source, 'name'):
        file_name = source.name
    else:
        file_name = str(source)

    f_priority = []
    # Based on extension pick the most likely candidate format first
    if 'json' in file_name or 'jsn' in file_name:
        f_priority.append(ruleset_from_ryu_json)
    if 'pickle' in file_name or 'pkl' in file_name:
        f_priority.append(ruleset_from_pickle)
    if 'fib' in file_name:
        f_priority.append(ruleset_from_fib)

    # Add all remaining format options
    f_priority.extend(set(_input_load_fn.values()) -
                      set(f_priority))

    errors = []
    for load_fn in f_priority:
        try:
            ruleset = load_fn(source)
            return ruleset
        except Exception as e:
            errors.append((load_fn.__name__, e))
            if hasattr(source, 'seek'):
                source.seek(0)
    for error in errors:
        print(error[0], ":", error[1], file=sys.stderr)
    raise ValueError("Could not automatically open the file, unknown format: " + file_name)


def load_ruleset(source, _format='auto'):
    """ Load a ruleset from a file of the specified format

        source: A file handle or pathname, use None or "-" to read from stdin
        _format: the input file format (from INPUT_FORMATS)
    """
    if source is None or source == "-":
        if six.PY3:
            source = sys.stdin.buffer
        else:
            source = sys.stdin
    if _format == "auto":
        ruleset = ruleset_from_auto(source)
    elif _format in _input_load_fn:
        ruleset = _input_load_fn[_format](source)
    else:
        raise ValueError("Cannot load input format: " + str(_format))
    return ruleset


def save_ruleset(ruleset, destination, _format):
    """ Save a ruleset as the specified format

        ruleset: The ruleset to save
        destination: A file handle or pathname, use None or "-" to write to stdout
        _format: the output file format (from OUTPUT_FORMATS)

    """
    if destination is None or destination == "-":
        if six.PY3:
            # Needs the bytes version
            destination = sys.stdout.buffer
        else:
            destination = sys.stdout

    if _format == "ryu_json":
        ruleset_to_ryu_json(ruleset, destination)
    elif _format == "ryu_pickle":
        ruleset_to_ryu_pickle(ruleset, destination)
    elif _format == "pickle":
        ruleset_to_pickle(ruleset, destination)
    elif _format == "text":
        print_ruleset(ruleset, destination)


def main():
    parser = argparse.ArgumentParser(
        description='Converts a ruleset to either ryu_json, ryu_pickle, or Open vSwitch',
        )

    parser.add_argument('-i', '--input-format', default="auto",
                        choices=INPUT_FORMATS)
    parser.add_argument('-o', '--output-format', default="text",
                        choices=OUTPUT_FORMATS)
    parser.add_argument('source', help="the ruleset, in --input-format (use - for stdin)")
    parser.add_argument('destination', default=None, nargs='?',
                        help="the destination (stdout if omitted)")

    args = parser.parse_args()

    ruleset = load_ruleset(args.source, args.input_format)
    save_ruleset(ruleset, args.destination, args.output_format)


@as_file_handle('w', arg=('file', 1))
def print_ruleset(ruleset, file):
    """ Print a human-readable ruleset """
    pprint(ruleset, stream=file)


if __name__ == "__main__":
    main()
