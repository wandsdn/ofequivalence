""" Extra util classes and methods
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
from .cuddbdd import wc_to_BDD


class nullcontext(object):
    """ A context that does nothing
        Similar to contextlib.nullcontext since version 3.7
    """
    def __init__(self, enter_result=None, *_args, **_kwargs):
        self.enter_result = enter_result

    def __enter__(self, *_args, **_kwargs):
        return self.enter_result

    def __exit__(self, *_args, **_kwargs):
        pass


class AttachBDD(object):
    """ Adds as_BDD to a rule
        Undone once the block is left

        Usage with:
        with(ruleset):
            pass
    """
    def __init__(self, ruleset):
        self.ruleset = ruleset

    def __enter__(self):
        # Re-entry, assume if one rule does all do
        if hasattr(self.ruleset[0], "as_BDD"):
            self.ruleset = None
            return
        for rule in self.ruleset:
            rule.as_BDD = wc_to_BDD(rule.match.get_wildcard(), "1", "1")

    def __exit__(self, *args):
        if self.ruleset:
            for rule in self.ruleset:
                del rule.as_BDD


def open_compressed(f_name, mode="rb"):
    """ open() a file which might be compressed """
    if f_name.endswith(".gz"):
        import gzip
        f_handle = gzip.GzipFile(f_name, mode)
    elif f_name.endswith(".bz2"):
        import bz2
        f_handle = bz2.BZ2File(f_name, mode)
    else:
        f_handle = open(f_name, mode)
    return f_handle
