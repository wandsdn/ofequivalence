"""
Provides a methods of normalising the flow rules in a pipeline to canonical
form so that two solutions can easily be compared for equality and
in the case of conflicts those conflicting portions of traffic can be
identified.

This implementation uses headerspace to compute equality.

WARNING: This is not complete/correct, use the BDD implementation instead
         BDDs are much faster and have more predictable memory requirements.
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

import collections
from six import viewitems, viewvalues
from .headerspace import (flow_wildcard_to_fields,
                          wildcard_is_subset, wildcard_intersect)
from .ruleset import sort_ruleset


class BooleanShim(object):
    zero = False
    include = None
    excludes = None

    def __init__(self, wc=None):
        self.excludes = set()
        if wc is not None:
            self.add(wc, True)
        else:
            self.zero = True

    def dup(self):
        ret = BooleanShim()
        ret.include = self.include
        ret.excludes = set(self.excludes)
        ret.zero = self.zero
        return ret

    def add(self, wc, include):
        if self.zero:
            return
        if include:
            if self.include is None:
                self.include = wc
                if self.include == 0:
                    self.zero = True
                    return
            else:
                self.include = wildcard_intersect(self.include, wc)
                # Check that there is an intersecting portion
                if self.include == 0:
                    self.zero = True
                    return
                # Check this has not become zero against an exclude
                for x in self.excludes:
                    if wildcard_is_subset(self.include, x):
                        self.zero = True
        else:
            # If include is a subset of exclude this simplifies to zero
            # Or includes it's self
            if wildcard_is_subset(self.include, wc):
                self.zero = True
            else:
                #if not wildcard_intersect(self.include, wc):
                #    return
                rem = []
                for existing in self.excludes:
                    # If this covers all of an existing simply get rid of it
                    if wildcard_is_subset(existing, wc):
                        rem.append(existing)
                    elif wildcard_is_subset(wc, existing):
                        # Already covered by another don't add
                        assert len(rem) == 0
                        return
                for x in rem:
                    self.excludes.remove(x)
                """ Check if we continue on from an existing bit pattern
                    i.e. if two have a single bit of difference
                """
                for existing in self.excludes:
                    i = wildcard_intersect(wc, existing)
                    if str(i) == "empty":
                        # TODO
                        diff_pos = None
                        for i in range(0, len(wc)):
                            diff = wc[i] ^ existing[i]
                            # look for differences i.e. places with 1 and 0
                            # A 1 is 2 so we are looking for two
                            # aligned values
                            if diff:
                                values = (3, 12, 48, 192, 768, 3072, 12288,
                                          49152)
                                if diff in values:
                                    if diff_pos is None:
                                        diff_pos = i*8 + values.index(diff)
                                    else:
                                        diff_pos = "NUKE"
                                        break
                                else:
                                    diff_pos = "NUKE"
                                    break
                                    pass
                        if diff_pos is not None and diff_pos != "NUKE":
                            nw = wc  # TODO Double check this was a wc copy
                            nw[(diff_pos/8, diff_pos % 8)] = 3
                            self.excludes.remove(existing)
                            self.add(nw, False)
                            return
                # Ok nothing is simplifying lets stop
                self.excludes.add(wc)

    def __eq__(self, other):
        if self.zero or other.zero:
            if self.zero and other.zero:
                return True
            else:
                return False
        return (self.include == other.include and self.excludes ==
                other.excludes)

    def __ne__(self, other):
        return not self == other

    def __str__(self):
        if self.zero:
            return "empty"

        def fields_to_str(fs):
            ret = []
            for f in fs:
                if f[2] is None:
                    ret.append(f[0] + "=" + str(f[1]))
                else:
                    ret.append(f[0] + "=" + str(f[1]) + "/" + str(f[2]))
            return ",".join(ret)

        ret = ""
        ex_map = {}
        for a in self.excludes:
            fields = flow_wildcard_to_fields(a)
            ex_map[a] = fields_to_str(fields)

        ret = "(" + fields_to_str(flow_wildcard_to_fields(self.include)) + ") "
        for a in sorted(viewvalues(ex_map)):
            ret += "!(" + a + ") "
        return ret

    def __hash__(self):
        if self.zero:
            return hash(self.zero)
        return hash((self.include, frozenset(self.excludes)))

    def matches(self, match):
        if self.include != wildcard_intersect(self.include, match):
            return False
        else:
            return True

    def intersection(self, match):
        ret = self.dup()
        ret.include = wildcard_intersect(self.include, match)
        return ret


def rules_to_shim_map(rules):
    ret = collections.OrderedDict()
    for r in rules:
        # Make sure we don't overwrite a high priority rule with an identical
        # low priority one
        b = BooleanShim(r[0])
        if b not in ret:
            ret[b] = r[1]
    return ret


def normalise(rules, match_redundancy=False):
    """
    rules: A list of Flows() in priority order and in single table form
    match_redundancy: Unsupported, ignored
    return: A dictionary of rule to action
    """
    # Action mapping 1
    # 2 etc.

    # Convert to (wildcard -> action) mapping
    rules = [(x.match.get_wildcard(),
              (x.instructions.apply_actions +
                  x.instructions.write_actions).per_output_actions())
             for x in rules]

    # So we want to expand up every rule
    add_fields = set([x[0] for x in rules])
    rules = rules_to_shim_map(rules)
#    rules = [(BooleanShim(x[0]), x[1]) for x in rules]
    working_rules = merge_rules(rules, add_fields)
    """
    working_rules = {}
    for r in rules:
        # Merge each rule with the others for the yes and no case
        excluding = list(rules)
        excluding.remove(r)
        group_rules = {}
        group_rules[BooleanShim(r[0])] = r[1]
        next_group_rules = {}
        for a in excluding:
            next_group_rules = {}
            for z in viewitems(group_rules):
                pos = z[0].dup()
                neg = z[0].dup()
                neg.add(a[0], False)
                pos.add(a[0], True)
                if pos not in next_group_rules:
                    next_group_rules[pos] = r[1]
                if neg not in next_group_rules:
                    next_group_rules[neg] = r[1]
            group_rules = next_group_rules
        z = group_rules.copy()
        z.update(working_rules)
        working_rules = z
    """
    # Reduce
    # reduce down the rules

    """
    print "Set done"
    for a, b in viewitems(working_rules):
        print a, "->", b
    """
    return (working_rules, add_fields)


def merge_rules(rules_in, add_fields):

    resulting = {}
    for r in viewitems(rules_in):
        group_rules = {}
        group_rules[r[0]] = r[1]
        for a in add_fields:
            next_group_rules = {}
            for z in viewitems(group_rules):
                pos = z[0].dup()
                neg = z[0].dup()
                neg.add(a, False)
                pos.add(a, True)
                if pos not in next_group_rules:
                    next_group_rules[pos] = r[1]
                if neg not in next_group_rules:
                    next_group_rules[neg] = r[1]
            group_rules = next_group_rules
        z = group_rules.copy()
        z.update(resulting)
        resulting = z
    return resulting


def check_equal(norm1, norm2, debug_=False, diff=False):
    """ Checks if the two canonical forms are equivalent.
        a: The output of normalise
        b: The output of normalise
        debug_: Print additional debug information
        diff: If set returns is a tuple, (is_equal, difference)
              The difference returned should be considered opaque.
        return: True if a is equal b, otherwise False
    """
    addto1 = norm2[1] - norm1[1]
    addto2 = norm1[1] - norm2[1]

    if debug_:
        print("Input 1")
        for a, b in viewitems(norm1[0]):
            print(a, "->", b)
        print("Input 2")
        for a, b in viewitems(norm2[0]):
            print(a, "->", b)

    working_rules1 = merge_rules(norm1[0], addto1)
    working_rules2 = merge_rules(norm2[0], addto2)

    # Remove any empty booleans
    del working_rules1[BooleanShim()]
    del working_rules2[BooleanShim()]

    if debug_ or diff:
        new_only = set(working_rules1) - set(working_rules2)
        missing_only = set(working_rules2) - set(working_rules1)
        difference = set(working_rules1).intersection(set(working_rules2))
        difference = [x for x in difference
                      if working_rules1[x] != working_rules2[x]]

    if debug_:
        print("Merged new")
        for a, b in viewitems(working_rules1):
            print(a, "->", b)
        print("Merged target")
        for a, b in viewitems(working_rules2):
            print(a, "->", b)

        print("Only in new")
        for a in new_only:
            b = working_rules1[a]
            print(a, "->", b)
        print("Only in target")
        for a in missing_only:
            b = working_rules2[a]
            print(a, "->", b)
        print("Mismatched")
        for a in difference:
            print(a, "new ->", working_rules1[a])
            print("\t", "orig ->", working_rules2[a])

    if diff:
        assert len(new_only) == 0
        assert len(missing_only) == 0
        return working_rules1 == working_rules2, difference
    else:
        return working_rules1 == working_rules2


def _collect_paths(headerspace, ruleset):
    """ Find the path packets a subset of packets will hit in a pipeline

        headerspace: A BooleanShim
        ruleset: Must be ordered and in single table form
        return: A list of tuples (path, BooleanShim)
    """
    collected = []
    for rule in ruleset:
        if headerspace.matches(rule.match.get_wildcard()):
            collected.append((rule.path, headerspace.intersection(rule.match.get_wildcard())))
    return collected


def find_conflicting_paths(diff, orig_flows, new_flows):
    """ Maps a BDD difference back to the paths in the ruleset

        Takes two rulesets and returns a mapping from the original paths
        through the pipeline to those paths which differ in the new ruleset.

        Here a path is a tuple of rules which form a path through the pipeline
        always starting from table 0 and finishing on a rule without a goto.

        diff: The difference, resulting from check_equal
        orig_flows: The original single-table ruleset
        new_flows: The new single-table ruleset
        return: A dict mapping the original paths attached, to a
                set of the conflicting flows in new_flows
                (i.e. those flows on paths which match the same traffic)

        NOTE: A path is a list of flows each of which 'goes to' the next until
              no more gotos are found and the packet exits the pipeline.

        WARNING: Does not account for shadowed rules, use the BDD implementation
    """
    orig_flows = sort_ruleset(orig_flows)
    new_flows = sort_ruleset(new_flows)
    r = {}

    for headerspace_shim in diff:
        orig_paths = _collect_paths(headerspace_shim, orig_flows)
        for orig_path, hss in orig_paths:
            new_conflicts = []
            new_paths = _collect_paths(hss, new_flows)
            for new_path, _ in new_paths:
                new_conflicts.append(new_path)
            if orig_path in r:
                r[orig_path] |= frozenset(new_conflicts)
            else:
                r[orig_path] = frozenset(new_conflicts)
    return r
