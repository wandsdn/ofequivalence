"""
Provides a method of normalising the flow rules in a pipeline to canonical
form so that two solutions can easily be compared for equality and
in the case of conflicts those conflicting portions of traffic can be
identified.

This implementation uses binary decision diagrams to compute equality.
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

import itertools
try:
    from tqdm import tqdm
except ImportError:
    pass
from .cuddbdd import (BDD, wc_to_BDD, IS_DIFFERING_TUPLE, BDD_to_matches)
from .rule import Match, ActionList
from .headerspace import wildcard_intersect, flow_wildcard_to_flowmatches
from .ruleset import sort_ruleset


def normalise_set_fields(rule):
    """ Normalises a flow rule containing set fields

    This is the EAGER solution to the set field problem.

    If a flow rule contains a set field, if the match is already
    set to that value a NOP is equivalent. This becomes a problem
    if one ruleset was:
    1.1.1.0/24 -> set field 1.1.1.1

    And another
    1.1.1.1 -> NOP
    1.1.1.0/24 -> set field

    So we normalise to the latter. For every set field found an equivalent
    NOP is added for the overlapping field at a higher priority.

    Complexity (Space and Time): Scales (2^x) - 1: where x is the number of set
                                 fields

    rule: The flow rule
    output: A list of priority-ordered (highest first)
    (wildcard, per output actions) pairs. See _per_output_actions().

    Bugs: Does not correctly account for vlan_vid as the tag depth is
          not considered. TODO
    """
    pp_actions = rule.instructions.full_actions()._per_output_actions()
    res = []

    # Collect all unique set fields
    set_fields = set()
    for output in pp_actions.values():
        for action in output:
            if action[0] == "SET_FIELD":
                set_fields.add(action[1])

    # Grab all combinations starting with all fields first (the most specific)
    for comb_len in range(len(set_fields), 0, -1):
        for combination in itertools.combinations(set_fields, comb_len):
            # We can get both set field x and set field y here
            # TODO should be tag depth aware

            # Convert set fields to match
            sf_wc = Match().get_wildcard()
            for field in combination:
                # Like this to detect overwrites
                wc = Match([(field[0], field[1], None)]).get_wildcard()
                sf_wc = wildcard_intersect(sf_wc, wc)

            # Check is this field combo in the match
            overlap = wildcard_intersect(rule.match.get_wildcard(), sf_wc)
            if not overlap:
                continue

            # Remove all set field x from the outputs
            new_actions = {}
            for port, actions in pp_actions.items():
                new_actions[port] = [action for action in actions
                                     if action[1] not in combination]
            # Should probably check action type here but mah, why bother
            # only set actions are going to have the format (field, value)
            # anyway
            res.append((overlap, new_actions))

    # Lowest priority add the original
    res.append((rule.match.get_wildcard(), pp_actions))
    for rule in res:
        print(flow_wildcard_to_flowmatches(rule[0], Match), rule[1])
    return res


def normalise_divide_and_conquer(rules, progress=False,
                                 match_redundancy=False):
    """ Recursive pairwise merging of rules to a canonical form

        Merge each pair of rules then recursively repeat on the result until
        one BDD remains. Like how merge-sort works. This is more efficient
        than the naive approach as most merges are dealing with smaller BDDs.

        rules: A list of Flows() in priority order and single table form.
        progress: Print progress using tqdm, Default False
        match_redundancy: If True resolve redundancy between set fields and
                          match. This is more expensive, but can resolve more
                          equivalences. See normalise_set_fields for more.
        return: A canonical form which should be considered opaque. In practice
                this is a BDD.
    """
    bdds = []
    for rule in rules:
        if match_redundancy:
            for match_wc, actions in normalise_set_fields(rule):
                bdds.append(wc_to_BDD(match_wc, actions, str(actions)))
        else:
            actions = rule.instructions.full_actions()._per_output_actions()
            bdds.append(wc_to_BDD(rule.match.get_wildcard(),
                                  actions, str(actions)))
    while len(bdds) > 1:
        pairs = zip(bdds[::2], bdds[1::2])
        if progress:
            pairs = tqdm(pairs)
        n_bdds = [a+b for a, b in pairs]
        if len(bdds) % 2 == 1:
            n_bdds.append(bdds[-1])
        bdds = n_bdds
    assert len(bdds) == 1
    return bdds[0]


def normalise_naive(rules, progress=False, match_redundancy=False):
    """ Top to bottom building of a BDD to a canonical form

        Simply build the BDD by adding the next lowest priority rule to
        the last result. By the end the BDD being added to can be large
        and this operation can slow significantly.

        rules: A list of Flows() in priority order and single table form.
        progress: Print progress using tqdm, default False
        match_redundancy: If True resolve redundancy between set fields and
                          match. This is more expensive, but can resolve more
                          equivalences. See normalise_set_fields for more.
        return: A canonical form which should be considered opaque. In practice
                this is a BDD.
    """
    bdd = BDD()
    if progress:
        rules = tqdm(rules)
    for rule in rules:
        if match_redundancy:
            for match_wc, actions in normalise_set_fields(rule):
                bdd = bdd + wc_to_BDD(match_wc, actions, str(actions))
        else:
            actions = rule.instructions.full_actions()._per_output_actions()
            bdd = bdd + wc_to_BDD(rule.match.get_wildcard(),
                                  actions, str(actions))
    return bdd

# Use divide and conquer by default as it is faster
normalise = normalise_divide_and_conquer


def check_equal_match_redundancy(a, b):
    """ Performs extra checking on any two seemingly different BDDs.

        This is the LAZY approach, to solving the set field problem.

        This detects this case:
        Match(field:1) ApplyActions(set field:1) == Match(field:1)
        Where the match makes the a set field action a NOP.

        return: (is equal, diff tagged)
    """
    diff = a.difftagged(b)
    # For every path collect the left and right sides
    for match, left, right in BDD_to_matches(diff):
        # Check early if keys (i.e. output ports) fail to match
        if set(left.keys()) != set(right.keys()):
            return False, diff
        # Normalise the actions by adding a SET_FIELD action to the beginning
        # of the existing actions for every fully matched field.
        set_fields = ActionList()
        for field, value in match.items():
            if value[1] is None:  # No mask
                set_fields.append('SET_FIELD', (field, value[0]))
        if not len(set_fields):
            return False, diff
        # The actions left/right are already per port, each key is a port
        for k in left.keys():
            newleft = set_fields + left[k]
            newright = set_fields + right[k]
            if newleft._per_output_actions() != newright._per_output_actions():
                return False, diff
    return True, diff


def check_equal(a, b, debug_=False, diff=False, check_match_redundancy=True):
    """ Checks if the two canonical forms are equivalent.
        a: The output of normalise
        b: The output of normalise
        debug_: Print additional debug information
        diff: If set returns is a tuple, (is_equal, difference)
              The difference returned should be considered opaque.
        check_match_redundancy: Defaults to True. Lazily performs additional
                                checks to find NO-OP set fields based on the
                                match.
        return: True if a is equal b, otherwise False
    """
    if diff is False:
        if check_match_redundancy:
            return check_equal_match_redundancy(a, b)[0]
        else:
            return a == b
    else:
        if check_match_redundancy:
            return check_equal_match_redundancy(a, b)[0], a.difference(b)
        else:
            return a == b, a.difference(b)


def _collect_paths(bdd, ruleset):
    """ Find all paths a subset of packets take through a pipeline

        bdd: The BDD representing the section of traffic, from BDD.difference
        ruleset: A ruleset as a single table, with Rule.path populated
                 by ruleset.to_single_table()
        return: A list of paths matching the bdd
                e.g.
                [
                ((r1,r2), BDD),
                ((r1,r2,r3), BDD),
                ((r1,r2,r3), BDD),
                ]
    """
    collected = []
    remaining_bdd = bdd
    empty = BDD()
    for rule in ruleset:
        assert rule.table == 0
        # The difference uses the termination IS_DIFFERING, so we match the
        # rule to that and use intersection to find the overlap.
        r_bdd = wc_to_BDD(rule.match.get_wildcard(), *IS_DIFFERING_TUPLE)
        intersection = remaining_bdd.intersection(r_bdd)
        if intersection != empty:
            remaining_bdd = remaining_bdd.difference(intersection)
            collected.append((rule.path, intersection))
        if remaining_bdd == empty:
            break
    # If we have a remaining unmatched portion we must not have a default
    # rule. Per OpenFlow spec this is a drop (unless, overridden by switch
    # configuration; but we'll ignore that).
    # As we don't have an actual rule for this return an empty set
    if remaining_bdd != empty:
        collected.append((tuple(), remaining_bdd))

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
    """
    orig_flows = sort_ruleset(orig_flows)
    new_flows = sort_ruleset(new_flows)
    r = {}

    conflicting_orig_paths = _collect_paths(diff, orig_flows)
    for orig_path, orig_path_BDD in conflicting_orig_paths:
        new_conflicts = []
        for new_path, _bdd in _collect_paths(orig_path_BDD, new_flows):
            new_conflicts.append(new_path)
        r[orig_path] = frozenset(new_conflicts)
    return r
