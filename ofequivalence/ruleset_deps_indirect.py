"""
Methods for calculating the direct and indirect dependencies of an
OpenFlow 1.3 ruleset.

Indirect dependencies refer to all rules which shadow or goto another, directly
or indirectly. This includes across multiple tables.


For consistency, by default all functions use the headerspace implementation.
Headerspace is faster for the intersection operation, which is all that indirect
dependencies need to check.
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

from collections import defaultdict

from .utils import AttachBDD
from .rule import Rule, UniqueRules
from .headerspace import wildcard_intersect
from .utils import nullcontext
from .cuddbdd import wc_to_BDD


def add_parents_hs(R, P, reaches):
    if P and R.table == next(iter(P)).table:
        wc = R.match.get_wildcard()
    else:
        wc = R.get_goto_egress().get_wildcard()
    for Rj in P:
        if wildcard_intersect(wc, Rj.match.get_wildcard()):
            reaches.add((R, Rj))


def add_parents_bdd(R, P, reaches, parent_to_edge=None):
    """ Map all dependencies direct or indirect
    """
    if P and R.table == next(iter(P)).table:
        packets = R.as_BDD
    else:
        packets = wc_to_BDD(R.get_goto_egress().get_wildcard(), "1", "1")
    for Rj in P:
        if packets.intersection(Rj.as_BDD):
            reaches.add((R, Rj))
            if parent_to_edge is not None:
                parent_to_edge[Rj].add(R)


def build_table_deps(ruleset, use_bdd=False):
    """ Builds the dependencies within a table (direct and indirect)

    Loosely based on CacheFlow (2016), algorithm 1
    ruleset: Takes a list of Rule objects
    use_bdd: Defaults to False
    return: A mapping from edges to packet-space on that path.
            An edge is a tuple (child, parent) and add_parents selects the
            packet-space encoding.
    """
    reaches = set()
    _AttachBDD = AttachBDD if use_bdd else nullcontext
    with _AttachBDD(ruleset):
        for R in ruleset:
            potential_parents = [Rj for Rj in ruleset
                                 if Rj.priority < R.priority or Rj.table > R.table]
            if use_bdd:
                add_parents_bdd(R, potential_parents, reaches)
            else:
                add_parents_hs(R, potential_parents, reaches)

    return reaches


def build_prefix_table_deps(ruleset):
    """ Finds all direct and indirect dependencies of a prefix table

    Requires a single IPv4 prefix table as input

    Requires a ruleset with a default rule at priority 0.
    Assumes that rules are in the correct format.

    Internally uses headerspace wildcards for calculations as intersection
    is faster than BDDs and this saves an extra conversion step.

    ruleset: A list of Rule objects, must be a single IPv4 prefix table
    return: A iterable list of (child, parent) dependencies
    """
    # Sort subnets from 0.0.0.0 -> 255.255.255.255 then if required /0 -> /32
    ruleset = sorted(ruleset,
                     key=lambda x: (x.match["IPV4_DST"][0], x.priority))
    reaches = list()
    assert ruleset[0].priority == 0
    assert ruleset[0].match.get_wildcard() == Rule().match.get_wildcard()

    # Add the default rule to the bottom of the chain
    chain = [ruleset[0]]
    for rule in ruleset[1:]:
        # As rules are ordered, once we stop overlapping a rule we know
        # no subsequent rules will. So pop that.
        while not wildcard_intersect(chain[-1].match.get_wildcard(),
                                     rule.match.get_wildcard()):
            chain.pop()
        # We can only overlap with one rule and will do so completely
        for c_rule in chain:
            reaches.append((rule, c_rule))
        chain.append(rule)
    return reaches


def _recurse_goto_deps(tables, table, match, parents, edges):
    for rule in tables[table]:
        next_table = rule.instructions.goto_table
        if next_table is None:
            if (match is not None and
                    not wildcard_intersect(match.get_wildcard(), rule.match.get_wildcard())):
                continue
        else:
            try:
                egress = rule.get_goto_egress(match)
            except Exception:
                continue
        for parent in parents:
            edges.add((parent, rule))
        if next_table:
            assert rule.instructions.goto_table > table
            _recurse_goto_deps(tables, next_table, egress, parents + (rule,), edges)


def build_ruleset_deps(ruleset, build_table=build_table_deps,
                       use_bdd=None):
    """ Build the dependencies for a multi-table ruleset

        ruleset: Takes a list of Rule objects
        _build_table: Algorithm within a table, build_table_deps by default
        returns: A list of dependency pairs in the format
                 [(f1, f2), (f1, f3), ...]
    """
    edges = set()
    _AttachBDD = AttachBDD if use_bdd else nullcontext
    with UniqueRules(), _AttachBDD(ruleset):
        ruleset_tables = defaultdict(list)
        for rule in ruleset:
            ruleset_tables[rule.table].append(rule)

        for table in ruleset_tables:
            _recurse_goto_deps(ruleset_tables, table, None, tuple(), edges)

        for table in ruleset_tables.values():
            if use_bdd is not None:
                edges.update(build_table(table, use_bdd=use_bdd))
            else:
                edges.update(build_table(table))

    return list(edges)
