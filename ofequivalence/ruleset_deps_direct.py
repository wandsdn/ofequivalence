"""
Methods for calculating the direct dependencies of an OpenFlow 1.3 ruleset.

Direct dependencies refer to only directly shadowed rules, or direct goto's.
For consistancy, by default all functions use the BDD implementation.
Despite in some cases headerspace being faster, such as a prefix table.
Overall though using BDD, allows this to more easily be combined with other functions

This is the CacheFlow (2016) style of building dependency DAGs
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
import warnings

from six import viewitems
from .rule import Rule, Match, UniqueRules
from .utils import nullcontext, AttachBDD
from .headerspace import headerspace, wildcard_intersect
from .cuddbdd import wc_to_BDD, BDD

DO_LAZY = True
# Offline algorithm 1 for building dependency graph
# Finding direct dependencies: Ri (child) is a dependency of Rj (parent)
# iff Ri is removed packets that should hit Ri will instead hit Rj
def get_header_space(rule):
    hs = headerspace()
    hs.add_hs(rule.match.get_wildcard())
    return hs


def add_parents_hs(R, P, reaches):
    if P and R.table == next(iter(P)).table:
        packets = get_header_space(R)
    else:
        packets = headerspace()
        packets.add_hs(R.get_goto_egress().get_wildcard())
    for Rj in sorted(P, key=lambda x: -x.priority):  # descending order
        Rj_hs = get_header_space(Rj)
        intersection = packets.copy_intersect(Rj_hs)
        intersection.clean_up()
        if not intersection.is_empty():
            reaches[(R, Rj)] = intersection
            if DO_LAZY:
                assert len(Rj_hs.hs_list) == 1 and not Rj_hs.hs_diff[0]
                packets.diff_hs(Rj_hs.hs_list[0])
            else:
                packets.minus(Rj_hs)


def add_parents_bdd(R, P, reaches, parent_to_edge=None):
    if P and R.table == next(iter(P)).table:
        packets = R.as_BDD
    else:
        packets = wc_to_BDD(R.get_goto_egress().get_wildcard(), "1", "1")
    for Rj in sorted(P, key=lambda x: -x.priority):  # descending order
        intersection = packets.intersection(Rj.as_BDD)
        if intersection:
            reaches[(R, Rj)] = intersection
            if parent_to_edge is not None:
                parent_to_edge[Rj].add(R)
            packets = packets.subtract(Rj.as_BDD)
            if not packets:
                break

def build_table_deps(ruleset, use_bdd=True):
    """
    Based on CacheFlow (2016), algorithm 1
    ruleset: Takes a list of Rule objects
    use_bdd: Default True, use a BDD for calculations, alternativly use headerspace

    return: A mapping from edges to packet-space on that path.
            An edge is a tuple (child, parent) and add_parents selects the
            packet-space encoding.
    """
    reaches = {}
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


def build_prefix_table_deps(ruleset, use_bdd=True):
    """
    Builds a DAG for a IPv4 prefix table

    Requires a ruleset with a default rule at priority 0.
    Assumes that rules are in the correct format.

    ruleset: A list of Rule objects
    use_bdd: Default True, use a BDD for calculations, alternativly use headerspace
    return: A mapping from edges to packet-space on that path.
            An edge is a tuple (child, parent) and add_parents selects the
            packet-space encoding.
    """
    # Sort subnets from 0.0.0.0 -> 255.255.255.255 then if required /0 -> /32
    ruleset = sorted(ruleset,
                     key=lambda x: (x.match["IPV4_DST"][0], x.priority))
    reaches = {}
    assert ruleset[0].priority == 0
    assert ruleset[0].match.get_wildcard() == Rule().match.get_wildcard()

    # Add the default rule to the bottom of the chain
    chain = [ruleset[0]]
    _AttachBDD = AttachBDD if use_bdd else nullcontext
    with _AttachBDD(ruleset):
        for rule in ruleset[1:]:
            # As rules are ordered, once we stop overlapping a rule we know
            # no subsequent rules will. So pop that.
            if use_bdd:
                while not chain[-1].as_BDD.intersection(rule.as_BDD):
                    chain.pop()
                reaches[(rule, chain[-1])] = rule.as_BDD
            else:
                while not wildcard_intersect(chain[-1].match.get_wildcard(),
                                             rule.match.get_wildcard()):
                    chain.pop()
                reaches[(rule, chain[-1])] = rule.match.get_wildcard()
            chain.append(rule)

    return reaches


def _find_affected_edges(rule, new_rule, aff_edges, potential_parents, reaches,
                         parent_to_edge):
    for child in parent_to_edge[rule]:
        if child.priority > new_rule.priority:
            # We might have to modify existing edges
            if reaches[(child, rule)].intersection(new_rule.as_BDD):
                aff_edges[child].append((child, rule))
        elif child.priority < new_rule.priority:
            # We might need to add new edges
            # CacheFlow Algorithm says check the union, but that does not make
            # sense. This needs to be the intersection.
            # Don't reconsider the same node twice
            if (child not in potential_parents and
                    child.as_BDD.intersection(new_rule.as_BDD)):
                potential_parents.add(child)
                _find_affected_edges(child, new_rule, aff_edges,
                                     potential_parents, reaches, parent_to_edge)
        # Do not need check if priorities are equal


def _process_affected_edges(aff_edges, new_rule, reaches, parent_to_edge):
    for child, edges in viewitems(aff_edges):
        # The CacheFlow algorithm listed does not make sense here as it only
        # as it takes the reaches for the new edge from the packet-space of
        # only one edge.
        # Instead this should be the union of all edges overlap (intersection)
        # with the new rule
        # Note: BDD + is priorityAdd, which gives the union

        # Delete edges which are now empty
        new_packets = BDD()
        for edge in edges:
            diff = reaches[edge].subtract(new_rule.as_BDD)
            if not diff:
                # The old edge is empty delete, so 100% intersect overlap
                new_packets += reaches.pop(edge)
                parent_to_edge[edge[1]].remove(edge[0])
            else:
                # The old edge still exists, update the packet space
                new_packets += reaches[edge].intersection(new_rule.as_BDD)
                reaches[edge] = diff
        reaches[(child, new_rule)] = new_packets
        parent_to_edge[new_rule].add(child)


def dep_dag_insert(default_rule, new_rule, reaches, parent_to_edge):
    """
    Insert a rule into an existing dependency DAG
    """
    # A list of affected edges Map child -> list of edges list[(child, parent) ...]
    aff_edges = defaultdict(list)
    potential_parents = set()  # A set of potential parent nodes
    potential_parents.add(default_rule)
    _find_affected_edges(default_rule, new_rule, aff_edges, potential_parents,
                         reaches, parent_to_edge)
    _process_affected_edges(aff_edges, new_rule, reaches, parent_to_edge)
    add_parents_bdd(new_rule, potential_parents, reaches, parent_to_edge)


def build_table_deps_incremental(ruleset, use_bdd=True):
    """
    Based on CacheFlow (2006), algorithm 2

    An incremental version of building the DAG which can outperform
    the naive, by only considering parts of the DAG which can actually
    overlap.

    The incremental building always uses a BDD

    ruleset: Takes a list of Rule objects
    use_bdd: Must be True, ignored as headerspace is not supported
    return: A mapping from edges to packet-space on that path.
            An edge is a tuple (child, parent) and add_parents selects the
            packet-space encoding.
    """
    # Find the default
    exc_default = []
    default = None
    ruleset = sorted(ruleset, key=lambda key: key.priority)
    match_all = Match().get_wildcard()
    for rule in ruleset:
        if rule.match.get_wildcard() == match_all:
            default = rule
        else:
            exc_default.append(rule)

    if default is None:
        raise ValueError("No default rule found in table {}".format(ruleset[0].table))

    reaches = {}  # Map (child, parent) [aka. an edge] -> packet-space on edge
    parent_to_edge = defaultdict(set)

    with UniqueRules(reaches), AttachBDD(ruleset):  # Faster object compare
        for rule in exc_default:
            dep_dag_insert(default, rule, reaches, parent_to_edge)

    return reaches


def build_ruleset_deps(stats, build_table=build_table_deps_incremental,
                       use_bdd=True):
    """ A multi-table implementation of DAG.

        stats: Takes a list of Rule objects
        build_table: Algorithm to build deps for a single table, default incremental
        use_bdd: Default True, use a BDD for calculations, alternativly use headerspace
        returns: A list of dependencies in the format
                 [(f1, f2), (f1, f3), ...]
    """
    if build_table_deps == build_table_deps_incremental:
        if not use_bdd:
            warnings.warn("Incremental deps only supports BDD, continuing as a BDD")
            use_bdd = True
    _AttachBDD = AttachBDD if use_bdd else nullcontext
    with UniqueRules(), _AttachBDD(stats):
        ruleset_tables = defaultdict(list)
        for rule in stats:
            ruleset_tables[rule.table].append(rule)
        tables = sorted(ruleset_tables)
        input_to_table = defaultdict(set)
        reaches = {}

        # All goto's out of table 1
        for stat in ruleset_tables[0]:
            if stat.instructions.goto_table is not None:
                input_to_table[stat.instructions.goto_table].add(stat)

        # Now lets walk the remaining tables in order
        for table in tables:
            # Find the deps within a table
            table_reaches = build_table(ruleset_tables[table], use_bdd=use_bdd)
            # Use every goto with every rule in the table
            for stat in input_to_table[table]:
                if use_bdd:
                    add_parents_bdd(stat, ruleset_tables[table], reaches)
                else:
                    add_parents_hs(stat, ruleset_tables[table], reaches)
                for nstat in (x[1] for x in reaches if x[1].table == table):
                    if nstat.instructions.goto_table is not None:
                        input_to_table[nstat.instructions.goto_table].add(nstat)
            reaches.update(table_reaches)
            input_to_table[table] = set()

        for x in input_to_table:
            # Something went backwards
            assert len(input_to_table[x]) == 0
    return list(reaches)
