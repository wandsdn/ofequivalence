"""
Methods for working with OpenFlow 1.3 rulesets.
A ruleset is a list
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
from collections import defaultdict
from .rule import MergeException, Rule
from .headerspace import headerspace

# The MAX_PRIORITY rule in openflow
MAX_PRIORITY = 2**16

def sort_ruleset(ruleset):
    """ Returns a ruleset sorted from highest priority to lowest

        Sorts from highest to lowest priority first table to last
        return: A new sorted ruleset
    """
    return sorted(ruleset, key=lambda rule: (rule.table, -rule.priority))


def single_table_condense(first, second, second_num, openflow=True):
    """ Condense the first and right tables into a single table.
        This is a shortened version of the multitable to single
        table algorithm.

        If the input is priority ordered the result returned will be also.

        first: The first table ruleset
        second: The second table ruleset
        second_num: The table number of the second
        openflow: Remain openflow compatible, if not throw
                  a MergeException. Default True
        return: A list of rules
    """
    res = []
    for first_rule in first:
        # Are we going to the next table, if so lets see what rules we hit
        # For now don't try track overlapping rules, simply check the merge
        # between tables

        if first_rule.instructions.goto_table == second_num:
            for second_rule in second:
                try:
                    res.append(first_rule.merge(second_rule, openflow))
                    # Store the original path for later use
                    res[-1].path = first_rule.path
                    res[-1].path += second_rule.path
                except MergeException:
                    pass

        else:
            # Does not go to the next table, copy as is
            res.append(first_rule.copy())
            res[-1].path = first_rule.path

    # Debug
    if False:
        print("First Table", len(first))
        for rule in first:
            print(rule)

        print("Right Table", len(second))
        for rule in second:
            print(rule)

        print("Merged Table", len(res))
        for rule in res:
            print(rule)
    return res


def scale_ruleset(ruleset):
    """ Scale the priorities of a ruleset in-place

        Scale priorities such that the result of merging rules is correct by
        simply adding together priorities.
        Rules in the first tables are scaled up such that all priorities in
        subsequent tables can fit between two rules.

        Note: The priorities returned are larger than the priorities supported
              by OpenFlow

        ruleset: A ruleset, can be unsorted
        return: ruleset
    """
    tables = sorted({x.table for x in ruleset})
    table_to_power = dict(zip(tables, range(len(tables) - 1, -1, -1)))
    for rule in ruleset:
        assert rule.priority < MAX_PRIORITY
        rule.priority *= MAX_PRIORITY ** table_to_power[rule.table]
    return ruleset


def to_single_table_scaled(ruleset, openflow=True):
    """ Convert a pre-scaled ruleset to an equivalent single table

        Path is attached to all rules and records the original rules
        combined to create the single table rule.

        ruleset: A list of Rules, pre-scaled by scale_ruleset()
        openflow: Remain openflow compatible, if not throw
                  a MergeException. Default True
        return: A single table representation
    """
    tables = sorted({x.table for x in ruleset})
    assert 0 in tables
    for rule in ruleset:
        if not rule.path:
            rule.path = (rule,)
    # Fill in any missing default rules
    for table in tables:
        for rule in ruleset:
            if rule.priority == 0 and rule.table == table:
                break
        else:
            ruleset.append(Rule(priority=0, table=table))
            ruleset[-1].path = (ruleset[-1],)

    condensed = sorted([x for x in ruleset if x.table == tables[0]],
                       key=lambda x: -x.priority)

    for next_num in tables[1:]:
        next_table = sorted([x for x in ruleset if x.table == next_num],
                            key=lambda x: -x.priority)
        condensed = single_table_condense(condensed, next_table, next_num, openflow)
    return condensed


def to_single_table(ruleset, openflow=True):
    """ Convert a ruleset to an equivalent single table

        Path is attached to all rules and records the original rules
        combined to create the single table rule.

        ruleset: A list of Rules
        openflow: Remain openflow compatible, if not throw
                  a MergeException. Default True
        return: A single table representation
    """
    scale_ruleset(ruleset)
    return to_single_table_scaled(ruleset)


DO_LAZY = True

# Offline algorithm 1 for building dependency graph
# Finding direct dependencies: Ri (child) is a dependency of Rj (parent)
# iff Ri is removed packets that should hit Ri will instead hit Rj

def get_header_space(rule):
    wc = rule.match.get_wildcard()
    hs = headerspace()
    hs.add_hs(wc)
    return hs

def add_parents(R, P):
    deps = []
    reaches = {}

    packets = get_header_space(R)
    P.sort(key=lambda x: -x.priority)  # descending
    for Rj in P:
        Rj_hs = get_header_space(Rj)
        intersection = packets.copy_intersect(Rj_hs)
        intersection.clean_up()
        if not intersection.is_empty():
            deps.append((R, Rj))
            reaches[(R, Rj)] = intersection
            # gotos = deps.append((R, Rj))
            if DO_LAZY:
                assert len(Rj_hs.hs_list) == 1 and not Rj_hs.hs_diff[0]
                packets.diff_hs(Rj_hs.hs_list[0])
            else:
                packets.minus(Rj_hs)
    return deps, reaches


def build_DAG(ruleset):
    """
    Based on CacheFlow (2016), algorithm 1
    ruleset: Takes a list of Rule objects
    """
    res = []
    reaches = {}
    for R in ruleset:
        potential_parents = [Rj for Rj in ruleset
                            if Rj.priority < R.priority or Rj.table > R.table]
        deps, reach = add_parents(R, potential_parents)
        res += deps
        reaches.update(reach)
    return res, reaches


def cross_tables_DAG(stats):
    """ A multi-table implementation of DAG.
        stats: Takes a list of Rule objects
        returns: A list of dependencies in the format
                 [(f1, f2), (f1, f3), ...]
    """
    tables = set([x.table for x in stats if x.table != 0])
    tables = sorted(tables)
    res = []
    input_to_table = defaultdict(set)
    reaches = {}

    # Do table 0, all packets hit this
    table_zero = [stat for stat in stats if stat.table == 0]
    deps, reach = build_DAG(table_zero)
    res += deps
    reaches.update(reach)

    # Now with all those rules figure out the gotos
    for stat in table_zero:
        if stat.instructions.goto_table is not None:
            input_to_table[stat.instructions.goto_table].add(stat)

    # Now lets walk the remaining tables in order
    for table in tables:
        table_rules = [stat for stat in stats if stat.table == table]
        # Use every goto with every rule in the table
        for stat in input_to_table[table]:
            deps, reach = add_parents(stat, table_rules)
            res += deps
            reaches.update(reach)
            for nstat in [x[1] for x in deps]:
                if nstat.instructions.goto_table is not None:
                    input_to_table[nstat.instructions.goto_table].add(nstat)
        # Also do deps within the table
        deps, reach = build_DAG(table_rules)
        res += deps
        reaches.update(reach)
        input_to_table[table] = set()

    for x in input_to_table:
        # Something went backwards
        assert len(input_to_table[x]) == 0
    return res


def node_to_tree(dep_list, nodes):
    """ Takes a dependency list and adds children and parents to each
        dep_list: A list of all dependencies such as output from
                  cross_tables_DAG
        nodes: A list of all nodes
        return None (nodes are modified)
    """
    for node in nodes:
        node.parents = []
        node.children = []
    for parent, child in dep_list:
        parent.children.append(child)
        child.parents.append(parent)
    return


def simplify_tree(nodes):
    """ Remove links where a parent is listed already by a parent
        nodes: The nodes
        return None, this works in place
    """
    for node in nodes:
        parents_parents = set()

        def get_parents(node):
            ret = set(node.parents)
            for parent in node.parents:
                ret.update(get_parents(parent))
            return ret

        for parent in node.parents:
            parents_parents.update(get_parents(parent))

        my_parents = set(node.parents)
        for item in my_parents.intersection(parents_parents):
            item.children.remove(node)
            node.parents.remove(item)

# By the definition a dep exists if removing the parent will change the
# traffic hitting the rule x.
# So we should we make a dep between rules that overlap with the next table
# And then remove the overlapping portion
# TODO we should also apply actions before this


def directed_layout(G, scale=1.0, push_down=True, cluster=True,
                    separate_tables=True, key=None):
    """ Create a directed layout from top to bottom, in 2D.

        This layout ensures that all children are placed on lower levels
        than their parents.

        G: The NetworkX graph - nodes are expected to contain the table
           attribute if separate table is set.
        scale: The nodes are positioned with a box of size [0,scale]
               x [0, scale]
        push_down: If True, nodes are placed at the lowest possible point in
                   the graph, i.e. directly above their closest parent.
                   Otherwise they are placed at the highest position
                   possible within the graph.
        cluster: Apply a very simple clustering algorithm to try and group
                 nodes with the same destination close to each other and
                 close to their descendants.
        separate_tables: Tables will be on a lower level then earlier tables
        key: How to sort rules from high to low priority, by default we assume
             Flows are being used.
    """
    def _layout(nodes, key):
        levels = []
        if key is None:
            key = lambda n: -n.priority + 100000 * n.table
        for x in sorted(nodes, key=key):
            edges_in = [e[0] for e in G.edges() if e[1] == x]
            next_level = -1
            # We find the level at which we can place this
            # on level below its lowest parent
            for l in range(0, len(levels)):
                for n in levels[l]:
                    if n in edges_in:
                        next_level = l
            next_level += 1
            if len(levels) <= next_level:
                levels.append([])
            levels[next_level].append(x)

        # Now push down any which do not have anything under them, starting at
        # the bottom and working up
        # We find that the top row is normally the largest, so we move down
        # those with no connections
        if push_down:
            for l in reversed(range(0, len(levels)-1)):
                n = 0
                while n < len(levels[l]):
                    for to in [e[1] for e in G.edges()
                               if e[0] == levels[l][n]]:
                        if to in levels[l+1]:
                            n += 1
                            break
                    else:
                        # move down
                        levels[l+1].append(levels[l][n])
                        del levels[l][n]

        # Try to cluster
        # sort such that the line below is about right
        # the final level is in fixed positions
        # The level above is sorted left to right depending upon deps on the
        # final
        if cluster:
            for i in reversed(range(0, len(levels)-1)):
                def generate_sort_level(x):
                    m = 99999999999999
                    for to in [e[1] for e in G.edges() if e[0] == x]:
                        if to in levels[i+1]:
                            m = min(m, levels[i+1].index(to))
                    return m
                levels[i].sort(key=generate_sort_level)
        return levels

    levels = []
    if separate_tables:
        tables = set([G.node[x]['table'] for x in G.nodes()])
        for table in sorted(tables):
            table_nodes = [x for x in G.nodes() if G.node[x]['table'] == table]
            levels += _layout(table_nodes, key)
    else:
        levels = _layout(G.nodes(), key)

    positions = {}
    for l in range(0, len(levels)):
        y = 1.0 - (1.0 / float(len(levels))) * (l + 0.5)
        l = levels[l]
        for n in range(0, len(l)):
            x = (1.0 / float(len(l))) * (n + 0.5)
            n = l[n]
            positions[n] = (x*scale, y*scale)

    return positions
