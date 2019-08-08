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
from itertools import groupby
from six import viewitems, viewvalues

from .rule import MergeException, Rule, UniqueRules
from .headerspace import get_wildcard_mask
from . import ruleset_deps_indirect
from . import ruleset_deps_direct

# The MAX_PRIORITY rule in OpenFlow
MAX_PRIORITY = 2**16


def sort_key_ruleset_priority(rule):
    """ Sort key for a ruleset

        From highest priority rule first table to lowest priority last table.
    """
    return (rule.table, -rule.priority)


def sort_ruleset(ruleset):
    """ Returns a ruleset sorted from highest priority to lowest

        Sorts from highest to lowest priority first table to last
        return: A new sorted ruleset
    """
    return sorted(ruleset, key=sort_key_ruleset_priority)


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
        openflow: Remain OpenFlow compatible, if not throw
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
        condensed = single_table_condense(condensed, next_table, next_num,
                                          openflow)
    return condensed


def to_single_table(ruleset, openflow=True):
    """ Convert a ruleset to an equivalent single table

        Path is attached to all rules and records the original rules
        combined to create the single table rule.

        ruleset: A list of Rules
        openflow: Remain OpenFlow compatible, if not throw
                  a MergeException. Default True
        return: A single table representation
    """
    scale_ruleset(ruleset)
    return to_single_table_scaled(ruleset, openflow)

def node_to_tree(dep_list, nodes):
    """ Takes a dependency list and adds children and parents to each
        dep_list: A list of all dependencies such as output from
                  build_ruleset_deps
        nodes: A list of all nodes
        return None (nodes are modified)
    """
    for node in nodes:
        node.parents = []
        node.children = []
    for parent, child in dep_list:
        parent.children.append(child)
        child.parents.append(parent)


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
            key = sort_key_ruleset_priority
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


def create_similar_groups(ruleset, groups=None, rule2group=None,
                          deps=None):
    """ Creates groupings of similar rules ready for select_compressed_ruleset

        For more details see compress_ruleset

        ruleset: The ruleset to group
        groups: A dict, if included filled in-place
        rule2group: A dict, if included filled in-place
        deps: Optional, precomputed dependencies
        return: (groups, rule2group)
    """
    def _get_similar_tuple(flow):
        """ Returns a tuple, to match similar looking rules """
        actions = set()
        if flow.instructions.write_actions:
            actions.update([flow.instructions.write_actions.to_type(k)
                            for k in flow.instructions.write_actions])
        if flow.instructions.apply_actions:
            actions.update([flow.instructions.apply_actions.to_type(k)
                            for k in flow.instructions.apply_actions])
        actions = tuple(sorted(actions, key=str))
        goto = (flow.instructions.goto_table if
                flow.instructions.goto_table is not None else 0)
        return (flow.table, -flow.priority,
                get_wildcard_mask(flow.match.get_wildcard()),
                goto, actions
               )

    def _get_p_and_c(flow):
        # Arrg never use ID, cannot reproduce issues half the time
        return (tuple(sorted([x._u_id for x in flow.parents])),
                tuple(sorted([x._u_id for x in flow.children])))

    if groups is None:
        groups = {}
    if rule2group is None:
        rule2group = {}

    if deps is None:
        deps = ruleset_deps_indirect.build_ruleset_deps(ruleset)
    # Tag each with children etc.
    node_to_tree(deps, ruleset)
    # Add a unique sorting ID
    for i, rule in enumerate(ruleset):
        rule._u_id = i

    # Compression groups
    # Simply group by each of this
    rules_sorted = sorted(ruleset, key=_get_similar_tuple)
    for _, itr in groupby(rules_sorted, _get_similar_tuple):
        rules_grouped = sorted(itr, key=_get_p_and_c)
        groups[rules_grouped[0]] = rules_grouped

    # Try figure dependencies
    for group, rules in viewitems(groups):
        for rule in rules:
            rule2group[rule] = group

    # Keep splitting groups while a difference in dependencies exists
    while True:
        for group, rules in viewitems(groups):
            if len(rules) == 1:
                continue
            new_groups = defaultdict(list)
            for rule in rules:
                p_set = frozenset([rule2group[parent] for parent in rule.parents])
                c_set = frozenset([rule2group[child] for child in rule.children])
                new_groups[(p_set, c_set)].append(rule)
            if len(new_groups) > 1:
                # Replace the original group and recheck
                del groups[group]
                for new_rules in viewvalues(new_groups):
                    groups[new_rules[0]] = new_rules
                    for new_rule in new_rules:
                        rule2group[new_rule] = new_rules[0]
                break
        else:
            break

    return (groups, rule2group)

def _allowed_options(groups, rule2group, assigned, group):
    res = set()
    rule_options = groups[rule2group[group]]
    for option in rule_options:
        expected, overlap = _check_option_full(rule2group, assigned, option)
        # Check if all child dependencies of this option have been selected
        if expected == overlap:
            res.add(option)
    return res

def _check_option_full(rule2group, assigned, rule):
    """ Check if a rule has all the required dependencies with assigned rules

        Vs. check_option_children, this checks all assigned groups
    """
    deps = set(rule.children + rule.parents)
    overlap = deps.intersection(assigned)
    expected = {rule2group[dep] for dep in deps}.intersection(assigned)
    return expected, overlap

def _check_option(rule2group, assigned, rule):
    """ Check if a rule has all the required dependencies with assigned children

        Assumes that all children rules have been assigned, and only children
    """
    children = set(rule.children)
    overlap = children.intersection(assigned)
    # NOTE: Building 'expected' like this seems excessive, but, is
    # required.
    # A simple overlap == children, or length check fails because
    # an option might have multiple deps to rules in the same group. So
    # this checks that one child from each group has been selected.
    expected = {rule2group[child] for child in children}
    return expected, overlap

def _switch_assigned(groups, rule2group, assigned, new_assigned):
    """ Make or change the assignment from a group """
    old_assigned = rule2group[new_assigned]
    if old_assigned != new_assigned:
        rule_options = groups[old_assigned]
        # We selected option, and update the mapping
        for rule in rule_options:
            rule2group[rule] = new_assigned
        # Get index and move it to front of the list
        index = rule_options.index(new_assigned)
        assert index > 0
        rule_options[0], rule_options[index] = (
            rule_options[index], rule_options[0])
        del groups[old_assigned]
        groups[new_assigned] = rule_options
        if old_assigned in assigned:  # Updated the selected assignment
            assigned.remove(old_assigned)
            assigned.add(new_assigned)


def select_compressed_ruleset(ruleset, groups, rule2group):
    """ Select the compressed rules, with create_similar_groups()'s output

        For more details see compress_ruleset

        ruleset: The original ruleset
        groups: From create_similar_groups
        rule2group: From create_similar_groups
        return: A compressed ruleset
    """
    # In order we traverse and pick rules such that we keep dependencies
    # Work from the bottom up, as following back paths will add the most
    # restrictions
    unassigned_groups = sort_ruleset(groups)

    # Begin by assigning the default in the final table
    assigned = set((unassigned_groups.pop(),))

    # Pick a rule such that its children are fully included in the
    # rules already assigned. Reverse order seems to work best.
    while unassigned_groups:
        assigning = unassigned_groups.pop()
        rule_options = groups[assigning]
        for option in rule_options:
            expected, overlap = _check_option(rule2group, assigned, option)
            if expected == overlap:
                _switch_assigned(groups, rule2group, assigned, option)
                assigning = option
                break
        else:
            # No single rule fulfils all dependency requirements

            # See if an easy solution exists by changing some assigned rules
            # This only checks one level, changing the directly dependent groups
            differences = {}
            # Calculate which assigned groups might need to be changed
            for opt in rule_options:
                exp, over = _check_option_full(rule2group, assigned, opt)
                differences[opt] = exp - over

            # Start by considering the option requiring the fewest changes
            best_diff = sorted(differences, key=lambda x: len(differences[x]))
            for diff in best_diff:
                # Can we pick a valid rule from all assigned groups
                for rule in differences[diff]:
                    allows = _allowed_options(groups, rule2group, assigned, rule)
                    if not allows.intersection(set(diff.children)):
                        break
                else:
                    # Yes we can move all rules, so lets do it
                    # There is still a chance that in moving one breaks moving
                    # another. But, seems unlikely
                    for rule in differences[diff]:
                        candidates = _allowed_options(groups, rule2group, assigned, rule)
                        candidates = list(candidates.intersection(set(diff.children)))
                        _switch_assigned(groups, rule2group, assigned, candidates[0])
                    assert diff in _allowed_options(groups, rule2group, assigned, diff)
                    _switch_assigned(groups, rule2group, assigned, diff)
                    assigning = diff
                    break
                continue
            else:
                # Could not shift rules around
                # TODO, fail gracefully or add better logic here
                from trepan.api import debug
                debug()

        assigned.add(assigning)

    return sort_ruleset(assigned)


def compress_ruleset(ruleset, deps=None):
    """ Creates a compressed ruleset which represents the original.

        Minimises a ruleset by removing similar rules, yet maintaining
        the complexity between rules. This aims to remain representative
        of the original ruleset.

        The idea is to try fit this much smaller ruleset to a new pipeline
        and then apply the same placements to all rules.

        The key to maintaining the original complexity is ensuring the all
        dependencies between groups of similar rules remain in the compressed
        ruleset.

        We are very restrictive about what 'similar' rules are:
        * Same priority and table
        * Same match mask (can be different values)
        * Same actions (can be different values but same primitives)
        * Same parents and children


        ruleset: The input ruleset
        deps: Optional list of precomputed dependencies for the ruleset
        return: (Minimised ruleset, mapping to similar rules). The mapping is
                from the selected rule in the compressed ruleset to all
                'similar' rules.
    """
    # Rule -> tuple(Rules)
    groups = {}
    rule2group = {}

    with UniqueRules(groups):
        create_similar_groups(ruleset, deps=deps, groups=groups,
                              rule2group=rule2group)
        select_compressed_ruleset(ruleset, groups=groups,
                                  rule2group=rule2group)

    # Now pick rules which have the deps
    new_ruleset = sort_ruleset(groups)
    return (new_ruleset, groups)
