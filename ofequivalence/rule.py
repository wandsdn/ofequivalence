"""
Our representation of OpenFlow 1.3 forwarding rules in a match+action pipeline.

We refer to an OpenFlow Flow as a Rule.
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
import bisect
from six import string_types, viewitems

from . import headerspace
from .headerspace import (wildcard_is_subset, wildcard_intersect)
from .openflow_desc import OpenFlow1_3_5

# A global copy of OpenFlow
G_OF = OpenFlow1_3_5()


class MergeException(Exception):
    """ The internal representation cannot represent these rules merged.

        This occurs if a label is popped in the first rule, and the second
        tries to match the on the inner label.
    """
    def __init__(self, first, second):
        super(MergeException, self).__init__()
        self.first = first
        self.second = second

    def __str__(self):
        return "Cannot merge {}\nwith:\n{}".format(self.first, self.second)


class MergeExceptionNoOverlap(MergeException):
    """ Two rules cannot be merged because their matches don't overlap """
    def __str__(self):
        return "Cannot merge {}\nwith:\n{} - no overlap".format(
            self.first, self.second)


def demote_match(match, field, num=1):
    """ Increases a field match by num, thus matching a inner field

        e.g. VLAN_VID -> VLAN_VID(num)
             VLAN_VID2 -> VLAN_VID(2+num)

        match: The Match to demote inplace
        field: The base field to demote
        num: The depth to demote by
    """
    if num == 0:
        return
    # Find all variations of the base field
    fmatch = list(filter(lambda x: x.startswith(field), match))
    fmatch.sort(reverse=True)
    for _field in fmatch:
        if _field != field:
            depth = int(_field[len(field):]) + num
            if depth > G_OF.HEADER_DEPTH:
                raise OverflowError("Cannot demote field," +
                                    " increase HEADER_DEPTH to " + str(depth))
            match.append(field + str(depth), *match[_field][:2])
            del match[_field]
        else:
            if num > G_OF.HEADER_DEPTH:
                raise OverflowError("Cannot demote field," +
                                    " increase HEADER_DEPTH to " + str(depth))
            match.append(field + str(num), *match[_field][:2])
            del match[_field]


def promote_match(match, field, num=1):
    """ Decreases a field match by num, thus matching an outer field
        e.g. VLAN_VID -> Exception
             VLAN_VID2 -> VLAN_VID(2-num)
        match: The Match to promote inplace
        field: The base field to promote
        num: The depth to promote by
    """
    if num == 0:
        return
    fmatch = list(filter(lambda x: x.startswith(field), match))
    for _field in fmatch:
        if _field != field:
            depth = int(_field[len(field):]) - num
            if depth > 0:
                match.append(field + str(depth), *match[_field][:2])
                del match[_field]
            elif depth == 0:
                match.append(field, *match[_field][:2])
                del match[_field]
            else:
                raise OverflowError("Cannot promote field below zero")
        else:
            raise OverflowError("Cannot promote field below zero")


class Rule(object):
    """
    A standard format for representing forwarding rules internally
    """
    priority = None
    cookie = None
    match = None
    instructions = None
    table = None
    ttp_link = None
    path = ()  # Store the original path, i.e the originally merged rules

    def __init__(self, dup=None, priority=None, cookie=None, match=None,
                 instructions=None, table=None, ttp_link=None, path=None):
        object.__init__(self)
        if dup is not None:
            self.priority = dup.priority
            self.cookie = dup.cookie
            self.match = Match(dup.match)
            self.instructions = Instructions(dup.instructions)
            self.table = dup.table
            self.ttp_link = dup.ttp_link
            self.path = dup.path
        else:
            self.instructions = Instructions()
            self.match = Match()
        if priority is not None:
            self.priority = priority
        if cookie is not None:
            self.cookie = cookie
        if match is not None:
            self.match = match
        if instructions is not None:
            self.instructions = instructions
        if table is not None:
            self.table = table
        if ttp_link is not None:
            self.ttp_link = ttp_link
        if path is not None:
            self.path = path

    def get_goto_set_fields(self):
        """ Returns the fields with their values set by apply_actions

            This is expected to be used to find the values changed before
            a goto operation to the next table.

            return: A list of tuples in the form [(field, value),...]
        """
        # Use a dict to ensure only the last field set is maintained
        # if set more than once only the latest applies
        set_fields = {}
        for x in self.instructions.apply_actions:
            if x[0] == 'SET_FIELD':
                set_fields[x[1][0]] = x[1][1]
        return [(k, v) for k, v in viewitems(set_fields)]

    def _get_simulated_egress(self, ingress=None):
        """ Computes the headerspace that packets egressing this rule can have.

            This is based on the match and the write actions
            applied by this rule and may be filtered by providing a ingress
            headerspace.

            ingress: An optional match_set filtering the ingress to this rule
            return: overlapping, rewritten_values, op_count
        """
        if ingress:
            simulated_packet = self.match.intersection(ingress)
        else:
            simulated_packet = self.match.copy()
        # The fields rewritten by SET actions, match on these fields
        # are removed
        rewritten = Match()
        if self.ttp_link:
            OF = self.ttp_link.ttp.OF
        else:
            OF = G_OF

        # Resolve all push pop operations
        pops = OF.tun_pop
        pushes = OF.tun_push
        # Counts of push/pop operations encountered
        op_count = defaultdict(lambda: 0)

        # Loop instructions applying SET_FIELD, PUSH/POP to simulated_packet
        for action in self.instructions.apply_actions:
            if action[0] == "SET_FIELD":
                if action[1][0] == "VLAN_VID":
                    # Special case set VID present bit
                    simulated_packet.append(action[1][0], 0x1000 | action[1][1], None)
                    rewritten.append(action[1][0], 0x1000 | action[1][1], None)
                else:
                    simulated_packet.append(action[1][0], action[1][1], None)
                    rewritten.append(action[1][0], action[1][1], None)
            elif action[0] in pushes:
                tunnel = pushes[action[0]]
                for field in tunnel['fields']:
                    demote_match(simulated_packet, field)
                    demote_match(rewritten, field)
                    # OpenFlow spec says values for a newly pushed field are
                    # set to the value of the existing field if it exists
                    # otherwise 0.
                    # If we know the next inner value we set it to that,
                    # otherwise use 0. XXX this is not 100% correct
                    # as just because we don't know the value doesn't mean
                    # it does not exist, ideally we would express a linked
                    # value.
                    mask_in = 0
                    if field == "VLAN_VID":
                        mask_in = 0x1000
                    if field + "1" in simulated_packet:
                        simulated_packet.append(
                            field, mask_in | simulated_packet[field+"1"][0],
                            None)
                        rewritten.append(
                            field, mask_in | simulated_packet[field+"1"][0],
                            None)
                    else:
                        simulated_packet.append(field, mask_in, None)
                        rewritten.append(field, mask_in, None)
                op_count[action[0]] += 1
            elif action[0] in pops:
                tunnel = pops[action[0]]
                for field in tunnel['fields']:
                    if field in simulated_packet:
                        del simulated_packet[field]
                    if field in rewritten:
                        del rewritten[field]
                    promote_match(simulated_packet, field)
                    promote_match(rewritten, field)
                op_count[action[0]] += 1

        if self.instructions.write_metadata is not None:
            # Combine metadata with ingress
            if "METADATA" not in simulated_packet or self.instructions.write_metadata[1] is None:
                # Not included in match or fully overwritten
                simulated_packet.append("METADATA",
                                        *self.instructions.write_metadata)
            else:
                # Overwrite (m)atch with (w)rite to calc (s)imulated metadata
                m_value, m_mask, _ = simulated_packet["METADATA"]
                w_value, w_mask = self.instructions.write_metadata
                s_value = (w_value & w_mask) | (~w_mask & m_value)
                if m_mask is None:
                    s_mask = None
                else:
                    s_mask = m_mask | w_mask
                simulated_packet.append("METADATA", s_value, s_mask)
            rewritten.append("METADATA", *self.instructions.write_metadata)

        return simulated_packet, rewritten, op_count

    def get_goto_egress(self, ingress=None):
        """ Computes the headerspace that packets leaving this rule
            can have.

            This is based on the match applied and the write actions
            applied.

            ingress: An optional match_set filtering the ingress to this rule
        """
        return self._get_simulated_egress(ingress)[0]

    def egress_overlap(self, other, ingress=None):
        """ Check if there is an overlap between the ingress and egress space
            ingress: An match_set describing the ingress to this rule
        """
        return wildcard_intersect(
            self.get_goto_egress(ingress).get_wildcard(),
            other.match.get_wildcard()) != 0

    def __hash__(self):
        """ Returns a hash which matches __eq__ """
        return hash((self.priority,
                     self.cookie,
                     self.match,
                     self.instructions,
                     self.table))

    def __eq__(self, other):
        """ Returns if equal"""
        return (self.priority == other.priority and
                self.cookie == other.cookie and
                self.match == other.match and
                self.instructions == other.instructions and
                self.table == other.table
                )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return ("Rule(\n\tpriority: %s\n\tcookie: %s\n\tmatch: %s"
                "\n\tinstructions: %s\n\ttable: %s)") % (
                    self.priority, self.cookie, self.match,
                    self.instructions, self.table)

    def __repr__(self):
        return str(self)

    def copy(self):
        """
        Copies the Rule
        """
        return self.__class__(dup=self)

    def merge(self, second, openflow=True):
        """ Return a rule representing this and another Flow merged together.
            Matches are the intersection, i.e. traffic that hits both self
            and second. Instructions are merged following OpenFlow behaviour.
            Priorities are added together. Cookie and table are taken from
            self.

            i.e. The result of merging two flows in different tables will
                 return a single table equivalent.

            self: The first rule
            second: The second rule
            openflow: Remain openflow compatible, if not throw a MergeException
                      Namely matching inner headers is not possible in a
                      single rule.
            return: A new Flow
            exception: Throws a MergeException if the two rules are not
                       mergable. This happens in the case a header is popped
                       and matched in the next rule. MergeExceptionNoOverlap
                       is returned if the rules don't intersect.
        """

        # Merging matches
        # The common intersection (representing the packets that hit both) is
        # the new match set. With one exception, in the case that a field is
        # rewritten - we know that this is a fixed value and we have already
        # checked the match set will match the rewritten value. But because it
        # is rewritten (but not yet on entry to a single rule) we must remove
        # the match for that field on the rightside.

        simulated_packet, rewritten, op_count = self._get_simulated_egress()

        # Check that packets egressing first are accepted by second
        if wildcard_intersect(simulated_packet.get_wildcard(),
                              second.match.get_wildcard()) == 0:
            raise MergeExceptionNoOverlap(self, second)

        # Remove matches on fields which have been rewritten by the second
        remove_fields = [(x,) for x in rewritten if x in second.match and x != "METADATA"]
        second_match = second.match.copy(remove=remove_fields)

        # Each bit of metadata can be set, so consider each bit
        if ('METADATA' in second_match and "METADATA" in rewritten):
            if rewritten["METADATA"][1] is None:
                # The whole field has been set
                del second_match['METADATA']
            else:
                # Unset bits of the right match if they are set
                mm = second_match['METADATA'][1]
                if mm is None:
                    mm = 0xFFFFFFFFFFFFFFFF
                new_mask = mm & ~rewritten["METADATA"][1]
                if new_mask != 0:
                    second_match.append('METADATA', second_match['METADATA'][0] & new_mask,
                                  new_mask)
                else:
                    del second_match['METADATA']

        if self.ttp_link:
            OF = self.ttp_link.ttp.OF
        else:
            OF = G_OF
        # Demote/Promote the second match the packet entering first
        for tunnel in OF.tunnels:
            count = op_count[tunnel["pop"]]-op_count[tunnel["push"]]
            if count > 0:
                for field in tunnel["fields"]:
                    demote_match(second_match, field, count)
            elif count < 0:
                for field in tunnel["fields"]:
                    promote_match(second_match, field, -count)

        match = self.match.intersection(second_match)

        inst = self.instructions + second.instructions
        # Compute the new write_metadata
        if self.instructions.write_metadata is None:
            metadata = second.instructions.write_metadata
        elif second.instructions.write_metadata is None:
            metadata = self.instructions.write_metadata
        else:  # Both set
            m1 = self.instructions.write_metadata
            m2 = second.instructions.write_metadata
            if m2[1] is None:
                metadata = m2
            else:
                metadata = (m1[0] & ~m2[1]) | (m2[0] & m2[1])
                if m1[1] is None:
                    metadata = (metadata, None)
                else:
                    metadata = (metadata, m1[1] | m2[1])
        inst.write_metadata = metadata

        # Check OpenFlow compliance, i.e. doesn't have inner matches
        if openflow:
            for x in match:
                if x[-1].isdigit():
                    raise MergeException(self, second)

        # TODO how to handle cookies

        rule = Rule(match=match, instructions=inst, cookie=self.cookie,
                    priority=self.priority+second.priority, table=self.table)
        return rule

    def __add__(self, second):
        """ Merges two Rules together - See merge() """
        return self.merge(second)


class ActionList(object):
    """
    A standard format used to store an action list.
    Per spec this is a list executed in the provided order.
    """
    ttp_link = None
    orig_order = None  # We keep the original so the removal is correct
    action_levels = None  # A list of lists ordered by dependency and sorted
                          # at each dependency level
    binding = ()
    _hash = None
    _per_output_actions = None
    _per_output_actions_pt = None

    def __init__(self, dup=None):
        object.__init__(self)
        if dup is not None:
            if isinstance(dup, ActionList):
                self.action_levels = [x[:] for x in dup.action_levels]
                self.orig_order = dup.orig_order[:]
                self.ttp_link = dup.ttp_link
                self.binding = dup.binding
                self._per_output_actions = dup._per_output_actions
                self._per_output_actions_pt = dup._per_output_actions_pt
                self._hash = dup._hash
            else:
                self.action_levels = []
                self.orig_order = []
                for x in dup:
                    self.append(*x)
        else:
            self.action_levels = []
            self.orig_order = []

    def invalidate_cache(self):
        self._hash = None
        self._per_output_actions = None
        self._per_output_actions_pt = None

    def _append(self, i):
        """ Append to the ordered structure """
        deepest_dep = -1
        for l in range(len(self.action_levels)):
            v = self.action_levels[l]
            for item in v:
                if self.depends(item, i):
                    deepest_dep = l
        if len(self.action_levels) <= deepest_dep + 1:
            self.action_levels.append([i])
        else:
            bisect.insort(self.action_levels[deepest_dep + 1], i)

    def append(self, type_, value):
        """
        Append to the end of the list a new action of type_ with a given value
        """
        self.invalidate_cache()
        i = (type_, value)
        self._append(i)
        self.orig_order.append(i)

    def __len__(self):
        return len(self.orig_order)

    def __iter__(self):
        for level in self.action_levels:
            for item in level:
                yield item
        return

    def __iadd__(self, other):
        for x in other:
            self.append(*x)
        return self

    def __add__(self, other):
        return self.copy(add=other)

    def __contains__(self, x):
        return x in self.orig_order

    def index(self, x):
        i = 0
        for level in self.action_levels:
            try:
                return i + level.index(x)
            except:
                i += len(level)
        raise ValueError

    def __getitem__(self, x):
        if isinstance(x, slice):
            # Slicing is complex let list do this
            return [i for i in self][x]
        if isinstance(x, int):
            if x >= 0:
                for level in self.action_levels:
                    if x < len(level):
                        return level[x]
                    else:
                        x -= len(level)
            else:
                # Negative offset
                for level in reversed(self.action_levels):
                    if -x <= len(level):
                        return level[x]
                    else:
                        x += len(level)
            raise IndexError
        raise TypeError

    def remove(self, x):
        """ Remove an item """
        self.invalidate_cache()
        offset = 0
        self.orig_order.remove(x)
        for l in range(len(self.action_levels)):
            level = self.action_levels[l]
            if x in level:
                # We remove this level and all past it
                # and then re add these flows
                self.action_levels = self.action_levels[:l]
                for a in self.orig_order[offset:]:
                    self._append(a)
                return
            offset += len(level)
        else:
            assert "Something is wrong internally"
            raise ValueError

    def __hash__(self):
        """ Returns a hash for the current action list
            The hash is based on the actions and their order within
            dependency groups.

            This is matches with the behaviour of __eq__.
        """
        if self._hash is None:
            self._hash = hash(tuple(self))
        return self._hash

    def replace(self, new):
        """ Replace all items with a new iterable ActionList or list """
        # Replace the array
        self.invalidate_cache()
        self.action_levels = []
        self.orig_order = []
        for i in new:
            self.append(*i)

    def _remove_redundant(self):
        """  Find and remove redundant actions

        Used as part of creating a canonical action form.

        Remove redundant actions:
         * SET VLAN_VID, POP_VLAN -> POP_VLAN
         * PUSH POP -> <removed>
         * SET X:1, SET X:2 -> SET X:2

        This function is careful to check for dependencies
        before removing. I.e. SET_VLAN, PUSH VLAN, POP
        cannot remove the SET_VLAN as it is a different VLAN.

        Assumes no OUTPUT actions are in the path

        return: self, redundancies are removed in-place
        """
        if self.ttp_link:
            OF = self.ttp_link.ttp.OF
        else:
            OF = G_OF

        push = OF.tun_push
        pop = OF.tun_pop

        # Remove push + pop pairs
        made_change = True
        new_actions = list(self)
        # As push, pops can be nested we loop until all possible are removed
        while made_change:
            for index, action in enumerate(new_actions):
                if action[0] in push:
                    ctun = push[action[0]]
                    to_remove = [index]
                    for i, act in enumerate(new_actions[index+1:], index+1):
                        if act[0] == action[0]:
                            # We have found a push pop sequence
                            # Resolve the inside first
                            to_remove = []
                            break
                        if act[0] == ctun["pop"]:
                            # OK we can remove
                            to_remove.append(i)
                            break
                        if act[0] == "SET_FIELD":
                            if act[1][0] in ctun["fields"]:
                                # collect for removal
                                to_remove.append(i)
                    else:
                        # Exited loop without finding a pop
                        to_remove = []
                    if to_remove:
                        # Remove and reloop
                        for i in reversed(to_remove):
                            del new_actions[i]
                        break
            else:
                # Fell out of the loop without calling break
                made_change = False

        # Remove case where a set field is pop'd
        # Note: We won't find a PUSH before a POP (already removed)
        fields_popped = set()
        to_remove = []
        for index, action in reversed(list(enumerate(new_actions))):
            if action[0] in pop:
                fields_popped.update(pop[action[0]]["fields"])
            elif action[0] == "SET_FIELD":
                if action[1][0] in fields_popped:
                    to_remove.append(index)
        for i in to_remove:
            del new_actions[i]

        # Remove fields set twice, iff no other dependency between
        to_remove = []
        for index, action in enumerate(new_actions):
            if action[0] != "SET_FIELD":
                continue
            for i, act in enumerate(new_actions[index+1:], index+1):
                if act[0] == "SET_FIELD" and act[1][0] == action[1][0]:
                    to_remove.append(index)
                    break
                if self.depends(action, act):
                    break
        for i in reversed(to_remove):
            del new_actions[i]
        self.replace(new_actions)

        return self

    def per_output_actions(self, pass_through=False):
        """
            pass_through: Default False. If True the key 'pass' is mapped
                          to the actions applied to packets passed through
                          to the next rule, i.e. the goto modifications.
            return: A frozenset() of tuples, (port, (actions, ...)),
                    hashable and suitable for equivalence checking
        """
        if self._per_output_actions is None:
            actions = self._per_output_actions_list()
            actions = {k: tuple(v._remove_redundant()) for k, v in actions.items()}
            self._per_output_actions_pt = frozenset(actions.items())
            del actions["pass"]
            self._per_output_actions = frozenset(actions.items())
        if pass_through:
            return self._per_output_actions_pt
        return self._per_output_actions

    def _per_output_actions_list(self):
        """ return: A port to ActionList mapping of the actions applied,
                     may still include redundancies. Includes the port
                     'pass' which represents to traffic passing through the
                     rule.
        """
        # TODO XXX this assumes that a port is only listed once
        current_state = ActionList()
        res = {}
        for action in self:
            if action[0] == 'OUTPUT':
                res[action[1]] = ActionList(current_state)
                # Finally add the output action
                res[action[1]].append(*action)
            elif action[0] == 'GROUP':
                group_res = {}
                for bucket in action[1].buckets:
                    group_res.update(bucket._per_output_actions_list())
                for k, v in viewitems(group_res):
                    res[k] = current_state + v
            else:
                current_state.append(*action)
        res['pass'] = current_state
        return res

    def equiv_equal(self, other):
        """ Check for forwarding behaviour equivalence
            other: The other part to check
            return: True if equivalent, otherwise False
        """
        return self.per_output_actions() == other.per_output_actions()

    def __eq__(self, other):
        """ A check if the actions performed are the same.
            This checks for equivalent orderings of rules,
            however will not detect unreachable, indirect groups vs. output
            actions or other equivalences matching a output rule etc.

            For this purpose use equiv_equal.
        """
        if len(self) != len(other):
            return False
        # TODO perf tuple and check?
        return tuple(self) == tuple(other)
        for a, b in zip(self, other):
            if a != b:
                return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_type(self, item):
        return item[0] if item[0] != "SET_FIELD" else (item[0], item[1][0])

    def depends(self, item1, item2):
        """ Returns true if the given instructions
            order cannot be swapped in the instruction list
        """
        type1 = self.to_type(item1)
        type2 = self.to_type(item2)
        if self.ttp_link:
            deps1 = self.ttp_link.ttp.OF.action_dependancies[type1]
            deps2 = self.ttp_link.ttp.OF.action_dependancies[type2]
        else:
            deps1 = G_OF.action_dependancies[type1]
            deps2 = G_OF.action_dependancies[type2]
        # Don't forget to check SET_FIELD
        if ((item1[0] == "SET_FIELD" and "SET_FIELD" in deps2) or
                (item2[0] == "SET_FIELD" and "SET_FIELD" in deps1)):
            return True
        return type1 in deps2 or type2 in deps1

    def __do_sort(self, orig):
        """ Obsolete function this is now done on insertion

        This is an ordered topological sort.
        We add everything to a dependency level
        And then sort within the levels and print these
        in level order.
        """
        levels = []  # A list of lists
        for i in orig:
            deepest_dep = -1
            for l in range(len(levels)):
                v = levels[l]
                for item in v:
                    if self.depends(item, i):
                        deepest_dep = max(deepest_dep, l)
            if len(levels) <= deepest_dep + 1:
                levels.append([])
            levels[deepest_dep + 1].append(i)

        ret = []
        for l in levels:
            l.sort()
            ret += l
        return ret

    def empty(self):
        """ Check if the actions are empty
        """
        return len(self) == 0

    def copy(self, add=[], remove=[]):
        """
        Copies the ActionList.
        add: Add the specified elements to the copy
        remove: An iterable list of elements to remove

        In both cases elements take the form (key, value)
        """
        # It is much better to rebuild from scratch, when removing many items
        remove = list(remove)
        if len(remove) > 1:
            new_actions = self.orig_order[:]

            # list.remove() removes the first matching item
            for r in remove:
                new_actions.remove(r)

            cpy = self.__class__(dup=new_actions+list(add))
            cpy.ttp_link = self.ttp_link
            cpy.binding = self.binding
            return cpy

        cpy = self.__class__(dup=self)
        for r in remove:  # Will iterate at most once
            cpy.remove(r)
        for a in add:
            cpy.append(*a)
        return cpy

    def __str__(self):
        return "[" + ",".join([str(x) for x in self]) + "]"


class ActionSet(ActionList):

    def append(self, type_, value):
        """
        Append to the end of the list a new action of type_ with a given value
        """
        self.invalidate_cache()
        rem = None
        for x in self:
            if type_ == x[0]:
                if type_ == 'SET_FIELD':
                    # Set fields are special we must ensure the field is the same
                    if value[0] == x[1][0]:
                        rem = x
                        break
                else:
                    rem = x
                    break
            # GROUP takes priority over OUTPUT and replaces it
            elif type_ == "GROUP" and x[0] == "OUTPUT":
                rem = x
                break
            elif type_ == "OUTPUT" and x[0] == "GROUP":
                return

        if rem:
            # print("Action Set: Replacing item ", rem, "with", (type_, value))
            item = (type_, value)
            self.orig_order[self.orig_order.index(rem)] = item
            for level in self.action_levels:
                try:
                    level[level.index(rem)] = item
                    break
                except:
                    pass
            else:
                assert not "Bug found in ActionSet"
        else:
            # A bit slow but we remove, sort and re-compute
            self.orig_order.append((type_, value))
            self.action_levels = []
            if self.ttp_link:
                self.orig_order.sort(key=lambda x:
                    self.ttp_link.ttp.OF.action_set_order.index(x[0]))
            else:
                self.orig_order.sort(key=lambda x:
                    G_OF.action_set_order.index(x[0]))
            for x in self.orig_order:
                self._append(x)
            assert len(self.orig_order) == len(self)


class Instructions(object):
    """
    A standard format used to store the instructions in a flow.
    Per of spec only one instance of each instruction type should
    be defined
    """
    goto_table = None  # An integer
    apply_actions = None  # ActionList
    write_actions = None  # ActionSet
    write_metadata = None  # (metadata, mask)
    clear_actions = None  # Set to True or None
    meter = None  # TBD TODO XXX TBA
    ttp_link = None
    binding = ()  # A list of bindings to the TTP instructions accepted

    def __init__(self, dup=None):
        object.__init__(self)
        if dup is not None:
            self.goto_table = dup.goto_table
            self.apply_actions = ActionList(dup.apply_actions)
            self.write_actions = ActionSet(dup.write_actions)
            self.write_metadata = dup.write_metadata
            self.meter = dup.meter
            self.clear_actions = dup.clear_actions
            self.binding = dup.binding
            self.ttp_link = dup.ttp_link
        else:
            self.apply_actions = ActionList()
            self.write_actions = ActionSet()

    # TODO MAKE HASHABLE IN A BETTER MANNER
    def __hash__(self):
        return 0

    def __eq__(self, other):
        if isinstance(other, Instructions):
            # Order from fast to slow (i.e. compare built-ins first)
            return (self.goto_table == other.goto_table and
                    self.write_metadata == other.write_metadata and
                    self.clear_actions == other.clear_actions and
                    self.apply_actions == other.apply_actions and
                    self.write_actions == other.write_actions and
                    self.meter == other.meter)
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def empty(self):
        return (self.goto_table is None and
                self.apply_actions.empty() and
                self.write_actions.empty() and
                self.write_metadata is None and
                self.clear_actions is None and
                self.meter is None)

    def __str__(self):
        ret = []
        if self.goto_table is not None:
            ret.append("goto_table=" + str(self.goto_table))
        if self.apply_actions:
            ret.append("apply_actions=" + str(self.apply_actions))
        if self.write_actions:
            ret.append("write_actions=" + str(self.write_actions))
        if self.write_metadata is not None:
            ret.append("write_metadata=" + str(self.write_metadata))
        if self.clear_actions is not None:
            ret.append("clear_actions")
        if self.meter is not None:
            ret.append("meter=" + str(self.meter))

        return "Instructions[" + ",".join(ret) + "]"

    def __repr__(self):
        return str(self)

    def full_actions(self):
        """ Returns a ActionList of both apply and write actions """
        return self.apply_actions + self.write_actions

    def canonical(self):
        """ Return a canonical representation of this instruction

            The returned value will equal another in terms of overall forwarding
            if, in all cases, this set of instructions is equivalent to the
            other, including when merged with any other instruction.

            This flattens groups and redundancies out of actions.
            But, considers differences in apply and write actions, and
            the next table, meter etc.

            return: A hashable tuple, do not assume anything about the contents
        """
        apply_inst = self.apply_actions.per_output_actions(pass_through=True)
        write_inst = self.write_actions.per_output_actions(pass_through=True)

        return (self.clear_actions, self.goto_table, self.meter,
                self.write_metadata, apply_inst, write_inst)

    def merge(self, r):
        """ Merge two instructions together (write and apply actions)
            self: The lefthand instructions
            r: The righthand instructions (later in the pipeline)

            This accounts for clear actions etc. in order self, r
        """
        inst = Instructions()

        # Merge action set, checking if actions are cleared by r
        action_set = None
        if r.clear_actions:
            action_set = r.write_actions.copy()
        else:
            action_set = (self.write_actions +
                          r.write_actions)
        inst.write_actions = action_set

        # Merge the actions
        action_apply = self.apply_actions + r.apply_actions
        inst.apply_actions = action_apply

        # Make sure we continue after the right side
        inst.goto_table = r.goto_table
        # Keep the clear actions from either side, in case instructions are
        # added out of table order
        inst.clear_actions = self.clear_actions or r.clear_actions
        return inst

    def __add__(self, r):
        """ Merges two instructions together - See merge() """
        return self.merge(r)


class Bucket(ActionSet):
    """ A group bucket.

        This is a rebranded action set.
        Changes in OpenFlow 1.4:
        Clarify that actions in a buckets always apply as an action-set
        (EXT-408).
    """


class Group(object):
    """
    A OpenFlow group, including a list of buckets stored as a tuple.
    """
    type_ = None
    number = None
    buckets = None
    ttp_link = None
    _hash = None

    def __init__(self, dup=None):
        if dup is not None:
            self.type_ = dup.type_
            self.numer = dup.number
            self.buckets = dup.buckets
            self.ttp_link = dup.ttp_link
            self._hash = dup._hash
        else:
            self.buckets = tuple()

    def __eq__(self, other):
        if isinstance(other, Group):
            return self.type_ == other.type_ and self.buckets == other.buckets
        return False

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.type_, tuple(self.buckets)))
        return self._hash

    def __ne__(self, other):
        return not self.__eq__(other)

    def empty(self):
        return len(self.buckets) == 0

    def __str__(self):
        return "Group-" + str(self.type_) + " Buckets(" + str([
            str(x) for x in self.buckets]) + ")"

    def __repr__(self):
        return str(self)


class Match(dict):
    """
    A standard format used to store a rule's match.

    This is compatible with sets in a specialised manner
    any match with the same fields included is equivalent.
    This also means equals only checks the fields set not
    their values.
    This is for an internal use.
    """
    required_mask = 0  # A bitmask of required fields, for quick comparison
    ttp_link = None
    _wildcard = None
    binding = ()

    def __init__(self, dup=None):
        """
            Provide value as a long, mask as a long or None(exact match).
            The field_name should be the string 'IN_PORT' etc.
        """
        if dup is not None:
            if isinstance(dup, Match):
                dict.__init__(self, dup)
                self.required_mask = dup.required_mask
                self.binding = dup.binding
                self._wildcard = dup._wildcard
                self.ttp_link = dup.ttp_link
            else:
                dict.__init__(self)
                for x in dup:
                    self.append(*x)
        else:
            dict.__init__(self)

    def intersection(self, other):
        """ Returns a new Match representing the packetspace that
            both satisfy.
            other: Another Match
            Like python's set objects this can be accessed using '&'
        """
        wc = wildcard_intersect(self.get_wildcard(),
                                other.get_wildcard())  # XXX TODO
        return headerspace.flow_wildcard_to_flowmatches(
            wc, class_=self.__class__)

    def __and__(self, other):
        """ Performs an in-place intersection.
            See the intersection method documentation
        """
        return self.intersection(other)

    def __iadd__(self, other):
        """ Performs an update intersection.
            See the intersection_update method documentation
        """
        return self.intersection_update(other)

    def union_cover(self, other):
        """ Returns a new Match representing the cover union

            As per headerspace a union of headerspace can not be simplified
            making this prone to expansion issues, and cannot be expressed
            in a single Match.

            As such the cover union is smallest single headerspace enclosing
            all valid values. This is useful to detect when a certain bit or
            field is restricted to a single value. This may include some
            headerspace which is not within the true union.

            Return: A new Match, bits masked in are required to be that
                    value. Excluded fields are masked out.
        """
        cover = headerspace.wildcard_union_cover(
            self.get_wildcard(), other.get_wildcard())
        return headerspace.flow_wildcard_to_flowmatches(
            cover, class_=self.__class__)

    def intersection_update(self, other):
        """ An in-place intersection, that updates the current match set """
        raise NotImplementedError

    def get_wildcard(self):
        if self._wildcard is None:
            self._wildcard = headerspace.flow_matches_to_wildcard(self)
        return self._wildcard

    def issubset(self, other):
        return wildcard_is_subset(self.get_wildcard(), other.get_wildcard())

    def overlaps(self, other):
        return wildcard_intersect(self.get_wildcard(),
                                  other.get_wildcard()) != 0

    def append(self, name, value, mask):
        assert isinstance(name, string_types)
        self._wildcard = None
        if self.ttp_link:
            field_id = self.ttp_link.ttp.OF.oxm_name_to_id(name)
            l = self.ttp_link.ttp.OF.oxm_fields[name][self.ttp_link.ttp.OF.INDEX_BITS]
        else:
            field_id = G_OF.oxm_name_to_id(name)
            l = G_OF.oxm_fields[name][G_OF.INDEX_BITS]

        if l and mask:
            max_mask = (2**l)-1
            mask = mask & max_mask
            value = value & mask
            if mask == max_mask:
                mask = None

        self[name] = (value, mask, field_id)
        self.required_mask |= 1 << field_id

    def copy(self, add=[], remove=[]):
        """
        Copies the Match.
        add: Add the specified elements to the copy
        remove: A iterable list of elements to remove

        In both cases elements take the form (key, value, mask)
        However removing only checks the key and as such the value and
        mask can be omitted. TODO I changed this behaviour
        """
        cpy = Match(dup=self)
        for r in remove:
            del cpy[r[0]]
        for a in add:
            cpy.append(a[0], a[1], a[2])
        return cpy

    def __delitem__(self, value):
        self._wildcard = None
        if value not in self:
            raise KeyError(value)
        field_id = self[value][2]
        self.required_mask &= ~(1 << field_id)
        dict.__delitem__(self, value)

    def __hash__(self):
        return hash(self.get_wildcard())

    def __eq__(self, other):
        # Perf! Consider using wildcard??
        if isinstance(other, Match):
            if self.required_mask == other.required_mask:
                return dict.__eq__(self, other)
            else:
                return False
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        ret = "{"
        for key, value in viewitems(self):
            ret += (key + "=" + hex(value[0]) +
                    (("/" + hex(value[1])) if value[1] is not None else "") +
                    ",")
        return ret + "}"

    def empty(self):
        return len(self) == 0


class UniqueRules():
    """ Set Rule equality to instance comparison

        This is primarily for performance purposes, if you are working with
        a single ruleset of unique rules.

        The hash and equal function of Rule are updated to be unique per
        instance.

        Usage:

        somedict = dict()
        with UniqueRules(somedict):
            new_dict = dict()
            for ...:
                for rule in ...:
                    # expensive operations using __hash__ or __eq__
                    somedict[rule] += something
                    new_dict[rule] = somethingelse
        somedict[rule]  # Valid if somedict passed to UniqueRules
        new_dict[rule]  # Invalid as hash changed item might not be found


        WARNING: This changes the hash function of all Rule objects, all dicts
        and sets will be invalid when leaving or entering this block.
        It is the responsibility of the caller to rebuild any such mappings
        when entering or exiting this block.
    """
    def __init__(self, *mappings):
        """ *mappings: mappings to be updated when exited (optional)
        """
        self.mappings = mappings

    def __enter__(self):
        if "__hash__" in Rule.__dict__:
            self._old_hash = Rule.__hash__
            self._old_eq = Rule.__eq__
            self._old_ne = Rule.__ne__
            del Rule.__hash__
            del Rule.__eq__
            del Rule.__ne__

    @staticmethod
    def rebuild_mappings(mappings):
        """ Forcibly rebuilds mapping types to recalculate item hashes
            Supports dict and set types
        """
        for _map in mappings:
            if isinstance(_map, dict):
                # Note we need to use iterator to force a rehash
                new = _map.__class__(viewitems(_map))
                _map.clear()
                _map.update(new)
            elif isinstance(_map, set):
                new = _map.__class__(iter(_map))
                _map.clear()
                _map.update(new)
            else:
                print("rebuild_mappings: Unknown mapping type", _map.__class__)

    def __exit__(self, excpt_type, excpt_value, traceback):
        try:
            Rule.__hash__ = self._old_hash
            Rule.__eq__ = self._old_eq
            Rule.__ne__ = self._old_ne
            self.rebuild_mappings(self.mappings)
        except AttributeError:
            # This was re-entered so was a no-op
            pass
