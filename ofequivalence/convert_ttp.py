"""
A conversion layer between built-in TTPFlows to our internal rule
representation.
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
from six import integer_types, string_types
from ttp_tools.TTP import TTPTable

from .rule import Rule, Match, Instructions, ActionSet, ActionList


def rule_from_ttp(ttp_flow):
    """ Convert a built-in TTPFlow to a Rule

        Handling of meta objects other than all are unspecified.

        ttp_flow: A TTPFlow instance
        return: A Rule
    """
    if not ttp_flow.built_in:
        print("Warning converting a non-built-in TTPFlow to a Flow.")

    rule = Rule()
    #flow.ttp_link = ttp_flow.ttp
    rule.priority = ttp_flow.priority
    assert isinstance(rule.priority, integer_types)
    rule.cookie = None

    rule.match = match_from_ttp(ttp_flow.match_set)
    rule.instructions = instructions_from_ttp(ttp_flow.instruction_set)
    rule.table = ttp_flow.walk_parents(TTPTable).number

    return rule


def match_from_ttp(ttp_match):
    """ Converts a TTPMatchSet to a Match
    """
    match = Match()
    #match.ttp_link = ttp_match.ttp
    for field in ttp_match.get_flat():
        if not field.is_required():
            print("Warning:", field, "not required, but in a builtin match")
        assert isinstance(field.field_name, string_types)
        assert isinstance(field.value, integer_types)
        assert isinstance(field.value, integer_types + (None.__class__,))
        match.append(field.field_name, field.value, field.mask)

    return match


def instructions_from_ttp(ttp_instructions):
    """ Converts a TTPInstructionSet to Instructions

        ttp_instructions: The TTPInstructionSet
        return: An Instructions object
    """
    instructions = Instructions()
    #instructions.ttp_link = ttp_instructions.ttp

    for inst in ttp_instructions.get_flat():

        if inst.instruction == "GOTO_TABLE":
            instructions.goto_table = inst.ttp.find_table(inst.table).number
        elif inst.instruction == "CLEAR_ACTIONS":
            instructions.clear_actions = True
        elif inst.instruction == "APPLY_ACTIONS":
            instructions.apply_actions = actions_from_ttp(inst.actions, 'list')
        elif inst.instruction == "WRITE_ACTIONS":
            instructions.write_actions = actions_from_ttp(inst.actions, 'set')
        elif inst.instruction == "METER":
            raise NotImplementedError
        elif inst.instruction == "WRITE_METADATA":
            raise NotImplementedError
        else:
            raise NotImplementedError

    assert (instructions.goto_table is None or
            isinstance(instructions.goto_table, integer_types))
    return instructions


def actions_from_ttp(ttp_actions, type_):
    """ Converts a TTPActions to an ActionSet or ActionList

    ttp_actions: The TTPActions
    type_: Either the string 'set' or 'list' to create an action set
           (Write Actions) or list (Apply Actions).
    return: Either a ActionList or ActionSet object
    """
    if type_ == 'set':
        ret = ActionSet()
    elif type_ == 'list':
        ret = ActionList()
    else:
        assert False

    for action in ttp_actions.get_flat():
        if action.action == "OUTPUT":
            ret.append('OUTPUT', action.port)
        elif action.action == "COPY_TTL_OUT":
            ret.append('COPY_TTL_OUT', None)
        elif action.action == "COPY_TTL_IN":
            ret.append('COPY_TTL_IN', None)
        elif action.action == "SET_MPLS_TTL":
            ret.append('SET_MPLS_TTL', action.ttl)
        elif action.action == "DEC_MPLS_TTL":
            ret.append('DEC_MPLS_TTL', None)
        elif action.action == "PUSH_VLAN":
            ret.append('PUSH_VLAN', action.ethertype)
        elif action.action == "POP_VLAN":
            ret.append('POP_VLAN', None)
        elif action.action == "PUSH_MPLS":
            ret.append('PUSH_MPLS', action.ethertype)
        elif action.action == "POP_MPLS":
            ret.append('POP_MPLS', action.ethertype)
        elif action.action == "SET_QUEUE":
            ret.append('SET_QUEUE', action.queue_id)
        elif action.action == "GROUP":
            raise NotImplementedError
            ret.append('GROUP', action.group_id)
        elif action.action == "SET_NW_TTL":
            ret.append('SET_NW_TTL', action.ttl)
        elif action.action == "DEC_NW_TTL":
            ret.append('DEC_NW_TTL', None)
        elif action.action == "SET_FIELD":
            if not action.field.startswith("$"):
                if not isinstance(action.value, integer_types):
                    print("Warning needs a fixed value", action)
                else:
                    ret.append('SET_FIELD', (action.field, action.value))
        elif action.action == "PUSH_PBB":
            ret.append('PUSH_PBB', action.ethertype)
        elif action.action == "POP_PBB":
            ret.append('POP_PBB', None)
        else:
            print("Unknown special instruction", action)
    return ret
