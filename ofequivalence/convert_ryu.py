"""
A conversion layer between ryu OpenFlow 1.3 flow rules and our internal rule
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
try:
    import cPickle as pickle
    from cPickle import UnpicklingError
except ImportError:
    import pickle
    from pickle import UnpicklingError
import json
import sys

import six
from six import viewitems
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as parser
from ryu.ofproto.ofproto_protocol import ProtocolDesc
from ryu.ofproto.ofproto_parser import ofp_msg_from_jsondict

from .rule import Rule, Match, Instructions, ActionSet, ActionList, Group
from .utils import open_compressed


def _normalise_bytes(value):
    """ Converts bytes or network strings to an int """
    if value is None:
        return None
    if not isinstance(value, six.integer_types):
        parts = None
        if six.PY3 and isinstance(value, str):
            value = bytes(value, 'latin')
        # Check for IPv6 note this can match the naive MAC
        # The smallest IPv6 is '::'
        if (len(value.split(b':')) == 8 or
                (len(value.split(b':')) >= 3 and value.find(b"::") != -1)):
            v2 = value
            while len(v2.split(b':')) < 8:
                v2 = v2.replace(b'::', b':::', 1)
            parts = v2.split(b':')
            assert len(parts) == 8
            res = 0
            shift = 112
            for part in parts:
                part = b"0" if part == b"" else part
                assert int(part, 16) <= 0xFFFF
                res |= int(part, 16) << shift
                shift -= 16
            return res
        # IPv4
        elif len(value.split(b'.')) == 4:
            parts = value.split(b'.')
            assert (int(parts[0]) | int(parts[1]) |
                    int(parts[2]) | int(parts[3])) <= 0xFF
            return (int(parts[0]) << 24 | int(parts[1]) << 16 |
                    int(parts[2]) << 8 | int(parts[3]))
        # Check for mac addresses
        elif len(value.split(b':')) == 6:
            parts = value.split(b':')
        elif len(value.split(b'-')) == 6:
            parts = value.split(b'-')
        if parts:
            return int(b"".join(parts), 16)
    if six.PY3 and isinstance(value, bytes):
        return int.from_bytes(value, 'big')
    if isinstance(value, str):
        return int(value.encode('hex'), 16)
    return int(value)


# ~~~~ Functions converting from ryu to the internal rule representation ~~~~ #


def match_from_ryu(ryu_match):
    """ Converts a ryu OFPMatch to a Match

    ryu_match: A ryu OFPMatch
    return: A Match object
    """
    if ryu_match is None:
        return Match()
    ret = Match()
    for field in ryu_match._fields2:
        oxm = ofproto_v1_3.oxm_from_user(*field)
        value = _normalise_bytes(oxm[1])
        mask = _normalise_bytes(oxm[2])
        ret.append(field[0].upper(), value, mask)
    return ret


def actions_from_ryu(ryu_actions, type_):
    """ Converts a list of ryu actions to a ActionSet or ActionList

    ryu_actions: The list of actions
    type_: Either the string 'set' or 'list' to create an action set
           (Write Actions) or list (Apply Actions).
    return: Either a ActionList or ActionSet object
    """
    if type_ == 'set':
        ret = ActionSet()
    elif type_ == 'list':
        ret = ActionList()
    else:
        raise ValueError("type_ should be either 'set' or 'list'")
    for action in ryu_actions:
        if action.type == ofproto_v1_3.OFPAT_OUTPUT:
            ret.append('OUTPUT', action.port)
        elif action.type == ofproto_v1_3.OFPAT_COPY_TTL_OUT:
            ret.append('COPY_TTL_OUT', None)
        elif action.type == ofproto_v1_3.OFPAT_COPY_TTL_IN:
            ret.append('COPY_TTL_IN', None)
        elif action.type == ofproto_v1_3.OFPAT_SET_MPLS_TTL:
            ret.append('SET_MPLS_TTL', action.mpls_ttl)
        elif action.type == ofproto_v1_3.OFPAT_DEC_MPLS_TTL:
            ret.append('DEC_MPLS_TTL', None)
        elif action.type == ofproto_v1_3.OFPAT_PUSH_VLAN:
            ret.append('PUSH_VLAN', action.ethertype)
        elif action.type == ofproto_v1_3.OFPAT_POP_VLAN:
            ret.append('POP_VLAN', None)
        elif action.type == ofproto_v1_3.OFPAT_PUSH_MPLS:
            ret.append('PUSH_MPLS', action.ethertype)
        elif action.type == ofproto_v1_3.OFPAT_POP_MPLS:
            ret.append('POP_MPLS', action.ethertype)
        elif action.type == ofproto_v1_3.OFPAT_SET_QUEUE:
            ret.append('SET_QUEUE', action.queue_id)
        elif action.type == ofproto_v1_3.OFPAT_GROUP:
            ret.append('GROUP', action.group_id)
        elif action.type == ofproto_v1_3.OFPAT_SET_NW_TTL:
            ret.append('SET_NW_TTL', action.nw_ttl)
        elif action.type == ofproto_v1_3.OFPAT_DEC_NW_TTL:
            ret.append('DEC_NW_TTL', None)
        elif action.type == ofproto_v1_3.OFPAT_SET_FIELD:
            try:
                ret.append('SET_FIELD', (action.key.upper(),
                                         _normalise_bytes(action.field.value)))
            except Exception:
                ret.append('SET_FIELD', (action.key.upper(),
                                         _normalise_bytes(action.value)))
        elif action.type == ofproto_v1_3.OFPAT_PUSH_PBB:
            ret.append('PUSH_PBB', action.ethertype)
        elif action.type == ofproto_v1_3.OFPAT_POP_PBB:
            ret.append('POP_PBB', None)
        else:
            raise ValueError("Unknown ryu action type " + str(action))
    return ret


def instructions_from_ryu(ryu_instructions):
    """ Converts a list of ryu OFPInstruction*'s to Instructions

        ryu_instructions: A list of OFPInstruction* objects
        return: An Instructions object
    """
    if ryu_instructions is None:
        return Instructions()
    ret = Instructions()
    for instruction in ryu_instructions:
        if instruction.type == ofproto_v1_3.OFPIT_GOTO_TABLE:
            ret.goto_table = instruction.table_id
        elif instruction.type == ofproto_v1_3.OFPIT_WRITE_METADATA:
            ret.write_metadata = (instruction.metadata, instruction.metadata_mask)
        elif instruction.type == ofproto_v1_3.OFPIT_WRITE_ACTIONS:
            ret.write_actions = actions_from_ryu(instruction.actions, 'set')
        elif instruction.type == ofproto_v1_3.OFPIT_APPLY_ACTIONS:
            ret.apply_actions = actions_from_ryu(instruction.actions, 'list')
        elif instruction.type == ofproto_v1_3.OFPIT_CLEAR_ACTIONS:
            ret.clear_actions = True
        elif instruction.type == ofproto_v1_3.OFPIT_METER:
            assert not "TODO"
            # ret.meter =
        else:
            assert "Not standard"
    return ret


def rule_from_ryu(ryu_flow):
    """ Converts a ryu OFPFlowStat to a Rule

        This will also work with similar types such as OFPFlowMod and
        OFPFlowRemoved.

        ryu_flow: A OFPFlowStat object or similar
        return: A Rule object
    """
    rule = Rule()
    rule.priority = ryu_flow.priority
    rule.cookie = ryu_flow.cookie
    rule.match = match_from_ryu(ryu_flow.match)
    rule.instructions = instructions_from_ryu(ryu_flow.instructions)
    rule.table = ryu_flow.table_id
    return rule


def ruleset_from_ryu(f_name):
    """ Loads a ryu ruleset from either a pickle or json format

        f_name: The path to the file
        return: A list of Rules
    """
    with open_compressed(f_name, "rb") as f_handle:
        ruleset = None
        if 'json' in f_name or 'jsn' in f_name:
            # Try json first
            try:
                ruleset = ruleset_from_ryu_json(f_handle)
            except ValueError:  # Only python3 has JSONDecodeError
                f_handle.seek(0)
                ruleset = ruleset_from_ryu_pickle(f_handle)
        else:
            try:
                ruleset = ruleset_from_ryu_pickle(f_handle)
            except UnpicklingError:
                f_handle.seek(0)
                ruleset = ruleset_from_ryu_json(f_handle)

    return ruleset

def ruleset_from_ryu_pickle(f_handle):
    """ Loads a pickled ryu ruleset

        The ruleset can be compressed, either .gz or .bz2 and are
        decompressed based on their extension.

        The ryu ruleset can be a dump of flow stats, or flow mods.

        f_handle: An open file handle
        return: A list of Rules
    """
    if six.PY3:
        stats = pickle.load(f_handle, encoding='latin1')
    else:
        stats = pickle.load(f_handle)
    if isinstance(stats, dict):
        stats = stats["flow_stats"]
    ruleset = [rule_from_ryu(r) for r in stats]
    return ruleset

def ryu_from_jsondict(jsondict):
    assert len(jsondict) == 1
    for oftype, value in jsondict.items():
        cls = getattr(parser, oftype)
        return cls.from_jsondict(value)

def ruleset_from_ryu_json(f_handle):
    """ Loads a ryu ruleset from json

        The ruleset can be compressed, either .gz or .bz2 and are
        decompressed based on their extension.

        The ryu ruleset can be a dump of flow stats, or flow mods.

        f_handle: An open file handle
        return: A list of Rules
    """
    if six.PY3:
        stats = json.load(f_handle, encoding='latin1')
    else:
        stats = json.load(f_handle)

    # Find something that looks about right
    while isinstance(stats, dict):
        first = next(iter(stats))
        if len(stats) != 1:
            print("ruleset_from_ryu_json: Warning found multiple values in a dict, using the first",
                  file=sys.stderr)
            print(next(iter(stats)), file=sys.stdout)
        if isinstance(first, six.string_types) and first.startswith("OFP"):
            break  # This should work and return a ruleset
        print("ruleset_from_ryu_json: Unknown value in json", first, ". Skipping into contents.",
              file=sys.stderr)
        stats = stats[first]

    if isinstance(stats, dict):
        # Could be a OFPFlowStatsReply message, untested code path
        dp = ProtocolDesc(version=ofproto_v1_3.OFP_VERSION)
        msg = ofp_msg_from_jsondict(dp, stats)
        stats = msg.body
    else:
        assert isinstance(stats, list)
        stats = [ryu_from_jsondict(r) for r in stats]

    ruleset = [rule_from_ryu(r) for r in stats]
    return ruleset


# ~~~~ Functions converting from the internal rule representation to ryu ~~~~ #


def group_ofdpa_id(group, rule, _bad_counter=[]):
    """ Gets a group ID which is valid for ofdpa.

        If detected ofdpa is detected in the ttp_link return a valid ofdpa
        group number. Otherwise returns the next unused number.

        group: The Group
        rule: The Rule, required to extract VLAN match from for ofdpa
        return: The next group ID as an integer
    """
    if "VLAN_VID" in rule.match:
        vlan_vid = rule.match["VLAN_VID"][0]
        vlan_vid &= 0xfff

    if group.buckets:
        for action in group.buckets[0]:
            if action[0] == "OUTPUT":
                port_id = action[1]
    group_id = None
    if group.ttp_link.name == "L2 Interface":
        # Naming Convention : Type [31:28]:0, Vlan Id [27:16]:0xnnn,
        # Port [15:0]:0xnnnn
        group_id = (vlan_vid << 16) | port_id
    elif group.ttp_link.name == "L2 Unfiltered Interface":
        # Naming Convention : Type [31:28]:11, Vlan Id [27:16]:0x000,
        # Port [15:0]:0xnnnn
        group_id = (11 << 28) | port_id
    elif group.ttp_link.name == "L3 Interface":
        # Naming Convention : Type [31:28]:5, Id [27:0]:0xnnnnnn
        _bad_counter.append(1)
        group_id = (5 << 28) | len(_bad_counter)
    elif group.ttp_link.name == "L3 Multicast":
        # Naming Convention : Type [31:28]:6, VLAN Id [27:16]:0xnnn,
        # Id [15:0]:0xnnnn
        _bad_counter.append(1)
        group_id = (6 << 28) | (vlan_vid << 16) | len(_bad_counter)
    elif group.ttp_link.name == "L3 Unicast":
        # Naming Convention : Type [31:28]:2, Id [27:0]:0xnnnnnn
        _bad_counter.append(1)
        group_id = (2 << 28) | len(_bad_counter)
    elif group.ttp_link.name == "L3 ECMP":
        # Naming Convention : Type [31:28]:7, Id [27:0]:0xnnnnnn, :
        _bad_counter.append(1)
        group_id = (7 << 28) | len(_bad_counter)
    elif group.ttp_link.name == "L2 Flood":
        # Naming Convention : Type [31:28]:4, VLAN Id [27:16]:0xnnn,
        # Id [15:0]:0xnnnn
        _bad_counter.append(1)
        group_id = (4 << 28) | (vlan_vid << 16) | len(_bad_counter)
    elif group.ttp_link.name == "L2 Multicast":
        # Naming Convention : Type [31:28]:3, VLAN Id [27:16]:0xnnn,
        # Id [15:0]:0xnnnn
        _bad_counter.append(1)
        group_id = (3 << 28) | (vlan_vid << 16) | len(_bad_counter)
    elif group.ttp_link.name == "L3 Rewrite":
        # Naming Convention : Type [31:28]:1, Id [27:0]:0xnnnnnn, :
        _bad_counter.append(1)
        group_id = (1 << 28) | len(_bad_counter)

    if group_id is not None:
        return group_id
    # Default non ofdpa groups
    _bad_counter.append(0)
    return len(_bad_counter)


def group_to_ryu(group, rule):
    """ Converts a group to the group id, and a group mod

        group: The group action
        rule: The original rule
        return: (group_id, extra_messages)
    """
    extra_messages = []

    type_ = getattr(ofproto_v1_3, "OFPGT_" + group.type_.upper())
    group_id = group_ofdpa_id(group, rule)
    buckets = []
    for bucket in group.buckets:
        actions, messages = actions_to_ryu(bucket, rule)
        buckets.append(parser.OFPBucket(actions=actions))
        extra_messages += messages

    extra_messages.append(
        parser.OFPGroupMod(None, type_=type_, group_id=group_id,
                           buckets=buckets))
    return (group_id, extra_messages)


def actions_to_ryu(actions, rule):
    """ Converts a list of actions to a list of ryu actions

        This returns both a instruction list and any extra messages that
        are required to install the instructions such as group mod messages.
        Currently this is not smart about reusing groups.

        actions: A iterable list actions such as ActionSet, ActionList,
                 or Bucket.
        rule: The rule being converted
        return: A tuple ([actions], [extra messages])
    """
    ret = []
    extra_messages = []
    for action in actions:
        if action[0] == 'OUTPUT':
            ret.append(parser.OFPActionOutput(action[1]))
        elif action[0] == 'COPY_TTL_OUT':
            ret.append(parser.OFPActionCopyTtlOut())
        elif action[0] == 'COPY_TTL_IN':
            ret.append(parser.OFPActionCopyTtlIn())
        elif action[0] == 'SET_MPLS_TTL':
            ret.append(parser.OFPActionSetMplsTtl(action[1]))
        elif action[0] == 'DEC_MPLS_TTL':
            ret.append(parser.OFPActionDecMplsTtl())
        elif action[0] == 'PUSH_VLAN':
            ret.append(parser.OFPActionPushVlan(action[1]))
        elif action[0] == 'POP_VLAN':
            ret.append(parser.OFPActionPopVlan())
        elif action[0] == 'PUSH_MPLS':
            ret.append(parser.OFPActionPushMpls(action[1]))
        elif action[0] == 'POP_MPLS':
            ret.append(parser.OFPActionPopMpls(action[1]))
        elif action[0] == 'SET_QUEUE':
            ret.append(parser.OFPActionSetQueue(action[1]))
        elif action[0] == 'GROUP':
            if isinstance(action[1], Group):
                group_id, extra = group_to_ryu(action[1], rule)
                ret.append(parser.OFPActionGroup(group_id))
                extra_messages += extra
            else:
                ret.append(parser.OFPActionGroup(action[1]))
        elif action[0] == 'SET_NW_TTL':
            ret.append(parser.OFPActionSetNwTtl(action[1]))
        elif action[0] == 'DEC_NW_TTL':
            ret.append(parser.OFPActionDecNwTtl())
        elif action[0] == 'SET_FIELD':
            set_field = {action[1][0].lower(): action[1][1]}
            ret.append(parser.OFPActionSetField(**set_field))
        elif action[0] == 'PUSH_PBB':
            ret.append(parser.OFPActionPushPbb(action[1]))
        elif action[0] == 'POP_PBB':
            ret.append(parser.OFPActionPopPbb())
        else:
            assert not "GGRR"
    return (ret, extra_messages)


def instructions_to_ryu(instructions, rule):
    """ Converts Instructions to a list of ryu instructions

        This returns both a instruction list and any extra messages that
        are required to install the instructions such as group mod messages.
        Currently this is not smart about reusing groups.

        instructions: A Instructions object
        rule: A Rule
        return: A tuple ([instructions], [extra messages])
    """
    ret = []
    extra_messages = []
    if instructions.goto_table is not None:
        ret.append(
            parser.OFPInstructionGotoTable(instructions.goto_table))
    if instructions.write_metadata is not None:
        assert not "TODO"
    if (instructions.write_actions is not None and
            not instructions.write_actions.empty()):
        actions, extra = actions_to_ryu(instructions.write_actions, rule)
        ret.append(parser.OFPInstructionActions(
            ofproto_v1_3.OFPIT_WRITE_ACTIONS, actions))
        extra_messages += extra
    if (instructions.apply_actions is not None and
            not instructions.apply_actions.empty()):
        actions, extra = actions_to_ryu(instructions.apply_actions, rule)
        ret.append(parser.OFPInstructionActions(
            ofproto_v1_3.OFPIT_APPLY_ACTIONS, actions))
        extra_messages += extra
    if instructions.clear_actions is True:
        ret.append(
            parser.OFPInstructionActions(ofproto_v1_3.OFPIT_CLEAR_ACTIONS))
    if instructions.meter is not None:
        assert not "TODO"

    return (ret, extra_messages)


def match_to_ryu(match):
    """ Converts a Match to a ryu OFPMatch

        match: A Match
        return: An OFPMatch
    """
    match = {field.lower(): value[0:2] for field, value in viewitems(match)}
    return parser.OFPMatch(**match)


def rule_to_ryu(rule):
    """ Converts a Rule to a ryu OFPFlowMod and other required messages

        This returns both a OFPFlowMod and any extra messages that
        are required to install the flow such as group mod messages.
        Currently this is not smart about reusing groups.

        rule: A Rule
        return: A tuple (OFPFlowMod, [extra messages])
    """
    match = match_to_ryu(rule.match)
    instructions, extra_messages = instructions_to_ryu(rule.instructions, rule)

    # Make sure priority is an integer
    if rule.priority is not None:
        rule.priority = int(rule.priority)

    ryu = parser.OFPFlowMod(datapath=None,
                            table_id=rule.table,
                            priority=rule.priority,
                            match=match,
                            instructions=instructions
                            )
    return (ryu, extra_messages)
