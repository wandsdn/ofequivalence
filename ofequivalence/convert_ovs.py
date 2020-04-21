"""
A conversion layer between an OvS table dump and ryu flows

Sample file format for a OvS flows:
 cookie=0x5adc15c0, table=1, priority=9000,in_port=30 actions=push_vlan:0x8100,set_field:4346->vlan_vid,goto_table:3
 cookie=0x5adc15c0, table=3, priority=9098,in_port=47,dl_vlan=99,dl_src=ec:cd:6d:00:00:0e actions=goto_table:6
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
import re
import logging

from .rule import (Rule, Group, Bucket, ActionList, ActionSet, Instructions,
                   Match, G_OF)
from .utils import as_file_handle
from .format_utils import FORMATTERS, normalise_string

logging.basicConfig()
log = logging.getLogger('ofequivalence.convert_ovs')
IP_MASK = 0xFFFFFFFF
Bucket.__repr__ = Bucket.__str__


SHORTHANDS = [
    ('icmp', [("ETH_TYPE", 0x0800), ("IP_PROTO", 1)]),
    ('icmp6', [("ETH_TYPE", 0x86dd), ("IP_PROTO", 58)]),
    ('tcp', [("ETH_TYPE", 0x0800), ("IP_PROTO", 6)]),
    ('tcp6', [("ETH_TYPE", 0x86dd), ("IP_PROTO", 6)]),
    ('udp', [("ETH_TYPE", 0x0800), ("IP_PROTO", 17)]),
    ('udp6', [("ETH_TYPE", 0x86dd), ("IP_PROTO", 17)]),
    ('sctp', [("ETH_TYPE", 0x0800), ("IP_PROTO", 132)]),
    ('sctp6', [("ETH_TYPE", 0x86dd), ("IP_PROTO", 132)]),
    ('ip', [("ETH_TYPE", 0x0800)]),
    ('ipv6', [("ETH_TYPE", 0x86dd)]),
    ('arp', [("ETH_TYPE", 0x0806)]),
    ('rarp', [("ETH_TYPE", 0x8035)]),
    ('mpls', [("ETH_TYPE", 0x8847)]),
    ('mplsm', [("ETH_TYPE", 0x8848)])
    ]

SHORTHANDS_MAP = dict(SHORTHANDS)


# Unimplemented in ovs IN_PHY_PORT, PBB_ISID, IPV6_EXTHDR
FIELD_TO_OVS = {
    "IN_PORT": "in_port",
    "METADATA": "metadata",
    "ETH_DST": "eth_dst",
    "ETH_SRC": "eth_src",
    "ETH_TYPE": "eth_type",
    "VLAN_VID": "vlan_vid",
    "VLAN_PCP": "vlan_pcp",
    "IP_DSCP": "ip_dscp",
    "IP_ECN": "ip_ecn",
    "IP_PROTO": "ip_proto",
    "IPV4_SRC": "ip_src",
    "IPV4_DST": "ip_dst",
    "TCP_SRC": "tcp_src",
    "TCP_DST": "tcp_dst",
    "UDP_SRC": "udp_src",
    "UDP_DST": "udp_dst",
    "SCTP_SRC": "sctp_src",
    "SCTP_DST": "sctp_dst",
    "ICMPV4_TYPE": "icmp_type",
    "ICMPV4_CODE": "icmp_code",
    "ARP_OP": "arp_op",
    "ARP_SPA": "arp_spa",
    "ARP_TPA": "arp_tpa",
    "ARP_SHA": "arp_sha",
    "ARP_THA": "arp_tha",
    "IPV6_SRC": "ipv6_src",
    "IPV6_DST": "ipv6_dst",
    "IPV6_FLABAL": "ipv6_label",
    "ICMPV6_TYPE": "icmpv6_type",
    "ICMPV6_CODE": "icmpv6_code",
    "IPV6_ND_TARGET": "nd_target",
    "IPV6_ND_SLL": "nd_sll",
    "IPV6_ND_TLL": "nd_tll",
    "MPLS_LABEL": "mpls_label",
    "MPLS_TC": "mpls_tc",
    "MPLS_BOS": "mpls_bos",
    "TUNNEL_ID": "tunnel_id",
    }


def _parse_field_name(key):
    """ Convert the ovs header field name to the corresponding OpenFlow name

        Note: this doesn't deal with VLAN oddities, as these don't directly
              map to OpenFlow
    """
    akas = {
        "in_port_oxm": "in_port",
        "dl_src": "eth_src",
        "dl_dst": "eth_dst",
        "dl_type": "eth_type",
        "dl_vlan_pcp": "vlan_pcp",
        "nw_ecn": "ip_ecn",
        "nw_proto": "ip_proto",
        "nw_src": "ipv4_src",
        "nw_dst": "ipv4_dst",
        "ip_src": "ipv4_src",
        "ip_dst": "ipv4_dst",
        "tp_src": "tcp_src",
        "tp_dst": "tcp_dst",
        "icmp_type": "icmpv4_type",
        "icmp_code": "icmpv4_code",
        "ipv6_label": "ipv6_flabel",
        "nd_target": "ipv6_nd_target",
        "nd_sll": "ipv6_nd_sll",
        "nd_tll": "ipv6_nd_tll",
        "tun_id": "tunnel_id",
        }

    if key in akas:
        key = akas[key]

    if key.upper() in G_OF.oxm_fields:
        return key.upper()
    return None


def _parse_port(port):
    """ Parses the value of a port, to an integer

    Handles special ports like controller, all etc.
    And converting strings in decimal, hex, octal format etc.

    port: The port as a string

    return: The port as an integer
    """
    # Handle special ports like controller, all etc.
    if "OFPP_" + port.upper() in G_OF.ofp_port_no:
        port = G_OF.ofp_port_no["OFPP_" + port.upper()]
        return port
    return int(port, 0)


def _match_token(expr, string):
    """ Frames an expression to match the next argument and runs re.match

        expr: The regex expression which can include capture groups
        returns: re.match() with an extra final capture group: the remaining string
    """
    expr = r"^\s*" + expr + r"\s*(?:,|$)(.*)"
    return re.match(expr, string)


def _parse_next_instruction(ovs_actions, inst, groups):
    """ Tries to parse the next argument as an instruction

        ovs_actions: The string of ovs actions (after actions=)
        inst: The Instruction to add to
        groups: A mapping from group_id to group, used to link group actions
        return: None if unmodified the next argument is not an instruction,
                otherwise the remaining actions
    """
    # clear_actions
    re_match = _match_token(r"clear_actions", ovs_actions)
    if re_match:
        remaining, = re_match.groups()
        inst.clear_actions = True
        return remaining

    # write_actions TODO
    # Here we assume we can only have at most one more level of nested brackets
    # I think that is a correct assumption
    re_match = _match_token(r"write_actions\(((?:[^()]*(?:\([^()]+\))?[^()]*)+)\)", ovs_actions)
    if re_match:
        _ovs_actions, remaining = re_match.groups()
        value = actions_from_ovs(_ovs_actions, groups, ActionSet)
        inst.write_actions = value
        return remaining

    # write_metadata:value[/mask]
    re_match = _match_token(r"write_metadata:([^,()\s/]+)(?:/([^,()\s]+))?", ovs_actions)
    if re_match:
        value, mask, remaining = re_match.groups()
        if not mask:
            mask = None
        else:
            mask = normalise_string(mask)
        value = normalise_string(value)
        inst.write_metadata = (value, mask)
        return remaining

    # goto_table:table
    re_match = _match_token(r"goto_table:([^,()\s]+)", ovs_actions)
    if re_match:
        table, remaining = re_match.groups()
        inst.goto_table = normalise_string(table)
        return remaining

    # resubmit([port],[table]); this variant is the same as goto
    re_match = _match_token(r"resubmit\((?:in_port)?,([^,()\s])\)", ovs_actions)
    if re_match:
        table, remaining = re_match.groups()
        inst.goto_table = normalise_string(table)
        return remaining

    # Unimplemented either in our code
    # copy_ttl_out
    # copy_ttl_in
    # push/pop pbb
    return None


def _parse_next_action(ovs_actions, actions, groups):
    """ Tries to parse the next argument as an action

        ovs_actions: The string of ovs actions (after actions=)
        actions: The ActionList or ActionSet to add to
        groups: A mapping from group_id to group, used to link group actions
        return: None if unmodified the next argument is not PCPinstruction,
                otherwise the remaining actions
    """

    # Single key -> action map
    #
    # drop
    # pop_vlan
    # strip_vlan
    # dec_ttl
    # dec_mpls_ttl
    # controller & controller:max_len & controller(key[=value], ...)
    key_map = {
        "drop": [],
        "pop_vlan": [("POP_VLAN", None)],
        "strip_vlan": [("POP_VLAN", None)],
        "dec_ttl": [("DEC_NW_TTL", None)],
        "dec_mpls_ttl": [("DEC_MPLS_TTL", None)],
        r"(?:controller|controller:[^,()]+|controller\([^()]+\))":
            [("OUTPUT", _parse_port("controller"))]
        }
    for key, _actions in key_map.items():
        re_match = _match_token(key, ovs_actions)
        if re_match:
            remaining, = re_match.groups()
            for act in _actions:
                actions.append(*act)
            return remaining

    # A key:value or key(value) map
    #
    # output:port & output:field
    # output(port=port, max_len=nbytes)
    # group:group
    # push_vlan:ethertype
    # push_mpls:ethertype
    # pop_mpls:ethertype
    # set_queue:queue
    key_value_map = {
        r"output:([^,()\s]*)":
            [lambda v: ("OUTPUT", _parse_port(v))],
        r"output\(\s*port=([^,()\s]+)\s*,\s*max_len=[^,()]+\)":
            [lambda v: ("OUTPUT", _parse_port(v))],
        r"group:([^,()\s]*)":
            [lambda v: ("GROUP", groups[int(v, 0)])],
        r"push_vlan:([^,()\s]*)":
            [lambda v: ("PUSH_VLAN", int(v, 0))],
        r"push_mpls:([^,()\s]*)":
            [lambda v: ("PUSH_MPLS", int(v, 0))],
        r"pop_mpls:([^,()\s]*)":
            [lambda v: ("POP_MPLS", int(v, 0))],
        r"set_queue:([^,()\s]+)":
            [lambda v: ("SET_QUEUE", int(v, 0))],
        r"mod_dl_dst:([^,()\s]+)":
            [lambda v: ("SET_FIELD", ("ETH_DST", normalise_string(v)))],
        r"mod_dl_src:([^,()\s]+)":
            [lambda v: ("SET_FIELD", ("ETH_SRC", normalise_string(v)))],
        r"mod_nw_dst:([^,()\s]+)":
            [lambda v: ("SET_FIELD", ("IPV4_DST", normalise_string(v)))],
        r"mod_nw_src:([^,()\s]+)":
            [lambda v: ("SET_FIELD", ("IPV4_SRC", normalise_string(v)))],
        r"mod_nw_tos:([^,()\s]+)":
            [lambda v: ("SET_FIELD", ("IP_DSCP", normalise_string(v)))],
        r"mod_nw_ecn:([^,()\s]+)":
            [lambda v: ("SET_FIELD", ("IP_ECN", normalise_string(v)))],
        r"mod_nw_ttl:([^,()\s]+)":
            [lambda v: ("SET_NW_TTL", normalise_string(v))],
        r"mod_nw_ttl\(([^,()\s]+)\)":
            [lambda v: ("SET_NW_TTL", normalise_string(v))],
        r"set_nw_ttl:([^,()\s]+)":
            [lambda v: ("SET_NW_TTL", normalise_string(v))],
        r"set_nw_ttl\(([^,()\s]+)\)":
            [lambda v: ("SET_NW_TTL", normalise_string(v))],
        r"set_mpls_ttl:([^,()\s]+)":
            [lambda v: ("SET_MPLS_TTL", normalise_string(v))],
        r"set_mpls_ttl\(([^,()\s]+)\)":
            [lambda v: ("SET_MPLS_TTL", normalise_string(v))],
        r"mod_tp_dst:([^,()\s]+)":
            [lambda v: ("SET_FIELD", ("TCP_DST", normalise_string(v)))],  # Also sets udp and sctp
        r"mod_tp_src:([^,()\s]+)":
            [lambda v: ("SET_FIELD", ("TCP_SRC", normalise_string(v)))],  # Also sets udp and sctp
        }

    for key, action_fns in key_value_map.items():
        re_match = _match_token(key, ovs_actions)
        if re_match:
            value, remaining = re_match.groups()
            for act_fn in action_fns:
                actions.append(*act_fn(value))
            return remaining

    # set_field:value[/mask]->dst
    # load:value->dst
    re_match = _match_token(r"set_field:([^,()/\s]+)(/[^,()]+)?->([a-zA-Z_0-9]+)", ovs_actions)
    if not re_match:
        re_match = _match_token(r"load:([^,()/\s]+)()->([a-zA-Z_0-9]+)", ovs_actions)
    if re_match:
        value, mask, dst, remaining = re_match.groups()
        assert not mask  # Currently not handled
        value = normalise_string(value)
        if dst == "mpls_ttl":
            actions.append("SET_MPLS_TTL", value)
            return remaining
        if dst == "nw_ttl":
            actions.append("SET_NW_TTL", value)
            return remaining
        if dst == "vlan_vid":
            value &= 0xfff
        dst = _parse_field_name(dst)
        assert dst
        actions.append("SET_FIELD", (dst, value))
        return remaining

    # NOTE: Set ttl part of set_field


    # Output ports can be listed directly
    # port, field
    re_match = _match_token(r"([a-zA-Z0-9]*)", ovs_actions)
    if re_match:
        port, remaining = re_match.groups()
        try:
            actions.append("OUTPUT", _parse_port(port))
            return remaining
        except ValueError:
            pass

    return None


def actions_from_ovs(ovs_actions, groups, type_=ActionList):
    """ Parses ovs actions

        Does not parse instructions

        ovs_actions: The actions as a string format as per ovs-actions(7)
        groups: A mapping from group_id to group, used to link group actions
        type_: The type of Actions to create ActionList, ActionSet, Bucket etc.
        return A list/set of actions of type_
    """

    actions = type_()

    while ovs_actions:
        remaining = _parse_next_action(ovs_actions, actions, groups)

        if remaining is not None:
            ovs_actions = remaining
            continue

        log.warning("Unknown instruction/action: %s", ovs_actions)
        break

    return actions


def instructions_from_ovs(ovs_actions, groups):
    """ Parses the actions and instructions

        I.e. parses everything after actions=

        ovs_actions: The actions as a string format as per ovs-actions(7)
            excluding actions=
            e.g. pop_vlan,output:10,goto_table:3
        inst: The rule's instructions to update
        groups: A mapping from group_id to group, used to link group actions

        return: An Instructions() object
    """
    inst = Instructions()
    ovs_actions = ovs_actions.lower()

    while ovs_actions:

        remaining = _parse_next_instruction(ovs_actions, inst, groups)

        if remaining is not None:
            ovs_actions = remaining
            continue

        remaining = _parse_next_action(ovs_actions, inst.apply_actions, groups)

        if remaining is not None:
            ovs_actions = remaining
            continue

        log.warning("Unknown instruction/action: %s", ovs_actions)
        break

    return inst


def _add_match(key, value, mask, match):
    """ Adds a match to a rule

        key: The key as a string
        value: The value as a string or None
        mask: The mask as a string or None
        match: Match() added too
    """

    if value and mask:
        # IPv4 with prefix
        if (value.count(".") == 3 and
                not "." in mask and
                normalise_string(mask) <= 32):
            value = normalise_string(value)
            mask = ((2**normalise_string(mask))-1) << (32-normalise_string(mask))
        elif (value.count(":") > 2 and
              "6" in key and
              not ":" in mask
              and normalise_string(mask) <= 128):
            # IPv6 with prefix
            value = normalise_string(value)
            mask = ((2**normalise_string(mask))-1) << (128-normalise_string(mask))
        else:
            value = normalise_string(value)
            mask = normalise_string(mask)
    elif value:
        value = normalise_string(value)

    if key in SHORTHANDS_MAP:
        assert value is None and mask is None
        to_set = SHORTHANDS_MAP[key]
        for field in to_set:
            match.append(field[0], field[1], None)
        return True

    # We need some special cases for the VLAN fields
    if key == "dl_vlan":
        # Old OpenFlow 1.0 style
        assert mask is None  # dl_vlan cannot be masked
        if value == 0xffff:  # Match no vlan
            match.append("VLAN_VID", 0, None)
        else:
            match.append("VLAN_VID", value & 0x1fff | 0x1000, None)
        return True
    if key == "vlan_vid":
        if mask is not None:
            match.append("VLAN_VID", value & 0x1fff, mask & 0x1fff)
        else:
            match.append("VLAN_VID", value & 0x1fff, None)
        return True
    if key == "vlan_tci":
        if mask & 0x1fff:
            match.append("VLAN_VID", value & 0x1fff, mask & 0x1fff)
        if mask & 0xe000:
            assert mask & 0xe000 == 0xe000
            match.append("VLAN_PCP", value>>9, None)
        return True

    if _parse_field_name(key):
        match.append(_parse_field_name(key), value, mask)
        return True

    return False


def _parse_flow_argument(key, value, mask, rule):
    """ Parse an ovs flow argument including match fields

        key: As a string
        value: As a string or None
        mask: As a string or None
        rule: The rule updated

        return: True if handled and added to the rule, otherwise
                False indicating the argument key was unknown.

        Note: Does not parse actions
    """

    if key in ("table_id", "table"):
        assert not mask
        rule.table = normalise_string(value)
    elif key == "priority":
        assert not mask
        rule.priority = normalise_string(value)
    elif key in ("duration", "n_packets", "n_bytes", "idle_timeout",
                 "hard_timeout", "importance", "send_flow_rem",
                 "no_packet_counts", "no_byte_counts", "reset_counts", "idle_age"):
        pass
    elif key in ("out_group", "out_port", "check_overlap"):
        log.warning("Unexpected key (from dump-flows): %s", key)
        return False
    elif key == "cookie":
        assert not mask
        rule.cookie = normalise_string(value)
    elif _add_match(key, value, mask, rule.match):
        pass
    else:
        log.warning("Unknown field %s %s %s", key, value, mask)
        return False
    return True


def _parse_bucket(line, groups):
    """ Parses the actions in a Bucket

        line: The bucket as a string
        groups: The groups defined so far
        return: A Bucket

        Note: We assume all actions come after the actions= argument although
              it is valid ovs syntax to enter actions without the action argument
    """
    if "actions=" in line:
        _, actions = line.split("actions=")
        return actions_from_ovs(actions, groups, Bucket)

    return Bucket()


def _parse_group(line, groups):
    group = Group()

    # Buckets must be at the end, and there can be multiple
    if "bucket=" in line:
        buckets = re.split(r'[\s,]*bucket=[\s,]*', line)
        #line.split("bucket=")
        group_args = buckets[0]
        buckets = buckets[1:]
    else:
        group_args = line

    for item in re.split(r'[\s,]+', group_args.strip()):
        k, v = item.split("=")
        if k == "group_id":
            group.number = normalise_string(v)
        elif k == "type":
            group.type_ = v
        else:
            log.warning("Unknown key in group: %s %s", k, v)

    for bucket in buckets:
        group.buckets += (_parse_bucket(bucket.strip(), groups),)

    return group


def match_from_ovs(match_ovs):
    """ Parses a string as ovs matches

        match_ovs: A string of ovs matches
                   - Note: don't include flow related keywords (e.g. priority)
                     use rule_from_ovs for that
        return: A Match object
    """
    match = Match()

    # Splitting on white-space and/or comma
    for item in re.split(r'[\s,]+', match_ovs.strip()):
        if not item:
            continue
        if "=" in item:
            k, v = item.split("=")
            if "/" in v:
                v, m = v.split("/")
                _add_match(k, v, m, match)
            else:
                _add_match(k, v, None, match)
        else:
            _add_match(item, None, None, match)

    return match


def rule_from_ovs(line, groups):
    """ Converts an ovs flow rule to a Rule

        line: A string, typically one line of ovs-ofctl dump-flows
              - Must end with the argument actions=
              - See ovs-ofctl(8) for format documentation
        groups: A mapping from group_id to group, used to link group actions
        return: A Rule object

        Note: For most errors related to unknown key words a warning is logged.
              However a bad value for a known value may cause an exception
    """
    rule = Rule()
    rule.table = 0  # By default the table might be omitted if 0
    rule.priority = 0x8000  # ovs omits the priority if it is the 'default'

    fields, actions = line.split("actions=")

    # Splitting on white-space and/or comma
    for item in re.split(r'[\s,]+', fields.strip()):
        if not item:
            continue
        if "=" in item:
            k, v = item.split("=")
            if "/" in v:
                v, m = v.split("/")
                _parse_flow_argument(k, v, m, rule)
            else:
                _parse_flow_argument(k, v, None, rule)
        else:
            _parse_flow_argument(item, None, None, rule)

    if actions:
        rule.instructions = instructions_from_ovs(actions, groups)

    return rule


def actions_to_ovs(actions):
    """ Convert Write/Apply Actions to an OvS representation

        actions: A ActionList or ActionSet based object
        return: A string in OvS action format
    """
    ret = []
    for action, value in actions:
        # Not implemented directly, COPY_TTL_OUT, COPY_TTL_IN
        # GROUP (purposely omitted), PUSH/POP PBB
        if action == "OUTPUT":
            ret.append("output:" + str(value))
        elif action == "SET_MPLS_TTL":
            ret.append("set_mpls_ttl:" + str(value))
        elif action == "DEC_MPLS_TTL":
            ret.append("dec_mpls_ttl")
        elif action == "PUSH_VLAN":
            ret.append("push_vlan:0x{:x}".format(value))
        elif action == "POP_VLAN":
            ret.append("pop_vlan")
        elif action == "PUSH_MPLS":
            ret.append("push_mpls:0x{:x}".format(value))
        elif action == "POP_MPLS":
            ret.append("pop_mpls:0x{:x}".format(value))
        elif action == "SET_QUEUE":
            ret.append("set_queue:" + str(value))
        elif action == "SET_NW_TTL":
            ret.append("set_nw_ttl:" + str(value))
        elif action == "DEC_NW_TTL":
            ret.append("dec_ttl")
        elif action == "SET_FIELD":
            field, _value = value
            if field not in FIELD_TO_OVS:
                raise NotImplementedError("Cannot convert the unknown field: " + field)
            if field == "VLAN_VID":
                _value |= 0x1000
            formatter = FORMATTERS[G_OF.oxm_fields[field].format]
            ret.append("set_field:{}->{}".format(formatter(_value, None), FIELD_TO_OVS[field]))
        else:
            raise NotImplementedError("Cannot convert the unknown action: " + action)
    return ",".join(ret)


def instructions_to_ovs(inst):
    """ Convert Instructions to an OvS representation

        inst: A Instructions object
        return: A string in OvS action format
    """
    ret = []
    if inst.apply_actions:
        ret.append(actions_to_ovs(inst.apply_actions))
    if inst.clear_actions:
        ret.append("clear_actions")
    if inst.write_actions:
        ret.append("write_actions({})".format(actions_to_ovs(inst.write_actions)))
    if inst.write_metadata is not None:
        if inst.write_metadata[1] is None:
            ret.append("write_metadata:{}".format(
                inst.write_metadata[0]))
        else:
            ret.append("write_metadata:{}/{}".format(
                inst.write_metadata[0], inst.write_metadata[1]))
    if inst.goto_table is not None:
        ret.append("goto_table:" + str(inst.goto_table))

    return ",".join(ret)


def match_to_ovs(match):
    """ Converts a Match to an OvS representation

        match: A Match object
        return: A comma separated list of field matches in the OvS format.
    """
    match = match.copy()

    ret = []

    for shorthand, requires in SHORTHANDS:
        for field, value in requires:
            if field in match and match[field] == (value, None):
                continue
            break
        else:
            # We have a match
            for field, _ in requires:
                del match[field]
            ret.append(shorthand)
            break  # A match can only match one shorthand

    for field, (value, mask, _) in match.items():
        if field not in FIELD_TO_OVS:
            raise NotImplementedError("Cannot convert field " + field)
        else:
            formatter = FORMATTERS[G_OF.oxm_fields[field].format]
            ret.append("{}={}".format(FIELD_TO_OVS[field], formatter(value, mask)))
    return ",".join(ret)


def rule_to_ovs(rule):
    """ Converts a Rule to an OvS representation

        rule: A Rule object
        return: A string in OvS flow/rule format
    """
    def _none_to_0(value):
        if value:
            return value
        return 0
    return "cookie=0x{:x}, table={:d}, priority={:d},{} actions={}".format(
        _none_to_0(rule.cookie),
        _none_to_0(rule.table),
        _none_to_0(rule.priority),
        match_to_ovs(rule.match),
        instructions_to_ovs(rule.instructions)
        )


@as_file_handle('w', arg=('file', 1))
def ruleset_to_ovs(ruleset, file):
    """ Writes a ruleset as a list of ovs flows

        This can be loaded using:
        ovs-ofctl add-flows SWITCH FILE

        ruleset: The ruleset to write
        file: The file path or a file handle
    """
    gen = (rule_to_ovs(r) + "\n" for r in ruleset)
    file.writelines(gen)


@as_file_handle('r')
def ruleset_from_ovs(file):
    """ Parses the text output from ovs-ofctl dump-flows/groups

        For dump-flows refer to ovs-ofctl(8) Flow Syntax
        and for dump-groups Group Syntax.

        This finds lines that look like flows or groups in a text file
        as parses them accordingly, for the most part ignoring (and logging)
        unknown lines and arguments it finds.

        file: The file path
        return: A ruleset

        Note: Logs most errors rather and continues parsing rather
              than raising an exception
    """
    l_rules = []  # Lines that look like rules
    l_groups = []  # Lines that look like groups
    ruleset = []
    groups = {}
    for line in file:
        line = line.strip()
        if "group_id=" in line:
            # Groups have to include a group_id
            l_groups.append(line)
        elif 'actions=' in line:
            # Flows have to include actions as its last argument
            l_rules.append(line)
        elif "OFPST_GROUP_DESC" in line:
            pass
        elif "NXST_GROUP_DESC" in line:  # OpenFlow 1.0 extension
            pass
        elif line:
            log.warning("Unknown line: %s", line)

    # Load in groups first
    for line in l_groups:
        group = _parse_group(line, groups)
        assert group.number not in groups
        groups[group.number] = group

    # Now remap group references to actions?
    for line in l_rules:
        rule = rule_from_ovs(line, groups)
        ruleset.append(rule)

    return ruleset
