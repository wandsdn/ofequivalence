""" A description of OpenFlow including matches and actions


The OpenFlowDescription class is a shared base, which is
extended to create an actual description.

The OpenFlow1_3_5 class provides a 1.3.5 OpenFlow description.
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
import difflib
import copy

from six import string_types
from six.moves import reduce

# The number of extra tunnel fields to create
HEADER_DEPTH = 2

class OpenFlowDescription(object):

    """ The base class describing an OpenFlow version.
        This contains constants from enums and oxm field
        information.

        This also assigns unique ID's to new OXM's seen in
        a Table Type Pattern using oxm_name_to_id and check_oxm_name.

    """

    # A list of valid OpenFlow OXM field names, mapped to an internal id, bit
    # width pipeline
    # name -> (identifier, bits, bytes, mask, default_value, pre-reqs)
    # name: the name of the field
    # identifier: the bit representing this in the bitmask (counting from zero)
    # length: The number of valid bits in the field, used to determine if mask
    #         is prefix etc.
    # default_value: If the field is pipeline metadata(i.e. not in the packet)
    #                set a default value
    #
    oxm_fields = None
    ordered_oxm_fields = None  # A stable ordered (by ident) list of oxm fields
    # A list of tunnel headers, defining push, pop and fields added
    tunnels = None
    # A dict of push to tunnel info, i.e. mapping into tunnels
    tun_push = None
    # A dict of pop to tunnel info, i.e. mapping into tunnels
    tun_pop = None

    action_set_order = None  # The order in which an action set will be applied

    # We say a dep exists for an operation x and y iff
    # switch the order of x and y could change the operation
    # x performs on the final packet. This includes changing
    # a field in the wrong header, because another is pushed.
    # However we note that the push header in this case does not
    # depend on x, unless x is copied in as part of the push
    # Either way moving x and y is not possible because one
    # half has a problem with it
    action_dependancies = None

    ofp_all = None  # A dict mapping name to value of all OFP* defines
    # ofp* enums of each thing

    def oxm_name_to_id(self, name):
        """ Takes an OXM name and returns a id number.

            Note: OXM numbers start at 0 and go up to about 60

            name: The field name
            return: If existing the OXM match id number, otherwise the next
                    free number is allocated and returned. This is logged to
                    stdout.
        """
        if name in self.oxm_fields:
            return self.oxm_fields[name].id
        else:
            maybes = difflib.get_close_matches(name, self.oxm_fields)
            last_id = self.oxm_fields[self.ordered_oxm_fields[-1]].id
            print("Adding field " + name + " as " + str(last_id + 1) +
                  "consider adding this with name and values")
            if maybes:
                print("Is this a simple typo? Maybe you meant: " + str(maybes))
            self.oxm_fields[name] = FieldDescription(name, last_id + 1, None, None,
                                                     None, None, [], "decimal")
            self.ordered_oxm_fields.append(name)
            return last_id + 1

    def check_oxm_name(self, name, log):
        """ Check if an oxm exists

            name: The match field name
            log: A log to print a warning if not found, required
            return: True if exists, otherwise False
        """
        if name not in self.oxm_fields:
            maybes = difflib.get_close_matches(name, self.oxm_fields)
            maybes = " or ".join(maybes)
            if maybes:
                log.warning("Unknown field %s used - did you mean: %s?",
                            name, maybes)
            else:
                log.warning("Unknown field %s used. Are you missing a $?",
                            name)
            return False
        return True

    def value_from_OFP(self, OFP):
        """ Returns a value from a OpenFlow Protocol define

            OFP: The OFP value name as a string
            return: The value defined, normally a integer.
                    Otherwise if not found None.
        """
        if isinstance(OFP, string_types):
            if "OFP" + OFP in self.ofp_all:
                return self.ofp_all["OFP" + OFP]
            elif OFP in self.ofp_all:
                return self.ofp_all[OFP]
        return None

    @staticmethod
    def merge_dicts(x, y):
        """ Helper function to merge dictionaries """
        new_len = len(x) + len(y)
        x.update(y)
        assert new_len == len(x)
        return x

class FieldDescription(object):
    """ Details of a header field from the OpenFlow Spec

        name: str, The field name
        id: int, The OXM ID in OpenFlow
        bits: int, The number of valid bits in this header (the lowest X bits)
        bytes: int, The number of bytes (sent in the OpenFlow OXM message)
        maskable: bool, True if the field can be masked
        default: The default value of the field, e.g. the default value of a
                 pipeline only field like metadata when it is created.
        prereqs: List of (field, value) tuples, the required prerequisites
                 to match on this field
        format: String, The human-readable format to display this field in
                Choices: decimal, hex, ipv4, ipv6, ethernet
                         - see format_utils.FORMATTERS
    """
    __slots__ = ("name", "id", "bits", "bytes", "maskable", "default", "prereqs",
                 "format")

    def __init__(self, name, _id, bits, _bytes, maskable, default, prereqs, _format):
        self.name = name
        self.id = _id
        self.bits = bits
        self.bytes = _bytes
        self.maskable = maskable
        self.default = default
        self.prereqs = prereqs
        self.format = _format

class OpenFlow1_3_5(OpenFlowDescription):

    """ The OpenFlow 1.3.5 OXMs and defines etc
    """

    def __init__(self):

        ipv4_or_6 = [("ETH_TYPE", 0x0800), ("ETH_TYPE", 0x86dd)]
        ipv4 = [("ETH_TYPE", 0x0800)]
        arp = [("ETH_TYPE", 0x0806)]
        ipv6 = [("ETH_TYPE", 0x86dd)]
        mpls = [("ETH_TYPE", 0x8847), ("ETH_TYPE", 0x8848)]
        pbb = [("ETH_TYPE", 0x88e7)]
        tcp = [("IP_PROTO", 6)]
        udp = [("IP_PROTO", 17)]
        sctp = [("IP_PROTO", 132)]
        icmp = [("IP_PROTO", 1)]
        icmpv6 = [("IP_PROTO", 58)]
        icmpv6_nd = [("ICMPV6_TYPE", 135), ("ICMPV6_TYPE", 136)]

        FD = FieldDescription
        self.oxm_fields = [
            # (name, id, bits, bytes, maskable, default, pre-requisites, format)
            FD("IN_PORT", 0, 32, 4, False, None, [], "decimal"),
            FD("IN_PHY_PORT", 1, 32, 4, False, None, [("IN_PORT")], "decimal"),
            FD("METADATA", 2, 64, 8, True, 0, [], "hex"),
            FD("ETH_DST", 3, 48, 6, True, None, [], "ethernet"),
            FD("ETH_SRC", 4, 48, 6, True, None, [], "ethernet"),
            FD("ETH_TYPE", 5, 16, 2, False, None, [], "hex"),
            FD("VLAN_VID", 6, 13, 2, True, None, [], "decimal"),
            FD("VLAN_PCP", 7, 3, 1, False, None, [("VLAN_VID")], "decimal"),
            FD("IP_DSCP", 8, 6, 1, False, None, ipv4_or_6, "decimal"),
            FD("IP_ECN", 9, 2, 1, False, None, ipv4_or_6, "decimal"),
            FD("IP_PROTO", 10, 8, 1, False, None, ipv4_or_6, "decimal"),
            FD("IPV4_SRC", 11, 32, 4, True, None, ipv4, "ipv4"),
            FD("IPV4_DST", 12, 32, 4, True, None, ipv4, "ipv4"),
            FD("TCP_SRC", 13, 16, 2, False, None, tcp, "decimal"),
            FD("TCP_DST", 14, 16, 2, False, None, tcp, "decimal"),
            FD("UDP_SRC", 15, 16, 2, False, None, udp, "decimal"),
            FD("UDP_DST", 16, 16, 2, False, None, udp, "decimal"),
            FD("SCTP_SRC", 17, 16, 2, False, None, sctp, "decimal"),
            FD("SCTP_DST", 18, 16, 2, False, None, sctp, "decimal"),
            FD("ICMPV4_TYPE", 19, 8, 1, False, None, icmp, "decimal"),
            FD("ICMPV4_CODE", 20, 8, 1, False, None, icmp, "decimal"),
            FD("ARP_OP", 21, 16, 2, True, None, arp, "decimal"),
            FD("ARP_SPA", 22, 32, 4, True, None, arp, "ipv4"),
            FD("ARP_TPA", 23, 32, 4, True, None, arp, "ipv4"),
            FD("ARP_SHA", 24, 48, 6, True, None, arp, "ethernet"),
            FD("ARP_THA", 25, 48, 6, True, None, arp, "ethernet"),
            FD("IPV6_SRC", 26, 128, 16, True, None, ipv6, "ipv6"),
            FD("IPV6_DST", 27, 128, 16, True, None, ipv6, "ipv6"),
            FD("IPV6_FLABEL", 28, 20, 4, True, None, ipv6, "hex"),
            FD("ICMPV6_TYPE", 29, 8, 1, False, None, icmpv6, "decimal"),
            FD("ICMPV6_CODE", 30, 8, 1, False, None, icmpv6, "decimal"),
            FD("IPV6_ND_TARGET", 31, 128, 16, False, None, icmpv6_nd, "ipv6"),
            FD("IPV6_ND_SLL", 32, 48, 6, False, None, icmpv6_nd, "ethernet"),
            FD("IPV6_ND_TLL", 33, 48, 6, False, None, icmpv6_nd, "ethernet"),
            FD("MPLS_LABEL", 34, 20, 4, False, None, mpls, "decimal"),
            FD("MPLS_TC", 35, 3, 1, False, None, mpls, "decimal"),
            FD("MPLS_BOS", 36, 1, 1, False, None, mpls, "decimal"),
            FD("PBB_ISID", 37, 24, 3, True, None, pbb, "decimal"),
            FD("TUNNEL_ID", 38, 64, 8, True, None, [], "hex"),
            FD("IPV6_EXTHDR", 39, 9, 2, True, None, ipv6, "decimal"),
        ]
        self.oxm_fields = {field.name: field for field in self.oxm_fields}

        self.tunnels = [
            {
                "push": "PUSH_VLAN",
                "pop": "POP_VLAN",
                "fields": ("VLAN_VID", "VLAN_PCP")
            }, {
                "push": "PUSH_MPLS",
                "pop": "POP_MPLS",
                "fields": ("MPLS_LABEL", "MPLS_TC", "MPLS_BOS")
            }, {
                "push": "PUSH_PBB",
                "pop": "POP_PBB",
                "fields": ("ETH_DST", "ETH_SRC", "PBB_ISID")
            }
        ]

        self.tun_push = {}
        self.tun_pop = {}
        for tun in self.tunnels:
            self.tun_push[tun["push"]] = tun
            self.tun_pop[tun["pop"]] = tun

        self.HEADER_DEPTH = HEADER_DEPTH
        for tunnel in self.tunnels:
            for field in tunnel['fields']:
                orig = self.oxm_fields[field]
                for i in range(1, HEADER_DEPTH+1):
                    new_field = copy.copy(orig)
                    new_field.name = field + str(i)
                    new_field.id = len(self.oxm_fields)
                    self.oxm_fields[new_field.name] = new_field

        # A stable list
        self.ordered_oxm_fields = [x.name for x in sorted(self.oxm_fields.values(),
                                                          key=lambda k: k.id)]

        """ The order in which an action set (i.e. write-actions and groups) is applied
        From the spec:
        1. Copy TTL inwards
        2. pop (all)
        3. push-mpls
        4. push pbb
        5. push vlan
        6. copy TTL outwards
        7. decrement TTL
        8. set fields
        9. qos
        10. group
        11. output (only if no group though)
        """
        self.action_set_order = ["COPY_TTL_IN", "POP_VLAN", "POP_PBB",
                                 "POP_MPLS", "PUSH_MPLS", "PUSH_PBB",
                                 "PUSH_VLAN", "COPY_TTL_OUT", "DEC_MPLS_TTL",
                                 "DEC_NW_TTL", "SET_FIELD", "SET_MPLS_TTL",
                                 "SET_NW_TTL", "SET_QUEUE", "GROUP", "OUTPUT"]

        """ We'll sort these specially """
        set_all = set(self.action_set_order)
        set_ttl = set(("COPY_TTL_OUT", "COPY_TTL_IN", "SET_MPLS_TTL",
                       "DEC_MPLS_TTL", "PUSH_MPLS", "POP_MPLS",
                       "SET_NW_TTL", "DEC_NW_TTL"))

        def S(x):
            return ("SET_FIELD", x)

        # Basically anything in an action list that cannot be reordered
        # The general strategy is to move all items as early as
        # possible and then sort
        self.action_dependancies = {
            # We say a dep exists for an operation x and y iff
            # switch the order of x and y could change the operation
            # x performs on the final packet. This includes changing
            # a field in the wrong header, because another is pushed.
            # However we note that the push header in this case does not
            # depend on x, unless x is copied in as part of the push
            # Either way moving x and y is not possible because one
            # half has a problem with it

            # Output and group both take copies of packets an hence can be
            # reordered amongst themselves however all other actions modify
            # the packet
            "OUTPUT": set_all - set(("OUTPUT", "GROUP")),
            "GROUP": set_all - set(("OUTPUT", "GROUP")),
            # Copying ttl will change if headers which include TTL and
            # are moved or any TTL copying, VLAN's don't have TTL
            "COPY_TTL_OUT": set_ttl - set(("COPY_TTL_OUT",)),
            "COPY_TTL_IN": set_ttl - set(("COPY_TTL_IN",)),
            "SET_MPLS_TTL": set(("PUSH_MPLS", "POP_MPLS", "SET_MPLS_TTL")),
            "DEC_MPLS_TTL": set_ttl - set(("DEC_MPLS_TLL", "SET_NW_TTL",
                                           "DEC_NW_TTL")),
            # TODO XXX If I care enough the OpenFlow 1.3 spec seems to say
            # in release notes tags are put in there outermost valid position
            # Then goes on to say that VLAN's are placed straight after the
            # ethernet header, but MPLS's are placed directly before the IP
            # and any other MPLS tag.
            # Is this because you are not allowed to put a MPLS before a VLAN
            # or a typo? I'll assume it is right for now!
            # Note a PBB also gets placed directly after the ethernet.
            # PBB also pushes the VLAN PCP into the I-SID pcp
            "PUSH_VLAN": set(("PUSH_VLAN", "POP_VLAN", "PUSH_PBB", "POP_PBB")),
            "POP_VLAN": set(("PUSH_VLAN", "PUSH_PBB")),
            # MPLS will copy in the TTL from IP or MPLS
            # Therefore all TTL operations must happen in order
            "PUSH_MPLS": set_ttl,
            "POP_MPLS": set_ttl,
            "SET_QUEUE": set(("SET_QUEUE",)),  # Cannot be reordered
            # Right now you cannot have 2 IP headers (I think)
            # As such copy out does not screw up this field
            "SET_NW_TTL": set(("SET_NW_TTL", "COPY_TTL_IN")),
            "DEC_NW_TTL": set(("SET_NW_TTL", "COPY_TTL_IN")),
            "SET_FIELD": set(),  # We do this per field
            # Eth src and dst are copied in, along with any existing vlan pcp
            "PUSH_PBB": set(("PUSH_PBB", "PUSH_VLAN", "POP_VLAN", "POP_PBB",
                             S("ETH_SRC"), S("ETH_DST"), S("VLAN_PCP"))),
            "POP_PBB": set(("PUSH_PBB", "PUSH_VLAN")),
            S("IN_PORT"): set((S("IN_PORT"),)),  # Not valid to set
            S("IN_PHY_PORT"): set((S("IN_PHY_PORT"),)),  # Not valid to set
            # Not valid to set METADATA (USE the instruction)
            S("METADATA"): set((S("METADATA"),)),
            S("ETH_DST"): set(("POP_PBB", "PUSH_PBB", S("ETH_DST"))),
            S("ETH_SRC"): set(("POP_PBB", "PUSH_PBB", S("ETH_SRC"))),
            # I dont think ETH_TYPE is settable
            S("ETH_TYPE"): set(("POP_PBB", "PUSH_PBB", S("ETH_TYPE"),
                                "PUSH_MPLS", "POP_MPLS", "POP_VLAN",
                                "PUSH_VLAN")),
            S("VLAN_VID"): set((S("VLAN_VID"), "PUSH_VLAN", "POP_VLAN")),
            S("VLAN_PCP"): set((S("VLAN_PCP"), "PUSH_VLAN", "POP_VLAN",
                                "PUSH_PBB")),
            S("IP_DSCP"): set((S("IP_DSCP"),)),
            S("IP_ECN"): set((S("IP_ECN"),)),
            S("IP_PROTO"): set((S("IP_PROTO"),)),
            S("IPV4_SRC"): set((S("IPV4_SRC"),)),
            S("IPV4_DST"): set((S("IPV4_DST"),)),
            S("TCP_SRC"): set((S("TCP_SRC"),)),
            S("TCP_DST"): set((S("TCP_DST"),)),
            S("UDP_SRC"): set((S("UDP_SRC"),)),
            S("UDP_DST"): set((S("UDP_DST"),)),
            S("SCTP_SRC"): set((S("SCTP_SRC"),)),
            S("SCTP_DST"): set((S("SCTP_DST"),)),
            S("ICMPV4_TYPE"): set((S("ICMPV4_TYPE"),)),
            S("ICMPV4_CODE"): set((S("ICMPV4_CODE"),)),
            S("ARP_OP"): set((S("ARP_OP"),)),
            S("ARP_SPA"): set((S("ARP_SPA"),)),
            S("ARP_TPA"): set((S("ARP_TPA"),)),
            S("ARP_SHA"): set((S("ARP_SHA"),)),
            S("ARP_THA"): set((S("ARP_THA"),)),
            S("IPV6_SRC"): set((S("IPV6_SRC"),)),
            S("IPV6_DST"): set((S("IPV6_DST"),)),
            S("IPV6_FLABEL"): set((S("IPV6_FLABEL"),)),
            S("ICMPV6_TYPE"): set((S("ICMPV6_TYPE"),)),
            S("ICMPV6_CODE"): set((S("ICMPV6_CODE"),)),
            S("IPV6_ND_TARGET"): set((S("IPV6_ND_TARGET"),)),
            S("IPV6_ND_SLL"): set((S("IPV6_ND_SLL"),)),
            S("IPV6_ND_TLL"): set((S("IPV6_ND_TLL"),)),
            S("MPLS_LABEL"): set((S("MPLS_LABEL"), "PUSH_MPLS", "POP_MPLS")),
            S("MPLS_TC"): set((S("MPLS_TC"), "PUSH_MPLS", "POP_MPLS")),
            S("MPLS_BOS"): set((S("MPLS_BOS"), "PUSH_MPLS", "POP_MPLS")),
            S("PBB_ISID"): set((S("PBB_ISID"), "PUSH_PBB", "POP_PBB")),
            S("TUNNEL_ID"): set((S("TUNNEL_ID"),)),  # Unsure if can set this?
            S("IPV6_EXTHDR"): set((S("IPV6_EXTHDR"),)),
        }

        self.ofp_port_no = {
            'OFPP_MAX': 0xffffff00,
            'OFPP_IN_PORT': 0xfffffff8,
            'OFPP_TABLE': 0xfffffff9,
            'OFPP_NORMAL': 0xfffffffa,
            'OFPP_FLOOD': 0xfffffffb,
            'OFPP_ALL': 0xfffffffc,
            'OFPP_CONTROLLER': 0xfffffffd,
            'OFPP_LOCAL': 0xfffffffe,
            'OFPP_ANY': 0xffffffff
        }

        self.ofp_type = {
            'OFPT_HELLO': 0,
            'OFPT_ERROR': 1,
            'OFPT_ECHO_REQUEST': 2,
            'OFPT_ECHO_REPLY': 3,
            'OFPT_EXPERIMENTER': 4,
            'OFPT_FEATURES_REQUEST': 5,
            'OFPT_FEATURES_REPLY': 6,
            'OFPT_GET_CONFIG_REQUEST': 7,
            'OFPT_GET_CONFIG_REPLY': 8,
            'OFPT_SET_CONFIG': 9,
            'OFPT_PACKET_IN': 10,
            'OFPT_FLOW_REMOVED': 11,
            'OFPT_PORT_STATUS': 12,
            'OFPT_PACKET_OUT': 13,
            'OFPT_FLOW_MOD': 14,
            'OFPT_GROUP_MOD': 15,
            'OFPT_PORT_MOD': 16,
            'OFPT_TABLE_MOD': 17,
            'OFPT_MULTIPART_REQUEST': 18,
            'OFPT_MULTIPART_REPLY': 19,
            'OFPT_BARRIER_REQUEST': 20,
            'OFPT_BARRIER_REPLY': 21,
            'OFPT_QUEUE_GET_CONFIG_REQUEST': 22,
            'OFPT_QUEUE_GET_CONFIG_REPLY': 23,
            'OFPT_ROLE_REQUEST': 24,
            'OFPT_ROLE_REPLY': 25,
            'OFPT_GET_ASYNC_REQUEST': 26,
            'OFPT_GET_ASYNC_REPLY': 27,
            'OFPT_SET_ASYNC': 28,
            'OFPT_METER_MOD': 29
        }

        self.ofp_hello_elem_type = {
            'OFPHET_VERSIONBITMAP': 1
        }

        self.ofp_config_flags = {
            'OFPC_FRAG_NORMAL': 0,
            'OFPC_FRAG_DROP': 1 << 0,
            'OFPC_FRAG_REASM': 1 << 1,
            'OFPC_FRAG_MASK': 3,
        }

        self.ofp_table_config = {
            'OFPTC_DEPRECATED_MASK': 3
        }

        self.ofp_table = {
            'OFPTT_MAX': 0xfe,
            'OFPTT_ALL': 0xff
        }

        self.ofp_capabilities = {
            'OFPC_FLOW_STATS': 1 << 0,
            'OFPC_TABLE_STATS': 1 << 1,
            'OFPC_PORT_STATS': 1 << 2,
            'OFPC_GROUP_STATS': 1 << 3,
            'OFPC_IP_REASM': 1 << 5,
            'OFPC_QUEUE_STATS': 1 << 6,
            'OFPC_PORT_BLOCKED': 1 << 8,
        }

        self.ofp_port_config = {
            'OFPPC_PORT_DOWN': 1 << 0,
            'OFPPC_NO_RECV': 1 << 2,
            'OFPPC_NO_FWD': 1 << 5,
            'OFPPC_NO_PACKET_IN': 1 << 6
        }

        self.ofp_port_state = {
            'OFPPS_LINK_DOWN': 1 << 0,
            'OFPPS_BLOCKED': 1 << 1,
            'OFPPS_LIVE': 1 << 2,
        }

        self.ofp_port_features = {
            'OFPPF_10MB_HD': 1 << 0,
            'OFPPF_10MB_FD': 1 << 1,
            'OFPPF_100MB_HD': 1 << 2,
            'OFPPF_100MB_FD': 1 << 3,
            'OFPPF_1GB_HD': 1 << 4,
            'OFPPF_1GB_FD': 1 << 5,
            'OFPPF_10GB_FD': 1 << 6,
            'OFPPF_40GB_FD': 1 << 7,
            'OFPPF_100GB_FD': 1 << 8,
            'OFPPF_1TB_FD': 1 << 9,
            'OFPPF_OTHER': 1 << 10,
            'OFPPF_COPPER': 1 << 11,
            'OFPPF_FIBER': 1 << 12,
            'OFPPF_AUTONEG': 1 << 13,
            'OFPPF_PAUSE': 1 << 14,
            'OFPPF_PAUSE_ASYM': 1 << 15,
        }

        self.ofp_match_type = {
            'OFPMT_STANDARD': 0,
            'OFPMT_OXM': 1,
        }

        self.ofp_port_reason = {
            'OFPPR_ADD': 0,
            'OFPPR_DELETE': 1,
            'OFPPR_MODIFY': 2,
        }

        self.ofp_oxm_class = {
            'OFPXMC_NXM_0': 0x0000,
            'OFPXMC_NXM_1': 0x0001,
            'OFPXMC_OPENFLOW_BASIC': 0x8000,
            'OFPXMC_EXPERIMENTER': 0xFFFF,
        }

        self.oxm_ofb_match_fields = {
            'OFPXMT_OFB_IN_PORT': 0,
            'OFPXMT_OFB_IN_PHY_PORT': 1,
            'OFPXMT_OFB_METADATA': 2,
            'OFPXMT_OFB_ETH_DST': 3,
            'OFPXMT_OFB_ETH_SRC': 4,
            'OFPXMT_OFB_ETH_TYPE': 5,
            'OFPXMT_OFB_VLAN_VID': 6,
            'OFPXMT_OFB_VLAN_PCP': 7,
            'OFPXMT_OFB_IP_DSCP': 8,
            'OFPXMT_OFB_IP_ECN': 9,
            'OFPXMT_OFB_IP_PROTO': 10,
            'OFPXMT_OFB_IPV4_SRC': 11,
            'OFPXMT_OFB_IPV4_DST': 12,
            'OFPXMT_OFB_TCP_SRC': 13,
            'OFPXMT_OFB_TCP_DST': 14,
            'OFPXMT_OFB_UDP_SRC': 15,
            'OFPXMT_OFB_UDP_DST': 16,
            'OFPXMT_OFB_SCTP_SRC': 17,
            'OFPXMT_OFB_SCTP_DST': 18,
            'OFPXMT_OFB_ICMPV4_TYPE': 19,
            'OFPXMT_OFB_ICMPV4_CODE': 20,
            'OFPXMT_OFB_ARP_OP': 21,
            'OFPXMT_OFB_ARP_SPA': 22,
            'OFPXMT_OFB_ARP_TPA': 23,
            'OFPXMT_OFB_ARP_SHA': 24,
            'OFPXMT_OFB_ARP_THA': 25,
            'OFPXMT_OFB_IPV6_SRC': 26,
            'OFPXMT_OFB_IPV6_DST': 27,
            'OFPXMT_OFB_IPV6_FLABEL': 28,
            'OFPXMT_OFB_ICMPV6_TYPE': 29,
            'OFPXMT_OFB_ICMPV6_CODE': 30,
            'OFPXMT_OFB_IPV6_ND_TARGET': 31,
            'OFPXMT_OFB_IPV6_ND_SLL': 32,
            'OFPXMT_OFB_IPV6_ND_TLL': 33,
            'OFPXMT_OFB_MPLS_LABEL': 34,
            'OFPXMT_OFB_MPLS_TC': 35,
            'OFPXMT_OFB_MPLS_BOS': 36,
            'OFPXMT_OFB_PBB_ISID': 37,
            'OFPXMT_OFB_TUNNEL_ID': 38,
            'OFPXMT_OFB_IPV6_EXTHDR': 39,
        }

        self.ofp_vlan_id = {
            'OFPVID_PRESENT': 0x1000,
            'OFPVID_NONE': 0x0000,
            'OFP_VLAN_NONE': 0x0000
        }

        self.ofp_ipv6exthdr_flags = {
            'OFPIEH_NONEXT': 1 << 0,
            'OFPIEH_ESP': 1 << 1,
            'OFPIEH_AUTH': 1 << 2,
            'OFPIEH_DEST': 1 << 3,
            'OFPIEH_FRAG': 1 << 4,
            'OFPIEH_ROUTER': 1 << 5,
            'OFPIEH_HOP': 1 << 6,
            'OFPIEH_UNREP': 1 << 7,
            'OFPIEH_UNSEQ': 1 << 8,
        }

        self.ofp_action_type = {
            'OFPAT_OUTPUT': 0,
            'OFPAT_COPY_TTL_OUT': 11,
            'OFPAT_COPY_TTL_IN': 12,
            'OFPAT_SET_MPLS_TTL': 15,
            'OFPAT_DEC_MPLS_TTL': 16,
            'OFPAT_PUSH_VLAN': 17,
            'OFPAT_POP_VLAN': 18,
            'OFPAT_PUSH_MPLS': 19,
            'OFPAT_POP_MPLS': 20,
            'OFPAT_SET_QUEUE': 21,
            'OFPAT_GROUP': 22,
            'OFPAT_SET_NW_TTL': 23,
            'OFPAT_DEC_NW_TTL': 24,
            'OFPAT_SET_FIELD': 25,
            'OFPAT_PUSH_PBB': 26,
            'OFPAT_POP_PBB': 27,
            'OFPAT_EXPERIMENTER': 0xffff,
        }

        self.ofp_controller_max_len = {
            'OFPCML_MAX': 0xffe5,
            'OFPCML_NO_BUFFER': 0xffff
        }

        self.ofp_instruction_type = {
            'OFPIT_GOTO_TABLE': 1,
            'OFPIT_WRITE_METADATA': 2,
            'OFPIT_WRITE_ACTIONS': 3,
            'OFPIT_APPLY_ACTIONS': 4,
            'OFPIT_CLEAR_ACTIONS': 5,
            'OFPIT_METER': 6,
            'OFPIT_EXPERIMENTER': 0xFFFF,
        }

        self.ofp_flow_mod_command = {
            'OFPFC_ADD': 0,
            'OFPFC_MODIFY': 1,
            'OFPFC_MODIFY_STRICT': 2,
            'OFPFC_DELETE': 3,
            'OFPFC_DELETE_STRICT': 4,
        }

        self.ofp_flow_mod_flags = {
            'OFPFF_SEND_FLOW_REM': 1 << 0,
            'OFPFF_CHECK_OVERLAP': 1 << 1,
            'OFPFF_RESET_COUNTS': 1 << 2,
            'OFPFF_NO_PKT_COUNTS': 1 << 3,
            'OFPFF_NO_BYT_COUNTS': 1 << 4,
        }

        self.ofp_group = {
            'OFPG_MAX': 0xffffff00,
            'OFPG_ALL': 0xfffffffc,
            'OFPG_ANY': 0xffffffff,
        }

        self.ofp_group_mod_command = {
            'OFPGC_ADD': 0,
            'OFPGC_MODIFY': 1,
            'OFPGC_DELETE': 2,
        }

        self.ofp_group_type = {
            'OFPGT_ALL': 0,
            'OFPGT_SELECT': 1,
            'OFPGT_INDIRECT': 2,
            'OFPGT_FF': 3,
        }

        self.ofp_packet_in_reason = {
            'OFPR_NO_MATCH': 0,
            'OFPR_ACTION': 1,
            'OFPR_INVALID_TTL': 2,
        }

        self.ofp_flow_removed_reason = {
            'OFPRR_IDLE_TIMEOUT': 0,
            'OFPRR_HARD_TIMEOUT': 1,
            'OFPRR_DELETE': 2,
            'OFPRR_GROUP_DELETE': 3,
        }

        self.ofp_meter = {
            'OFPM_MAX': 0xffff0000,
            'OFPM_SLOWPATH': 0xfffffffd,
            'OFPM_CONTROLLER': 0xfffffffe,
            'OFPM_ALL': 0xffffffff,
        }

        self.ofp_meter_band_type = {
            'OFPMBT_DROP': 1,
            'OFPMBT_DSCP_REMARK': 2,
            'OFPMBT_EXPERIMENTER': 0xFFFF,
        }

        self.ofp_meter_mod_command = {
            'OFPMC_ADD': 0,
            'OFPMC_MODIFY': 1,
            'OFPMC_DELETE': 2,
        }

        self.ofp_meter_flags = {
            'OFPMF_KBPS': 1 << 0,
            'OFPMF_PKTPS': 1 << 1,
            'OFPMF_BURST': 1 << 2,
            'OFPMF_STATS': 1 << 3,
        }

        self.ofp_error_type = {
            'OFPET_HELLO_FAILED': 0,
            'OFPET_BAD_REQUEST': 1,
            'OFPET_BAD_ACTION': 2,
            'OFPET_BAD_INSTRUCTION': 3,
            'OFPET_BAD_MATCH': 4,
            'OFPET_FLOW_MOD_FAILED': 5,
            'OFPET_GROUP_MOD_FAILED': 6,
            'OFPET_PORT_MOD_FAILED': 7,
            'OFPET_TABLE_MOD_FAILED': 8,
            'OFPET_QUEUE_OP_FAILED': 9,
            'OFPET_SWITCH_CONFIG_FAILED': 10,
            'OFPET_ROLE_REQUEST_FAILED': 11,
            'OFPET_METER_MOD_FAILED': 12,
            'OFPET_TABLE_FEATURES_FAILED': 13,
            'OFPET_EXPERIMENTER': 0xffff,
        }

        self.ofp_hello_failed_code = {
            'OFPHFC_INCOMPATIBLE': 0,
            'OFPHFC_EPERM': 1,
        }

        self.ofp_bad_request_code = {
            'OFPBRC_BAD_VERSION': 0,
            'OFPBRC_BAD_TYPE': 1,
            'OFPBRC_BAD_MULTIPART': 2,
            'OFPBRC_BAD_EXPERIMENTER': 3,
            'OFPBRC_BAD_EXP_TYPE': 4,
            'OFPBRC_EPERM': 5,
            'OFPBRC_BAD_LEN': 6,
            'OFPBRC_BUFFER_EMPTY': 7,
            'OFPBRC_BUFFER_UNKNOWN': 8,
            'OFPBRC_BAD_TABLE_ID': 9,
            'OFPBRC_IS_SLAVE': 10,
            'OFPBRC_BAD_PORT': 11,
            'OFPBRC_BAD_PACKET': 12,
            'OFPBRC_MULTIPART_BUFFER_OVERFLOW': 13,
        }

        self.ofp_bad_action_code = {
            'OFPBAC_BAD_TYPE': 0,
            'OFPBAC_BAD_LEN': 1,
            'OFPBAC_BAD_EXPERIMENTER': 2,
            'OFPBAC_BAD_EXP_TYPE': 3,
            'OFPBAC_BAD_OUT_PORT': 4,
            'OFPBAC_BAD_ARGUMENT': 5,
            'OFPBAC_EPERM': 6,
            'OFPBAC_TOO_MANY': 7,
            'OFPBAC_BAD_QUEUE': 8,
            'OFPBAC_BAD_OUT_GROUP': 9,
            'OFPBAC_MATCH_INCONSISTENT': 10,
            'OFPBAC_UNSUPPORTED_ORDER': 11,
            'OFPBAC_BAD_TAG': 12,
            'OFPBAC_BAD_SET_TYPE': 13,
            'OFPBAC_BAD_SET_LEN': 14,
            'OFPBAC_BAD_SET_ARGUMENT': 15,
        }

        self.ofp_bad_instruction_code = {
            'OFPBIC_UNKNOWN_INST': 0,
            'OFPBIC_UNSUP_INST': 1,
            'OFPBIC_BAD_TABLE_ID': 2,
            'OFPBIC_UNSUP_METADATA': 3,
            'OFPBIC_UNSUP_METADATA_MASK': 4,
            'OFPBIC_BAD_EXPERIMENTER': 5,
            'OFPBIC_BAD_EXP_TYPE': 6,
            'OFPBIC_BAD_LEN': 7,
            'OFPBIC_EPERM': 8,
        }

        self.ofp_bad_match_code = {
            'OFPBMC_BAD_TYPE': 0,
            'OFPBMC_BAD_LEN': 1,
            'OFPBMC_BAD_TAG': 2,
            'OFPBMC_BAD_DL_ADDR_MASK': 3,
            'OFPBMC_BAD_NW_ADDR_MASK': 4,
            'OFPBMC_BAD_WILDCARDS': 5,
            'OFPBMC_BAD_FIELD': 6,
            'OFPBMC_BAD_VALUE': 7,
            'OFPBMC_BAD_MASK': 8,
            'OFPBMC_BAD_PREREQ': 9,
            'OFPBMC_DUP_FIELD': 10,
            'OFPBMC_EPERM': 11,
        }

        self.ofp_flow_mod_failed_code = {
            'OFPFMFC_UNKNOWN': 0,
            'OFPFMFC_TABLE_FULL': 1,
            'OFPFMFC_BAD_TABLE_ID': 2,
            'OFPFMFC_OVERLAP': 3,
            'OFPFMFC_EPERM': 4,
            'OFPFMFC_BAD_TIMEOUT': 5,
            'OFPFMFC_BAD_COMMAND': 6,
            'OFPFMFC_BAD_FLAGS': 7,
        }

        self.ofp_group_mod_failed_code = {
            'OFPGMFC_GROUP_EXISTS': 0,
            'OFPGMFC_INVALID_GROUP': 1,
            'OFPGMFC_WEIGHT_UNSUPPORTED': 2,
            'OFPGMFC_OUT_OF_GROUPS': 3,
            'OFPGMFC_OUT_OF_BUCKETS': 4,
            'OFPGMFC_CHAINING_UNSUPPORTED': 5,
            'OFPGMFC_WATCH_UNSUPPORTED': 6,
            'OFPGMFC_LOOP': 7,
            'OFPGMFC_UNKNOWN_GROUP': 8,
            'OFPGMFC_CHAINED_GROUP': 9,
            'OFPGMFC_BAD_TYPE': 10,
            'OFPGMFC_BAD_COMMAND': 11,
            'OFPGMFC_BAD_BUCKET': 12,
            'OFPGMFC_BAD_WATCH': 13,
            'OFPGMFC_EPERM': 14,
        }

        self.ofp_port_mod_failed_code = {
            'OFPPMFC_BAD_PORT': 0,
            'OFPPMFC_BAD_HW_ADDR': 1,
            'OFPPMFC_BAD_CONFIG': 2,
            'OFPPMFC_BAD_ADVERTISE': 3,
            'OFPPMFC_EPERM': 4,
        }

        self.ofp_table_mod_failed_code = {
            'OFPTMFC_BAD_TABLE': 0,
            'OFPTMFC_BAD_CONFIG': 1,
            'OFPTMFC_EPERM': 2,
        }

        self.ofp_queue_op_failed_code = {
            'OFPQOFC_BAD_PORT': 0,
            'OFPQOFC_BAD_QUEUE': 1,
            'OFPQOFC_EPERM': 2,
        }

        self.ofp_switch_config_failed_code = {
            'OFPSCFC_BAD_FLAGS': 0,
            'OFPSCFC_BAD_LEN': 1,
            'OFPSCFC_EPERM': 2,
        }

        self.ofp_role_request_failed_code = {
            'OFPRRFC_STALE': 0,
            'OFPRRFC_UNSUP': 1,
            'OFPRRFC_BAD_ROLE': 2,
        }

        self.ofp_meter_mod_failed_code = {
            'OFPMMFC_UNKNOWN': 0,
            'OFPMMFC_METER_EXISTS': 1,
            'OFPMMFC_INVALID_METER': 2,
            'OFPMMFC_UNKNOWN_METER': 3,
            'OFPMMFC_BAD_COMMAND': 4,
            'OFPMMFC_BAD_FLAGS': 5,
            'OFPMMFC_BAD_RATE': 6,
            'OFPMMFC_BAD_BURST': 7,
            'OFPMMFC_BAD_BAND': 8,
            'OFPMMFC_BAD_BAND_VALUE': 9,
            'OFPMMFC_OUT_OF_METERS': 10,
            'OFPMMFC_OUT_OF_BANDS': 11,
        }

        self.ofp_multipart_request_flags = {
            'OFPMPF_REQ_MORE': 1
        }

        self.ofp_multipart_reply_flags = {
            'OFPMPF_REPLY_MORE': 1
        }

        self.ofp_table_features_failed_code = {
            'OFPTFFC_BAD_TABLE': 0,
            'OFPTFFC_BAD_METADATA': 1,
            'OFPTFFC_BAD_TYPE': 2,
            'OFPTFFC_BAD_LEN': 3,
            'OFPTFFC_BAD_ARGUMENT': 4,
            'OFPTFFC_EPERM': 5,
        }

        self.ofp_multipart_type = {
            'OFPMP_DESC': 0,
            'OFPMP_FLOW': 1,
            'OFPMP_AGGREGATE': 2,
            'OFPMP_TABLE': 3,
            'OFPMP_PORT_STATS': 4,
            'OFPMP_QUEUE': 5,
            'OFPMP_GROUP': 6,
            'OFPMP_GROUP_DESC': 7,
            'OFPMP_GROUP_FEATURES': 8,
            'OFPMP_METER': 9,
            'OFPMP_METER_CONFIG': 10,
            'OFPMP_METER_FEATURES': 11,
            'OFPMP_TABLE_FEATURES': 12,
            'OFPMP_PORT_DESC': 13,
            'OFPMP_EXPERIMENTER': 0xffff,
        }

        self.ofp_table_feature_prop_type = {
            'OFPTFPT_INSTRUCTIONS': 0,
            'OFPTFPT_INSTRUCTIONS_MISS': 1,
            'OFPTFPT_NEXT_TABLES': 2,
            'OFPTFPT_NEXT_TABLES_MISS': 3,
            'OFPTFPT_WRITE_ACTIONS': 4,
            'OFPTFPT_WRITE_ACTIONS_MISS': 5,
            'OFPTFPT_APPLY_ACTIONS': 6,
            'OFPTFPT_APPLY_ACTIONS_MISS': 7,
            'OFPTFPT_MATCH': 8,
            'OFPTFPT_WILDCARDS': 10,
            'OFPTFPT_WRITE_SETFIELD': 12,
            'OFPTFPT_WRITE_SETFIELD_MISS': 13,
            'OFPTFPT_APPLY_SETFIELD': 14,
            'OFPTFPT_APPLY_SETFIELD_MISS': 15,
            'OFPTFPT_EXPERIMENTER': 0xFFFE,
            'OFPTFPT_EXPERIMENTER_MISS': 0xFFFF,
        }

        self.ofp_group_capabilities = {
            'OFPGFC_SELECT_WEIGHT': 1 << 0,
            'OFPGFC_SELECT_LIVENESS': 1 << 1,
            'OFPGFC_CHAINING': 1 << 2,
            'OFPGFC_CHAINING_CHECKS': 1 << 3,
        }

        self.ofp_queue_properties = {
            'OFPQT_MIN_RATE': 1,
            'OFPQT_MAX_RATE': 2,
            'OFPQT_EXPERIMENTER': 0xffff,
        }

        self.ofp_controller_role = {
            'OFPCR_ROLE_NOCHANGE': 0,
            'OFPCR_ROLE_EQUAL': 1,
            'OFPCR_ROLE_MASTER': 2,
            'OFPCR_ROLE_SLAVE': 3,
        }

        self.ofp_top_level = {
            'OFP_VERSION': 0x04,
            'OFP_MAX_TABLE_NAME_LEN': 32,
            'OFP_MAX_PORT_NAME_LEN': 16,
            'OFP_TCP_PORT': 6653,
            'OFP_SSL_PORT': 6653,
            'OFP_ETH_ALEN': 6,
            'OFP_DEFAULT_MISS_SEND_LEN': 128,
            'OFPXMT_OFB_ALL': (1 << 40) - 1,
            'OFP_FLOW_PERMANENT': 0,
            'OFP_DEFAULT_PRIORITY': 0x8000,
            'OFPQ_ALL': 0xffffffff,
            'OFPQ_MIN_RATE_UNCFG': 0xffff,
            'OFPQ_MAX_RATE_UNCFG': 0xffff,
        }

        ofp_all = [
            self.ofp_port_no, self.ofp_type, self.ofp_hello_elem_type,
            self.ofp_config_flags, self.ofp_table, self.ofp_capabilities,
            self.ofp_port_config, self.ofp_port_state, self.ofp_port_features,
            self.ofp_port_reason, self.ofp_match_type, self.ofp_oxm_class,
            self.oxm_ofb_match_fields, self.ofp_vlan_id,
            self.ofp_ipv6exthdr_flags, self.ofp_action_type,
            self.ofp_controller_max_len, self.ofp_instruction_type,
            self.ofp_flow_mod_command, self.ofp_flow_mod_flags, self.ofp_group,
            self.ofp_group_mod_command, self.ofp_group_type,
            self.ofp_packet_in_reason, self.ofp_flow_removed_reason,
            self.ofp_meter, self.ofp_meter_band_type,
            self.ofp_meter_mod_command, self.ofp_meter_flags,
            self.ofp_error_type, self.ofp_hello_failed_code,
            self.ofp_bad_request_code, self.ofp_bad_action_code,
            self.ofp_bad_instruction_code, self.ofp_bad_match_code,
            self.ofp_flow_mod_failed_code, self.ofp_group_mod_failed_code,
            self.ofp_port_mod_failed_code, self.ofp_table_mod_failed_code,
            self.ofp_queue_op_failed_code, self.ofp_switch_config_failed_code,
            self.ofp_role_request_failed_code, self.ofp_meter_mod_failed_code,
            self.ofp_table_features_failed_code, self.ofp_multipart_type,
            self.ofp_multipart_request_flags, self.ofp_multipart_reply_flags,
            self.ofp_table_feature_prop_type, self.ofp_group_capabilities,
            self.ofp_queue_properties, self.ofp_controller_role,
            self.ofp_top_level]
        self.ofp_all = reduce(self.merge_dicts, ofp_all, {})
