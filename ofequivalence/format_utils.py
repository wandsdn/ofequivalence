"""
Convert between human-readable strings and numeric representations

This includes conversion to and from network types like
IPv4, IPv6, Ethernet formats.
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
import re

import six


def format_decimal(value, mask):
    """ Format an integer as a decimal string """
    if mask is None:
        return str(value)
    return "{:d}/{:d}".format(value, mask)


def format_hex(value, mask):
    """ Format an integer as a hexadecimal string """
    if mask is None:
        return "0x{:x}".format(value)
    return "0x{:x}/0x{:x}".format(value, mask)


def format_ethernet(value, mask):
    """ Format an integer as a Ethernet string """
    value_ether = ":".join(re.findall('..', "{:012x}".format(value)))
    if mask is None:
        return value_ether
    value_mask = ":".join(re.findall('..', "{:012x}".format(mask)))
    return "{}/{}".format(value_ether, value_mask)


def format_ipv6(value, mask):
    """ Format an integer as a IPv6 string """
    value_ipv6 = ":".join(re.findall('..', "{:032x}".format(value)))
    if mask is None:
        return value_ipv6
    value_mask = ":".join(re.findall('..', "{:032x}".format(mask)))
    return "{}/{}".format(value_ipv6, value_mask)


def format_ipv4(value, mask=None):
    """ Format an integer as a IPv4 string """
    value_ipv4 = ".".join([str(int(x, 16)) for x in re.findall('..', "{:08x}".format(value))])
    if mask is None:
        return value_ipv4
    value_mask = ".".join([str(int(x, 16)) for x in re.findall('..', "{:08x}".format(mask))])
    return "{}/{}".format(value_ipv4, value_mask)


# Match with the types labeled in openflow_desc
FORMATTERS = {
    "decimal": format_decimal,
    "hex": format_hex,
    "ethernet": format_ethernet,
    "ipv6": format_ipv6,
    "ipv4": format_ipv4,
}


def normalise_bytes(value):
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


def normalise_string(value):
    """ Normalises a network string to an int """
    try:
        return int(value, 0)
    except ValueError:
        return normalise_bytes(value)
