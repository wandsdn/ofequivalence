""" A pure python version of Header Space bytearry/wildcard.
    The overhead is too great calling into C all the time and using
    classes. It is better and simpler to use the built-in python types.
    Either python's long or mpz from gmpy2 which has better performance.

    We use the same encoding as Header Space
    00 = z --- Empty match if set anywhere
    01 = 0 --- Match 0
    10 = 1 --- Match 1
    11 = x --- Match 0 or 1
    Every bit matched in a field is two bits as it is a ternary

    This is based on the hsa-python lib and has copies of functions in
    that code

    Fields are encoded into integers as follows

    MSB                                               LSB
    +--------+----------+---------+--------+-----------+
    | field4 |  field3  | field2  | field1 | pad xx... |
    +--------+----------+---------+--------+-----------+

    The padding is unnecessary, however was a double check against the
    original headerspace library which require byte aligned numbers.
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

import math
import resource
import six
from six import viewitems
from .openflow_desc import OpenFlow1_3_5


MB_LIMIT = 1500
orig_limits = resource.getrlimit(resource.RLIMIT_AS)
# This takes bytes
resource.setrlimit(resource.RLIMIT_AS, ((MB_LIMIT*(0x100000), orig_limits[1])))

G_OF = OpenFlow1_3_5()

fields_bit_width = 0
for field, desc in viewitems(G_OF.oxm_fields):
    fields_bit_width += desc[G_OF.INDEX_BITS]

bytes_needed = int(math.ceil(fields_bit_width/8.0))
extra_padding = bytes_needed*8 - fields_bit_width
assert extra_padding >= 0


try:
    from gmpy2 import mpz
    wc_const = mpz
    wc_class = mpz(0).__class__
except ImportError:
    if six.PY2:
        wc_const = long
        wc_class = long
    else:
        wc_const = int
        wc_class = int

ODD_MASKS = None  # Mask with odd bits set
EVEN_MASKS = None  # Mask with even bits set
def _generate_masks():
    """ Generates the lists of EVEN and ODD masks """
    global ODD_MASKS
    global EVEN_MASKS
    ODD_MASKS = []
    odd_mask = wc_const(0)
    for _ in range(2024):
        ODD_MASKS.append(odd_mask)
        odd_mask <<= 2
        odd_mask |= 1
    ODD_MASKS = tuple(ODD_MASKS)
    EVEN_MASKS = tuple([x << 1 for x in ODD_MASKS])

_generate_masks()


def wildcard_intersect(first, second):
    """ Returns the intersection of two wildcards """
    ret = first & second
    if ~ret & (~ret >> 1) & ODD_MASKS[bytes_needed*8]:
        ret = wc_const(0)
    return ret


def wildcard_is_subset(first, second):
    """ Check if first is a subset of second. """
    # We ask the question does the first wildcard include packets not in the
    # second? If that is ever true for any tbit then it cannot be a subset.
    return not (first & ~second)


def wildcard_union_cover(left, right):
    """ A bitwise union of headerspace, in which a 0 and 1 will combine to x

        Not expecting any z positions

        Used to find those non x bits, as these are set to specific
        values in all cases.
    """
    return left | right


def wc_int_to_string(tint):
    """ tint: The ternary integer for (we'll really a quaternary however
              we don't expect a z)
    """
    as_str = ""
    while tint:
        part = tint & 3
        assert part
        if part == 1:
            as_str += '0'
        elif part == 2:
            as_str += '1'
        else:
            assert part == 3
            as_str += 'x'
        tint >>= 2
    as_str = as_str[::-1]
    return as_str


def swap_bit_position(wc, bit):
    assert bit >= 0
    # Offset by one, 1 index!!!
    byte = int(bit/8) + 1
    b_offset = 14 - (bit % 8) * 2
    gotten = wc[byte]

    current_value = ((0x3 << b_offset) & gotten) >> b_offset
    # turn it off
    gotten = (~(0x3 << b_offset)) & gotten
    if current_value == 0x1:
        # set 0 to 1
        gotten = 0x2 << b_offset | gotten
    else:
        # set 1 to 0
        assert current_value == 0x2
        gotten = 0x1 << b_offset | gotten
    wc[byte] = gotten


def find_smallest_set_bit(wc):
    """ Returns the smallest left most bit set

        0x0100xx returns 2, xx10x100 returns 0

        xxxxxxxx returns -1 (no small bits)
    """
    tint = wildcard_to_tint(wc)
    as_str = wc_int_to_string(tint)
    last_bit_set = max(as_str.rfind('0'), as_str.rfind('1'))
    swap_bit_position(wc, len(as_str) - last_bit_set - 1)
    if last_bit_set == -1:
        return -1
    else:
        return len(as_str) - last_bit_set - 1


def wildcard_to_tint(wc):
    if isinstance(wc, (wc_class)):
        # verify the padding
        if extra_padding:
            mask = (1 << (extra_padding*2)) - 1
            assert mask & wc == mask
            wc >>= extra_padding*2
        return wc
    full_tint = 0
    assert len(wc) == bytes_needed
    # We have to build this in reverse, so read in reverse
    for x in reversed(range(0, len(wc))):
        full_tint <<= 16
        full_tint |= wc[x]

    # verify the padding
    if extra_padding:
        mask = (1 << (extra_padding*2)) - 1
        assert mask & full_tint == mask
        full_tint >>= extra_padding*2

    return full_tint


def compress_wildcard_list(l):
    pop_index = []
    for i in range(len(l)):
        for j in range(i + 1, len(l)):
            if wildcard_is_subset(l[i], l[j]):
                pop_index.append(i)
            elif wildcard_is_subset(l[j], l[i]):
                pop_index.append(j)
    result = []
    for k in range(len(l)):
        if k not in pop_index:
            result.append(l[k])
    return result


MortonTable256 = [
    0x0000, 0x0001, 0x0004, 0x0005, 0x0010, 0x0011, 0x0014, 0x0015,
    0x0040, 0x0041, 0x0044, 0x0045, 0x0050, 0x0051, 0x0054, 0x0055,
    0x0100, 0x0101, 0x0104, 0x0105, 0x0110, 0x0111, 0x0114, 0x0115,
    0x0140, 0x0141, 0x0144, 0x0145, 0x0150, 0x0151, 0x0154, 0x0155,
    0x0400, 0x0401, 0x0404, 0x0405, 0x0410, 0x0411, 0x0414, 0x0415,
    0x0440, 0x0441, 0x0444, 0x0445, 0x0450, 0x0451, 0x0454, 0x0455,
    0x0500, 0x0501, 0x0504, 0x0505, 0x0510, 0x0511, 0x0514, 0x0515,
    0x0540, 0x0541, 0x0544, 0x0545, 0x0550, 0x0551, 0x0554, 0x0555,
    0x1000, 0x1001, 0x1004, 0x1005, 0x1010, 0x1011, 0x1014, 0x1015,
    0x1040, 0x1041, 0x1044, 0x1045, 0x1050, 0x1051, 0x1054, 0x1055,
    0x1100, 0x1101, 0x1104, 0x1105, 0x1110, 0x1111, 0x1114, 0x1115,
    0x1140, 0x1141, 0x1144, 0x1145, 0x1150, 0x1151, 0x1154, 0x1155,
    0x1400, 0x1401, 0x1404, 0x1405, 0x1410, 0x1411, 0x1414, 0x1415,
    0x1440, 0x1441, 0x1444, 0x1445, 0x1450, 0x1451, 0x1454, 0x1455,
    0x1500, 0x1501, 0x1504, 0x1505, 0x1510, 0x1511, 0x1514, 0x1515,
    0x1540, 0x1541, 0x1544, 0x1545, 0x1550, 0x1551, 0x1554, 0x1555,
    0x4000, 0x4001, 0x4004, 0x4005, 0x4010, 0x4011, 0x4014, 0x4015,
    0x4040, 0x4041, 0x4044, 0x4045, 0x4050, 0x4051, 0x4054, 0x4055,
    0x4100, 0x4101, 0x4104, 0x4105, 0x4110, 0x4111, 0x4114, 0x4115,
    0x4140, 0x4141, 0x4144, 0x4145, 0x4150, 0x4151, 0x4154, 0x4155,
    0x4400, 0x4401, 0x4404, 0x4405, 0x4410, 0x4411, 0x4414, 0x4415,
    0x4440, 0x4441, 0x4444, 0x4445, 0x4450, 0x4451, 0x4454, 0x4455,
    0x4500, 0x4501, 0x4504, 0x4505, 0x4510, 0x4511, 0x4514, 0x4515,
    0x4540, 0x4541, 0x4544, 0x4545, 0x4550, 0x4551, 0x4554, 0x4555,
    0x5000, 0x5001, 0x5004, 0x5005, 0x5010, 0x5011, 0x5014, 0x5015,
    0x5040, 0x5041, 0x5044, 0x5045, 0x5050, 0x5051, 0x5054, 0x5055,
    0x5100, 0x5101, 0x5104, 0x5105, 0x5110, 0x5111, 0x5114, 0x5115,
    0x5140, 0x5141, 0x5144, 0x5145, 0x5150, 0x5151, 0x5154, 0x5155,
    0x5400, 0x5401, 0x5404, 0x5405, 0x5410, 0x5411, 0x5414, 0x5415,
    0x5440, 0x5441, 0x5444, 0x5445, 0x5450, 0x5451, 0x5454, 0x5455,
    0x5500, 0x5501, 0x5504, 0x5505, 0x5510, 0x5511, 0x5514, 0x5515,
    0x5540, 0x5541, 0x5544, 0x5545, 0x5550, 0x5551, 0x5554, 0x5555
    ]


def morton_number(a, b):
    """ Interlace a and b's bits together a in evens, b in odds
        aa, bb -> baba
    """
    res = MortonTable256[b & 0xFF] << 1 | MortonTable256[a & 0xFF]
    if (a | b) > 0xFF:
        res |= morton_number(a >> 8, b >> 8) << 16
    return res

try:
    from ._utils import morton_number
except:
    print("Failed to load c morton_number")

WC_FULLWC = (wc_const(1) << (bytes_needed*16))-1
WC_FIELD_OFFSET = {}  # Offset of the field in the wc from the LSB


def build_field_offset():
    offset = extra_padding
    for field in reversed(G_OF.ordered_oxm_fields):
        WC_FIELD_OFFSET[field] = offset
        desc = G_OF.oxm_fields[field]
        offset += desc[G_OF.INDEX_BITS]
build_field_offset()


def flow_matches_to_wildcard(matches):
    wc = WC_FULLWC
    for field, value in viewitems(matches):
        try:
            desc = G_OF.oxm_fields[field]
        except:
            continue
        bit_width = desc[G_OF.INDEX_BITS]*2
        value, mask, _ = value
        wmask = (1 << (bit_width)) - 1
        if mask is None:
            mask = wmask
        # wc <<= bit_width*2
        wc &= ((morton_number((~value | ~mask) & wmask,
                              (value | ~mask) & wmask) <<
                (WC_FIELD_OFFSET[field]*2)) |
               (~(wmask << (WC_FIELD_OFFSET[field] * 2))))
    # assert wc == flow_matches_to_wildcard2(matches)
    return wc


def flow_wildcard_to_string(wc):
    res = []
    # This is a ternary int
    full_tint = wildcard_to_tint(wc)
    bits = 0
    # We have to do everything backwards!!
    for field in reversed(G_OF.ordered_oxm_fields):
        desc = G_OF.oxm_fields[field]
        length = desc[G_OF.INDEX_BITS]
        mask = (1 << (length*2)) - 1
        bits += length
        value = mask & full_tint
        full_tint >>= length*2
        as_str = ""
        while value:
            part = value & 3
            assert part
            if part == 1:
                as_str += '0'
            elif part == 2:
                as_str += '1'
            else:
                assert part == 3
                as_str += 'x'
            value >>= 2
        as_str = as_str[::-1]
        res.append(field + '=' + as_str)
    assert bits == fields_bit_width
    return ", ".join(res)


def flow_wildcard_zero():
    """ Returns a wildcard with all bits set to zero """
    return ODD_MASKS[bytes_needed*8] | (1 << (extra_padding*2))-1


def flow_wildcard_one():
    """ Returns a wildcard with all bits set to one """
    return EVEN_MASKS[bytes_needed*8] | (1 << (extra_padding*2))-1


def get_wildcard_mask(wc):
    """ Returns a unique full mask representation of the wildcard """
    return (wc & (wc >> 1)) & ODD_MASKS[bytes_needed*8]


RMortonTable256 = []


def _make_RMortonTable256():
    for x in range(2**16):
        a = x & 0x5555
        b = (x & 0xAAAA) >> 1
        a = (a | (a >> 1)) & 0x3333
        b = (b | (b >> 1)) & 0x3333
        a = (a | (a >> 2)) & 0x0f0f
        b = (b | (b >> 2)) & 0x0f0f
        a = (a | (a >> 4)) & 0x00ff
        b = (b | (b >> 4)) & 0x00ff
        RMortonTable256.append((a, b))
_make_RMortonTable256()


def RMorton(num):
    offset = 0
    a = 0
    b = 0
    while num:
        na, nb = RMortonTable256[num & 0xFFFF]
        a |= na << offset
        b |= nb << offset
        offset += 8
        num >>= 16
    return a, b

bit2field = []


def _fill_bit2field():
    for x in range(extra_padding):
        bit2field.append('NONE')
        bit2field.append('NONE')
    for field in reversed(G_OF.ordered_oxm_fields):
        for x in range(G_OF.oxm_fields[field][G_OF.INDEX_BITS]):
            bit2field.append(field)
            bit2field.append(field)

_fill_bit2field()

if "bit_scan0" in dir(wc_class):
    def flow_wildcard_to_fields(wc):
        """ Converts a wildcard to a list of fields

            wc: The wildcard
            return: A list of field tuples, (field name, value, mask).
        """
        res = []
        offset = wc.bit_scan0()
        while offset < bytes_needed*16:
            field = bit2field[offset]
            desc = G_OF.oxm_fields[field]
            length = desc[G_OF.INDEX_BITS]
            mask = ((1 << (length*2)) - 1)
            value = (wc >> (WC_FIELD_OFFSET[field]*2)) & mask
            assert value != mask
            a, b = RMorton(value)
            part_value = b & (a ^ b)
            part_mask = a ^ b
            if part_mask:
                # We care about this field:
                if part_mask == (1 << length) - 1:
                    # Fully masked, use None
                    res.append((field, part_value, None))
                else:
                    res.append((field, part_value, part_mask))
            offset = wc.bit_scan0(WC_FIELD_OFFSET[field]*2+length*2)
            # We wont have a zero in this, otherwise this is a zero set
        return res
else:
    def bit_scan0(i, offset):
        test = 0x1 << offset
        while True:
            if test & ~i:
                return offset
            test <<= 1
            offset += 1

    def flow_wildcard_to_fields(wc):
        res = []
        offset = bit_scan0(wc, 0)
        while offset < bytes_needed*16:
            field = bit2field[offset]
            desc = G_OF.oxm_fields[field]
            length = desc[G_OF.INDEX_BITS]
            mask = ((1 << (length*2)) - 1)
            value = (wc >> (WC_FIELD_OFFSET[field]*2)) & mask
            assert value != mask
            a, b = RMorton(value)
            part_value = b & (a ^ b)
            part_mask = a ^ b
            if part_mask:
                # We care about this field:
                if part_mask == (1 << length) - 1:
                    # Fully masked, use None
                    res.append((field, part_value, None))
                else:
                    res.append((field, part_value, part_mask))
            offset = bit_scan0(wc, WC_FIELD_OFFSET[field]*2+length*2)
            # We wont have a zero in this, otherwise this is a zero set
        return res


def flow_wildcard_to_flowmatches(wc, class_):
    """
    Turn a wildcard into flowmatches
    """
    fields = flow_wildcard_to_fields(wc)
    matches = class_()
    for match in fields:
        matches.append(*match)
    matches._wildcard = wc
    return matches


def flow_wildcard_read_field(wc, name):
    if len(wc) == 0:
        return None
    assert len(wc) == bytes_needed
    offset = extra_padding
    width = 0

    # verify the padding
    if extra_padding:
        padding = wc[0]
        mask = (1 << (extra_padding*2)) - 1
        assert mask & padding == mask

    for field in reversed(G_OF.ordered_oxm_fields):
        desc = G_OF.oxm_fields[field]
        length = desc[G_OF.INDEX_BITS]
        if field == name:
            width = length
            break
        else:
            offset += length
    else:
        assert "Bad name requested" == 0
        return None

    # So we want to read out at offset of size width, but we are reversed
    # and we also need to ensure alignment is correct"
    start_byte = int(offset/8)
    end_byte = int(math.ceil((offset+width)/8.0))
    tint = 0
    mask = (1 << (width*2)) - 1
    for x in reversed(range(start_byte, end_byte)):
        tint <<= 16
        print(x)
        tint |= wc[x]

    end_bit_offset = int(math.ceil((offset+width)/8.0))*8 - (offset+width)
    if end_bit_offset:
        tint >>= end_bit_offset * 2
    tint &= mask
    as_str = ""
    while tint:
        part = tint & 3
        assert part
        if part == 1:
            as_str += '0'
        elif part == 2:
            as_str += '1'
        else:
            assert part == 3
            as_str += 'x'
        tint >>= 2
    as_str = as_str[::-1]
    return as_str


class headerspace(object):

    def __init__(self):
        self.hs_list = []
        self.hs_diff = []
        self.lazy_rules = []
        self.applied_rules = []

    def add_hs(self, wc):
        if wc.__class__ == wc_class:
            self.hs_list.append(wc)
            self.hs_diff.append([])
        elif wc.__class__ == headerspace:
            assert 0
            pass

    def copy(self):
        c = headerspace()
        c.hs_list = list(self.hs_list)
        c.hs_diff = [list(x) for x in self.hs_diff]
        c.applied_rules = list(self.applied_rules)
        c.lazy_rules = [list(x) for x in self.lazy_rules]
        return c

    def copy_intersect(self, other):
        cpy = self.copy()
        cpy.intersect(other)
        return cpy

    def intersect(self, other):
        if other.__class__ == headerspace:
            new_hs_list = []
            new_hs_diff = []
            for i in range(len(self.hs_list)):
                for j in range(len(other.hs_list)):
                    isect = wildcard_intersect(self.hs_list[i],
                                               other.hs_list[j])
                    if isect != 0:
                        new_hs_list.append(isect)
                        diffs = []
                        for diff_hs in self.hs_diff[i]:
                            diff_isect = wildcard_intersect(isect, diff_hs)
                            if diff_isect != 0:
                                diffs.append(diff_isect)
                        for diff_hs in other.hs_diff[j]:
                            diff_isect = wildcard_intersect(isect, diff_hs)
                            if diff_isect != 0:
                                diffs.append(diff_isect)
                        new_hs_diff.append(diffs)
            self.hs_list = new_hs_list
            self.hs_diff = new_hs_diff
        else:
            assert 0

    def is_empty(self):
        return len(self.hs_list) == 0

    def diff_hs(self, other):
        if other.__class__ == wc_class:
            for i in range(len(self.hs_list)):
                insect = wildcard_intersect(self.hs_list[i], other)
                if insect != 0:
                    self.hs_diff[i].append(insect)
        else:
            assert 0

    def clean_up(self):
        new_hs_list = []
        new_hs_diff = []
        for i in range(len(self.hs_list)):
            flag = False
            for dh in self.hs_diff[i]:
                if wildcard_is_subset(self.hs_list[i], dh):
                    flag = True
            if not flag:
                new_hs_list.append(self.hs_list[i])
                new_hs_diff.append(compress_wildcard_list(self.hs_diff[i]))

        self.hs_list = new_hs_list
        self.hs_diff = new_hs_diff
