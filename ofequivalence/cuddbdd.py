""" A CUDD based multi-terminal bdd representation.

    That is to say a through the bdd can result in any
    action. For example A, B, C or undefined (None).
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

import six
from .headerspace import (bytes_needed, flow_wildcard_to_flowmatches,
                          G_OF, WC_FIELD_OFFSET)
from .rule import Match
from . import _cudd
from ._cudd import BDD, BDDIterator, shared_size

IS_DIFFERING_TUPLE = ("DIFFERS", "This is different")


ACTION_MAPPING = {}
FACTION_TO_ACTION = {}
ACTION_COUNTER = 1
ACTION_MAPPING[IS_DIFFERING_TUPLE[1]] = ACTION_COUNTER
FACTION_TO_ACTION = {IS_DIFFERING_TUPLE[1]: IS_DIFFERING_TUPLE[0]}
TERM_TO_ACTION = {0: None, 1: IS_DIFFERING_TUPLE[0]}
ACTION_COUNTER += 1
BDD_INDEX_TO_FIELD = {}  # Node index to (field, bit) where bit [0] is the LSB
def _generate_bdd_index_to_field():
    # Note the headerspace bit order is reversed vs.
    # BDD index number
    # bit [0] is the LSB of the field
    max_offset = (bytes_needed * 8) - 1
    for field in WC_FIELD_OFFSET:
        offset = WC_FIELD_OFFSET[field]
        for bit in range(G_OF.oxm_fields[field].bits):
            BDD_INDEX_TO_FIELD[max_offset - (offset + bit)] = field, bit
_generate_bdd_index_to_field()

def wc_to_BDD(wc, action, f_action):
    """ Convert a wildcard to a BDD
    """
    global ACTION_COUNTER
    if not wc:
        return BDD()

    tot_bits = bytes_needed * 8
    # Find the terminal id
    if f_action in ACTION_MAPPING:
        t_id = ACTION_MAPPING[f_action]
    else:
        t_id = ACTION_COUNTER
        ACTION_MAPPING[f_action] = ACTION_COUNTER
        FACTION_TO_ACTION[f_action] = action
        TERM_TO_ACTION[ACTION_COUNTER] = action
        ACTION_COUNTER += 1
    if six.PY3:
        bdd = _cudd.wc_to_BDD(int(wc), t_id, tot_bits)
    else:
        bdd = _cudd.wc_to_BDD(long(wc), t_id, tot_bits)
    return bdd


def BDD_to_wcs(BDD):
    """ Returns a generator of (wildcard, action left, action right)

        BDD: A BDD, if created using BDD.subtract() both action left and right
             will be populated. If created using any other function only left
             will be populated, and action right will be none.

        action left/right: As passed into wc_to_BDD, or a special value
                           depending on the last operation.

        For example difference will not return the right action, and as a
        result could be smaller in size.
    """
    if not isinstance(BDD, _cudd.BDD):
        return tuple()
    bits = (bytes_needed * 8)-1
    return ((a, TERM_TO_ACTION[b], TERM_TO_ACTION[c]) for a, b, c in
                BDDIterator(BDD, Match().get_wildcard(), bits))


def BDD_to_matches(BDD):
    """ Returns a generator of (Match, action left, action right)

        The same as BDD_to_wcs, except Match are returned
    """
    return ((flow_wildcard_to_flowmatches(x, Match), y, z)
            for x, y, z in BDD_to_wcs(BDD))
