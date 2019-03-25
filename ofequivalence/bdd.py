""" A pure python multiple-terminal bdd representation.

    That is to say a path through the bdd can result in any
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

from lru import LRU
from .headerspace import bytes_needed, flow_wildcard_to_flowmatches
from .rule import Match


# Keep every node uniquely
NODE_CACHE = dict()
# Keep the 100,000 most recent merges we attempt
CACHE_SIZE = 100000
MERGE_CACHE = LRU(CACHE_SIZE)
INTERSECTION_CACHE = LRU(CACHE_SIZE)
DIFFERENCE_CACHE = LRU(CACHE_SIZE)
RULE_CACHE = LRU(CACHE_SIZE)
SUBTRACT_CACHE = LRU(CACHE_SIZE)


class BDD(object):
    terminals = None
    root = None

    def __init__(self):
        self.terminals = []

    def __add__(self, other):
        bdd = BDD()
        bdd.root = meld_recursive(self.root, other.root)
        return bdd

    def difference(self, other):
        bdd = BDD()
        bdd.root = difference_recursive(self.root, other.root)
        return bdd

    def subtract(self, other):
        bdd = BDD()
        bdd.root = subtract_recursive(self.root, other.root)
        return bdd

    def intersection(self, other):
        bdd = BDD()
        bdd.root = intersection_recursive(self.root, other.root)
        return bdd

    def walk(self, node=None, visited=None):
        if visited is None:
            visited = set()
        if node is None:
            node = self.root
            if node is None:
                return
        if id(node) in visited:
            return
        if node.zero is not None:
            for x in self.walk(node.zero, visited):
                yield x
        if node.one is not None:
            for x in self.walk(node.one, visited):
                yield x
        visited.add(id(node))
        yield node

    def to_dot(self):
        parts = ["graph BDD {"]

        for node in self.walk():
            if isinstance(node, BDDTermination):
                parts += ['n' + str(id(node)),
                          '[label="' + str(node.friendly) + '",shape=box];']
            else:
                parts += ['n' + str(id(node)),
                          '[label="' + str(node.num) + '",shape=circle];']
        for node in self.walk():
            if node.zero is not None:
                parts += ['n' + str(id(node)), "--", 'n' + str(id(node.zero)),
                          '[label=0,style=dashed];']
            if node.one is not None:
                parts += ['n' + str(id(node)), "--", 'n' + str(id(node.one)),
                          '[label=1];']
        parts.append("}")
        return " ".join(parts)

    def show(self):
        """ Write to a temporary dot file and display using evince.
            - Primarily for debugging purposes
        """
        from tempfile import NamedTemporaryFile
        from subprocess import Popen, PIPE
        import time
        with NamedTemporaryFile(prefix='pdf', delete=True) as x:
            p = Popen(['/usr/bin/dot', '-Tpdf', '-o', x.name], stdin=PIPE)
            p.communicate(self.to_dot())
            p.wait()
            Popen(['/usr/bin/evince', x.name])
            time.sleep(5)

    def __eq__(self, other):
        return id(self.root) == id(other.root)

    def __ne__(self, other):
        return id(self.root) != id(other.root)

    def __len__(self):
        return len(list(self.walk()))


class BDDNode(object):
    __slots__ = "num", "zero", "one", "has_none"

    def __init__(self, num, zero=None, one=None):
        assert zero is None or zero != one
        self.num = num
        self.zero = zero
        self.one = one
        self.has_none = (self.zero is None or self.zero.has_none or
                         self.one is None or self.one.has_none)

    def __eq__(self, other):
        return (other is not None and self.num == other.num and
                id(self.zero) == id(other.zero) and
                id(self.one) == id(other.one))

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.num, id(self.zero), id(self.one)))


class BDDTermination(object):
    __slots__ = "action", "friendly"
    num = 1000000000000
    zero = None
    one = None
    has_none = False

    def __init__(self, action, friendly):
        self.action = action
        self.friendly = friendly

    def __eq__(self, other):
        if not isinstance(other, BDDTermination):
            return False
        return self.action == other.action

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        # Right now actions are not hashable
        # However can be compared
        # TODO use a proper hash
        # Hash if we can else drop into 0
        try:
            return hash(self.action)
        except:
            try:
                return hash(self.friendly)
            except:
                return 0

    def __str__(self):
        return "Termination: " + self.friendly

    def __repr__(self):
        return "Termination: " + self.friendly


def check_ncache(n):
    """ n: The node number
    """
    if n in NODE_CACHE:
        return NODE_CACHE[n]
    else:
        NODE_CACHE[n] = n
        return n


def check_ncache_rm_dup(num, zero, one):
    """ num: The node number
        zero: The zero
        one: The one
    """
    if zero is one:
        return zero
    n = BDDNode(num, zero, one)
    r = NODE_CACHE.get(n)
    if r is None:
        NODE_CACHE[n] = n
        return n
    return r


def wc_to_BDD(wc, action, f_action):
    """ Convert a wildcard to a BDD
        wc: The ternary wildcard, excepted to be a number type
        action: The terminal action
        f_action: The friendly action, fallback for hash and comparison
    """
    bdd = BDD()
    if not wc:
        return bdd

    tot_bits = bytes_needed * 8
    mask = 0x3
    # Build up in reverse
    # Start with terminal
    cnode = check_ncache(BDDTermination(action, f_action))
    term = cnode

    # Does this exist? If so duplicate
    root = RULE_CACHE.get((wc, id(cnode)))
    if root is not None:
        bdd.root = root
        return bdd

    # As WC are encoded
    #       F1           F2   ...  Fn
    # |MSB ... LSB|MSB ... LSB|MSB ... LSB|
    # Ensure MSB nodes are in the first nodes at the top of the BDD
    # This improves performance and decreases memory/size as it
    # more naturally matches prefix matching than LSB first.
    for b, num in zip(range(0, tot_bits), reversed(range(0, tot_bits))):
        value = (wc >> (b*2)) & mask
        assert value != 0
        if value == 0x1:  # 0
            cnode = check_ncache(BDDNode(num, cnode, None))
        elif value == 0x2:  # 1
            cnode = check_ncache(BDDNode(num, None, cnode))
    bdd.root = cnode
    RULE_CACHE[(wc, id(term))] = cnode
    return bdd


def BDD_to_wcs(BDD):
    """ Returns a list of wildcard -> BDDTermination """
    bits = (bytes_needed * 8)-1  # Less as node numbers start at 0
    return list(_BDD_to_wcs(BDD.root, Match().get_wildcard(), bits))


def BDD_to_matches(BDD):
    return [flow_wildcard_to_flowmatches(x) for x, y in BDD_to_wcs(BDD)]


def _BDD_to_wcs(node, wc, bits):
    if isinstance(node, BDDTermination):
        yield (wc, node)
    if node is None:
        return
    if node.zero is not None:
        wcz = wc & ~(2 << ((bits-node.num)*2))
        for x in _BDD_to_wcs(node.zero, wcz, bits):
            yield x
    if node.one is not None:
        wco = wc & ~(1 << ((bits-node.num)*2))
        for x in _BDD_to_wcs(node.one, wco, bits):
            yield x


def meld_recursive(a, b):
    """ Melding two tables together.
        Nodes: A and B

        A custom version of Art of Comp. fasc1b Algorithm 37)

        The meld logic is: (a->a b->a')

                 [(v,  l & l', h & h') if v == v' ]
        a & a' = [(v,  l & a', h & h') if v < v'  ]
                 [(v', a & l', a & h') if v > v'  ]

        Where the operator & is:
            if a is None:
                return a'
            else:
                return a
        i.e. Fill the empty parts with a', but don't overwrite a.
    """
    # Termination condition
    if a is None:
        return b
    if b is None:
        return a
    if not a.has_none:
        return a

    c_key = (id(a), id(b))
    cached = MERGE_CACHE.get(c_key)
    if cached is not None:
        return cached

    # Both should be nodes, only b could be a terminal
    # because terminal has_none is False
    if a.num == b.num:
        r = check_ncache_rm_dup(a.num, meld_recursive(a.zero, b.zero),
                                meld_recursive(a.one, b.one))
        MERGE_CACHE[c_key] = r
        return r
    if a.num < b.num:
        assert a.num < BDDTermination.num
        r = check_ncache_rm_dup(a.num, meld_recursive(a.zero, b),
                                meld_recursive(a.one, b))
        MERGE_CACHE[c_key] = r
        return r
    else:
        assert a.num > b.num
        assert b.num < BDDTermination.num
        r = check_ncache_rm_dup(b.num, meld_recursive(a, b.zero),
                                meld_recursive(a, b.one))
        MERGE_CACHE[c_key] = r
        return r

IS_DIFFERING_TUPLE = ("DIFFERS", "This is different")
IS_DIFFERING = BDDTermination(*IS_DIFFERING_TUPLE)
NODE_CACHE[IS_DIFFERING] = IS_DIFFERING


def difference_recursive(a, b):
    """ Finds the difference between a and b
        If a == b return None
        else: return a

        Returns A BDD pointing paths to a IS_DIFFERING terminal.
    """
    if a is b:
        return None
    if a is None:
        return IS_DIFFERING
    if b is None:
        if a.num == BDDTermination.num:
            return IS_DIFFERING
    else:  # Both have values
        # If instance terminal return a?
        if a.num == BDDTermination.num and b.num == BDDTermination.num:
            return IS_DIFFERING

    c_key = (id(a), id(b))
    cached = DIFFERENCE_CACHE.get(c_key)
    if cached is not None:
        return cached

    # We need to walk down the tree to duplicate out the a side
    if b is None:  # And a is not terminating, or None
        r = check_ncache_rm_dup(a.num, difference_recursive(a.zero, b),
                                difference_recursive(a.one, b))
        DIFFERENCE_CACHE[c_key] = r
        return r

    if a.num == b.num:
        r = check_ncache_rm_dup(a.num, difference_recursive(a.zero, b.zero),
                                difference_recursive(a.one, b.one))
        DIFFERENCE_CACHE[c_key] = r
        return r
    if a.num < b.num:
        assert a.num < BDDTermination.num
        r = check_ncache_rm_dup(a.num, difference_recursive(a.zero, b),
                                difference_recursive(a.one, b))
        DIFFERENCE_CACHE[c_key] = r
        return r
    else:
        assert a.num > b.num
        assert b.num < BDDTermination.num
        r = check_ncache_rm_dup(b.num, difference_recursive(a, b.zero),
                                difference_recursive(a, b.one))
        DIFFERENCE_CACHE[c_key] = r
        return r


def subtract_recursive(a, b):
    """ Finds the difference between a and b
        If a == b return None
        else: return a

        Returns BDD of packets in A not in B, or have a different terminal.
    """
    if a is b:
        return None
    if a is None:
        return None
    if b is None:
        return a
    else:  # Both have values
        # If instance terminal return a?
        if a.num == BDDTermination.num and b.num == BDDTermination.num:
            return a

    c_key = (id(a), id(b))
    cached = SUBTRACT_CACHE.get(c_key)
    if cached is not None:
        return cached

    if a.num == b.num:
        r = check_ncache_rm_dup(a.num, subtract_recursive(a.zero, b.zero),
                                subtract_recursive(a.one, b.one))
        SUBTRACT_CACHE[c_key] = r
        return r
    if a.num < b.num:
        assert a.num < BDDTermination.num
        r = check_ncache_rm_dup(a.num, subtract_recursive(a.zero, b),
                                subtract_recursive(a.one, b))
        SUBTRACT_CACHE[c_key] = r
        return r
    else:
        assert a.num > b.num
        assert b.num < BDDTermination.num
        r = check_ncache_rm_dup(b.num, subtract_recursive(a, b.zero),
                                subtract_recursive(a, b.one))
        SUBTRACT_CACHE[c_key] = r
        return r


def intersection_recursive(a, b):
    """
    Intersects a with b, only the matching portions are returned.

    That is to say they have the same terminal node also.
    Everything else is excluded/set to None.
    """
    if a is None or b is None:
        return None
    if a == b:
        return a

    c_key = (id(a), id(b))
    cached = INTERSECTION_CACHE.get(c_key)
    if cached is not None:
        return cached

    if a.num == b.num:
        r = check_ncache_rm_dup(a.num, intersection_recursive(a.zero, b.zero),
                                intersection_recursive(a.one, b.one))
        INTERSECTION_CACHE[c_key] = r
        return r
    if a.num < b.num:
        assert a.num < BDDTermination.num
        r = check_ncache_rm_dup(a.num, intersection_recursive(a.zero, b),
                                intersection_recursive(a.one, b))
        INTERSECTION_CACHE[c_key] = r
        return r
    else:
        assert a.num > b.num
        assert b.num < BDDTermination.num
        r = check_ncache_rm_dup(b.num, intersection_recursive(a, b.zero),
                                intersection_recursive(a, b.one))
        INTERSECTION_CACHE[c_key] = r
        return r
