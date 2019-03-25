""" A C backed multi-terminal bdd representation.

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
from .headerspace import bytes_needed, flow_wildcard_to_flowmatches
from .rule import Match
from . import _cbdd
from ._cbdd import (NODE_CACHE, MERGE_CACHE, INTERSECTION_CACHE,
                    DIFFERENCE_CACHE, RULE_CACHE, difference_recursive,
                    intersection_recursive, meld_recursive, subtract_recursive,
                    BDDNode, BDDTermination, IS_DIFFERING)

IS_DIFFERING_TUPLE = ("DIFFERS", "This is different")


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
    """
    bdd = BDD()
    if not wc:
        return bdd

    tot_bits = bytes_needed * 8
    # Build up in reverse
    # Start with termination
    cnode = check_ncache(BDDTermination(action, f_action))
    term = cnode

    # Does this exist? If so duplicate
    root = RULE_CACHE.get((wc, id(cnode)))
    if root is not None:
        bdd.root = root
        return bdd
    if six.PY3:
        cnode = _cbdd.wc_to_BDD(int(wc), term, tot_bits)
    else:
        cnode = _cbdd.wc_to_BDD(long(wc), term, tot_bits)
    bdd.root = cnode
    RULE_CACHE[(wc, id(term))] = cnode
    return bdd


def BDD_to_wcs(BDD):
    """ Returns a list of  wildcard -> BDDTermination """
    bits = (bytes_needed * 8)-1  # Less as node numbers start at 0
    return list(_BDD_to_wcs(BDD.root, Match().get_wildcard(), bits))


def BDD_to_matches(BDD):
    return [flow_wildcard_to_flowmatches(x, Match)
            for x, y in BDD_to_wcs(BDD)]


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
