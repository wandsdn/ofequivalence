"""
A conversion layer between an ascii FIB cisco style and OpenFlow 1.3
to internal Rules.

The file format is:
* route/prefix peer [metrics...]

e.g.
* 0.0.0.0/0 202.73.40.45 0 0 0 18106 i
* 1.0.4.0/22 103.247.3.45 0 0 0 58511 4826 38803 56203 i

This is converted to
Match: 0.0.0.0/0   Apply Actions: output(1)
Match: 1.0.4.0/22  Apply Actions: output(2)

Each unique peer is assigned a unique output port
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

from .rule import Rule, Match
from .utils import as_file_handle
IP_MASK = 0xFFFFFFFF


@as_file_handle('rb')
def ruleset_from_fib(file):
    """ Convert a ASCII file representing a FIB to Rule()s

        Expected format is cisco (like RouteViews publishes):
        * route/prefix peer [metrics...]

        Metrics and anything following is ignored

        Returns both the ruleset and output mapping.

        file: The readable binary file-like object, or the name of the input file
        return: (ruleset, output_mapping)
    """
    count = 0
    output_mapping = {}
    ruleset = []

    for line in file:
        line = line.split()
        # line[1] is  "A.B.C.D/E"
        subnet = line[1].split(b"/")
        mask = int(subnet[1])
        ipparts = subnet[0].split(b'.')
        ip = (int(ipparts[0]) << 24 | int(ipparts[1]) << 16 |
              int(ipparts[2]) << 8 | int(ipparts[3]))
        match_subnet = (ip, (IP_MASK<<(32-mask)) & IP_MASK)
        match = Match([("IPV4_DST", match_subnet[0], match_subnet[1])])
        if line[2] not in output_mapping:
            count += 1
            output_mapping[line[2]] = count
        rule = Rule(priority=mask, table=0, match=match)
        rule.instructions.write_actions.append("OUTPUT", output_mapping[line[2]])
        ruleset.append(rule)

    return ruleset
