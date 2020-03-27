""" Utils to apply resource limits
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

from __future__ import print_function, division
from resource import RLIMIT_AS, RLIM_INFINITY, getrlimit, setrlimit

_MB = 0x100000


def automatically_limit_memory(m_min=512*_MB, res_perc=20, max_res=2048*_MB):
    """
        Limits memory to a sensible value to prevent swapping

        Looks at the free memory currently avaliable and limits this process
        to using only a percentage of it. Sets the memory limit using
        RLIMIT_AS (ulimit -v), and will not change the limit if already set.

        m_min: The minimum memory to allow (in bytes)
        max_res: The maximum memory to reserve for other processes (in bytes).
                 If None, always use res_perc
        res_perc: The percentage of free memory to reserve

        return: True if the memory limit was changed, otherwise False

        Note: Implemented for Linux, won't do anything on other systems
    """
    assert 0 <= res_perc <= 100
    orig_limits = getrlimit(RLIMIT_AS)

    # Already limited, skip
    if orig_limits != (RLIM_INFINITY, RLIM_INFINITY):
        return False

    mem_free_kb = None
    try:
        with open('/proc/meminfo') as meminfo:
            for line in meminfo:
                if 'MemFree' in line:
                    mem_free_kb = int(line.split()[1])
                    break
    except IOError:
        return False

    if mem_free_kb is None:
        return False

    mem_free = mem_free_kb * 1024

    reserve = min(res_perc * mem_free // 100, max_res)
    new_limit = max(mem_free - reserve, m_min)

    setrlimit(RLIMIT_AS, (new_limit, orig_limits[1]))

    return True
