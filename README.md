A library for testing the equivalence of OpenFlow 1.3 rulesets.


### Running

The main executable is check_equivalence, this is installed to
/usr/bin in your python environment.

check_equivalence also serves as an example usage of the library.

Basic usage:
```
check_equivalence -d ruleset_a.pickle ruleset_b.pickle
```
Where a ruleset is a pickled ryu capture.

For other options view the help
```
$ check_equivalence -h
usage: check_equivalence [-h] [-d] [-r] [-D] [-v] [--auto RULESET]
                         [--ryu_pickle RULESET] [--ryu_json RULESET]
                         [--pickle RULESET] [--ovs RULESET] [--fib RULESET]
                         [ruleset [ruleset ...]]

Check for forwarding equivalence between two or more rulesets

positional arguments:
  ruleset               the rulesets to check equivalence of. This
                        automatically detects the ruleset format. Available
                        formats are listed in the formats section below.

optional arguments:
  -h, --help            show this help message and exit
  -d, --divide-conquer  use the faster divide-and-conquer method for building
                        the MTBDD
  -r, --reverse         reverse field bit ordering, which can force a
                        inefficient ordering within the MTBDD.
  -D, --difference      print the difference between the first and each
                        differing ruleset.
  -v, --verbose         print additional stats from CUDD

formats:
  Optional arguments to specify the format of the ruleset. Useful if reading
  from a pipe or stdin (denoted by -) where automatic detection cannot seek
  back in the file.

  --auto RULESET        load a ruleset from the auto format. This is the
                        default behaviour which tries all known formats.
  --ryu_pickle RULESET  load a ruleset from the ryu_pickle format.
  --ryu_json RULESET    load a ruleset from the ryu_json format.
  --pickle RULESET      load a ruleset from the pickle format.
  --ovs RULESET         load a ruleset from the ovs format.
  --fib RULESET         load a ruleset from the fib format.
```

#### Other Tools

ofequivalence also ships the following tools (use -h to show usage information):

```
compress_ruleset
graph_ruleset_deps
convert_ruleset
```

#### Memory Limit

The internal representations for a set of packets whether using  BDD's or
Header Space can grow large, often quite unexpectedly.

To reduce the risk of swapping and creating an out-of-memory situation,
ofequivalence applies a virtual memory limit to itself, unless
it finds an existing limit already. This limit is set to a minimum of
512MB up to 80% of free memory at load time.

To override the default limit use ulimit -Sv, for example
```
ulimit -Sv 1048576  # Set the soft virtual memory limit to 1GB
check_equivalence -d ruleset_a.pickle ruleset_b.pickle
```

For more see the implementation in [ofequivalence/limits.py](ofequivalence/limits.py)

### Pickled rulesets

A pickled ruleset can be collected using the included script, scripts/collect_state.py.


It is run as follows:
```
ryu-mananger --ofp-tcp-listen-port <port> --ofp-listen-host <host> ./collect_state.py
```

In some cases you might need to also specify ryu's --log-config-file.

### Installing

First install the requirements for [gmpy2](https://gmpy2.readthedocs.io/en/latest/).
For Debian based distributions run:
```
apt install libgmp-dev libmpfr-dev libmpc-dev
```

To install this library we recommend using pip

In the root directory (where this README is located) run:
```
pip install ./
```

Alternatively this can be run to installed for only the current user
without needing root:
```
pip install --user ./
```

Note: It is expected that the normalise headerspace tests will fail, as this
implementation is incomplete. Hence, the normalise bdd implementation
should be used in practice.

#### Dependencies

This library uses the CUDD 3.0.0 BDD package, available from:
https://github.com/ivmai/cudd

The install script downloads and builds the CUDD library automatically.

For python dependencies see requirements.txt

### Running tests

Unittest is used to run tests.

In the root directory, the following command will run the tests locally:
```
./setup.py test
```

Once fully installed the unittest module can be used for tests.
In the root directory, the following command will run the tests:
```
python -m unittest discover -v
```

### License

The code is licensed under the Apache License Version 2.0, see the included
LICENSE file.

### Referencing

We have published a paper about OpenFlow ruleset equivalence and this code.

Title: Identifying Equivalent SDN Forwarding Behaviour \
Authors: Richard Sanger, Matthew Luckie, Richard Nelson \
Conference: ACM Symposium on SDN Research (SOSR) 2019
