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
usage: check_equivalence [-h] [-d] [-r] [-D] [-f FIB] [-v] [files [files ...]]

Time building a ruleset into a MTBDD

positional arguments:
  files                 A pickled ryu ruleset capture

optional arguments:
  -h, --help            show this help message and exit
  -d, --divide-conquer  Use a divide and conquer building
  -r, --reverse         Reverse field bit ordering, can force a bad ordering
                        within the BDD.
  -D, --difference      Print the difference of rulesets.
  -f FIB, --FIB FIB     Pass a FIB rather than a ryu capture
  -v, --verbose         Print additional stats from CUDD
```

### Pickled rulesets

A pickled ruleset can be collected using the included script, scripts/collect_state.py.


It is run as follows:
```
ryu-mananger --ofp-tcp-listen-port <port> --ofp-listen-host <host> ./CollectState.py
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
