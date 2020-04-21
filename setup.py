#!/usr/bin/env python
"""
Installs the ofequivalence library

The script automatically downloads the required CUDD BDD library dependency.

If you wish to work offline, or are developing the library it is recommended
that you download CUDD into this folder to avoid downloading it again.
"""

import os
try:
    from urllib import urlretrieve
except ImportError:
    from urllib.request import urlretrieve
import tarfile
import subprocess
from setuptools import setup, Extension

CUDD_URL = "https://github.com/ivmai/cudd/archive/cudd-3.0.0.tar.gz"
CUDD_DIR = "cudd-cudd-3.0.0"  # The dir name within the tar
C_FLAGS = ["-Wall", "-Wextra", "-g3", "-ggdb", "-O3"]

with open('README.md') as f:
    README = f.read()

with open('LICENSE') as f:
    LICENSE = f.read()

_cbdd = Extension('ofequivalence._cbdd', sources=['c_src/cbddmodule.cpp'],
                  extra_compile_args=C_FLAGS + ["-std=c++11"])
_utils = Extension('ofequivalence._utils', sources=['c_src/utils.c'],
                   extra_compile_args=C_FLAGS + ["-mbmi2"])

_cudd = Extension(
    'ofequivalence._cudd',
    sources=['c_src/cuddmodule.c'],
    include_dirs=[CUDD_DIR + '/cudd',
                  CUDD_DIR,
                  CUDD_DIR + '/st',
                  CUDD_DIR + '/mtr',
                  CUDD_DIR + '/epd'],
    library_dirs=[CUDD_DIR + '/cudd/.libs'],
    extra_compile_args=['-fPIC'] + C_FLAGS,
    extra_link_args=['-fPIC', '-Wl,-Bstatic', '-lcudd', '-Wl,-Bdynamic'],)


# If CUDD is not already downloaded, download and unzip CUDD.
if not os.path.exists("cudd-3.0.0.tar.gz"):
    urlretrieve(CUDD_URL, "cudd-3.0.0.tar.gz")
if not os.path.isdir(CUDD_DIR):
    with tarfile.open("cudd-3.0.0.tar.gz", "r:gz") as tar:
        tar.extractall()

if not os.path.exists(CUDD_DIR + "/cudd/.libs/libcudd.so"):
    # Build CUDD
    subprocess.call(["./configure", "--enable-shared",
                     "CFLAGS=-fPIC -O3 -g3 -ggdb"], cwd=CUDD_DIR)
    subprocess.call(["make", "-j4"], cwd=CUDD_DIR)

setup(
    name='ofequivalence',
    version='1.0.0',
    description=('A python library which can check the equivalence of '
                 'OpenFlow 1.3 rulesets.'),
    long_description=README,
    author='Richard Sanger',
    author_email='rsanger@wand.net.nz',
    url='https://github.com/wandsdn/ofequivalence',
    license=LICENSE,
    packages=['ofequivalence'],
    install_requires=[
        "ryu",
        "lru-dict",
        "tqdm",
        "gmpy2",
        "six",
        "networkx"
        ],
    ext_modules=[_cbdd, _cudd, _utils],
    entry_points={
        "console_scripts": [
            "check_equivalence = ofequivalence.check_equivalence:main",
            "compress_ruleset = ofequivalence.compress_ruleset:main",
            "graph_ruleset_deps = ofequivalence.graph_ruleset_deps:main",
            "convert_ruleset = ofequivalence.convert_ruleset:main"
            ]
        }
    )
