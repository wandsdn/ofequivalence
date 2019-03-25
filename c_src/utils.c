// Copyright 2019 Richard Sanger, Wand Network Research Group
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <Python.h>
#include <longintrepr.h>
#include <longobject.h>
#include <stdio.h>
#include <x86intrin.h>

#define MODULE_NAME _utils
#define _STRINGIZE(a) #a
#define STRINGIZE(a) _STRINGIZE(a)
#define MODULE_NAME_S STRINGIZE(MODULE_NAME)

#ifndef Py_UNUSED /* This is already defined for Python 3.4 onwards */
#ifdef __GNUC__
#define Py_UNUSED(name) _unused_##name __attribute__((unused))
#else
#define Py_UNUSED(name) _unused_##name
#endif
#endif

#if PyLong_SHIFT % 2 != 0
#error "This code assumes PyLong_SHIFT is even (likely = 30), but it is " PyLong_SHIFT
#endif

#define PyLong_NumBits(num) _PyLong_NumBits((PyObject *)num)
/*
 * Casts a Python object to an PyLong
 * Returns a new reference which should be freed, this
 * may point to the original object if already a PyLong.
 */
static PyLongObject *num_to_py_long(PyObject *num) {
  PyLongObject *lnum = NULL;

  if (PyLong_Check(num)) {
    Py_INCREF(num);
    lnum = (PyLongObject *)num;
  } else {
    PyObject *args;
    if (!(args = Py_BuildValue("(O)", num))) {
      return NULL;
    }
    lnum = (PyLongObject *)PyObject_CallObject((PyObject *)&PyLong_Type, args);
    Py_DECREF(args);
  }
  return lnum;
}

static PyObject *morton_number(PyObject *Py_UNUSED(self), PyObject *args) {
  PyObject *a = NULL, *b = NULL;
  PyLongObject *la = NULL, *lb = NULL;
  if (!PyArg_ParseTuple(args, "OO", &a, &b))
    return NULL;

  la = num_to_py_long(a);
  if (!(lb = num_to_py_long(b))) {
    Py_DECREF(la);
    return NULL;
  }

  int a_bits = PyLong_NumBits(la);
  int b_bits = PyLong_NumBits(lb);
  int bits_to_read = a_bits > b_bits ? a_bits : b_bits;
  int words = (bits_to_read / 16) + 1;
  uint16_t a_b[words];
  uint16_t b_b[words];
  uint32_t r_b[words];

  if (_PyLong_AsByteArray(la, (unsigned char *)a_b, sizeof(a_b), 1, 0) != 0) {
    Py_DECREF(la);
    Py_DECREF(lb);
    return NULL;
  }
  if (_PyLong_AsByteArray(lb, (unsigned char *)b_b, sizeof(b_b), 1, 0) != 0) {
    Py_DECREF(la);
    Py_DECREF(lb);
    return NULL;
  }

  for (int i = 0; i < words; i++) {
    r_b[i] = _pdep_u32((uint32_t)a_b[i], 0x55555555);
    r_b[i] |= _pdep_u32((uint32_t)b_b[i], 0xAAAAAAAA);
  }
  PyObject *res =
      _PyLong_FromByteArray((unsigned char *)r_b, sizeof(r_b), 1, 0);
  Py_DECREF(la);
  Py_DECREF(lb);
  return res;
}

static PyObject *morton_number64(PyObject *Py_UNUSED(self), PyObject *args) {
  PyObject *a = NULL, *b = NULL;
  PyLongObject *la = NULL, *lb = NULL;
  if (!PyArg_ParseTuple(args, "OO", &a, &b))
    return NULL;

  la = num_to_py_long(a);
  if (!(lb = num_to_py_long(b))) {
    Py_DECREF(la);
    return NULL;
  }

  int a_bits = PyLong_NumBits(la);
  int b_bits = PyLong_NumBits(lb);
  int bits_to_read = a_bits > b_bits ? a_bits : b_bits;
  int words = (bits_to_read / 32) + 1;
  uint32_t a_b[words];
  uint32_t b_b[words];
  uint64_t r_b[words];

  if (_PyLong_AsByteArray(la, (unsigned char *)a_b, sizeof(a_b), 1, 0) != 0) {
    Py_DECREF(la);
    Py_DECREF(lb);
    return NULL;
  }
  if (_PyLong_AsByteArray(lb, (unsigned char *)b_b, sizeof(b_b), 1, 0) != 0) {
    Py_DECREF(la);
    Py_DECREF(lb);
    return NULL;
  }

  for (int i = 0; i < words; i++) {
    r_b[i] = _pdep_u64((uint64_t)a_b[i], 0x5555555555555555);
    r_b[i] |= _pdep_u64((uint64_t)b_b[i], 0xAAAAAAAAAAAAAAAA);
  }
  Py_DECREF(la);
  Py_DECREF(lb);
  PyObject *res =
      _PyLong_FromByteArray((unsigned char *)r_b, sizeof(r_b), 1, 0);
  return res;
}

static PyMethodDef utilMethods[] = {
    {"morton_number", morton_number, METH_VARARGS,
     "Merge to long integers into a morton number"},
    {"morton_number64", morton_number64, METH_VARARGS,
     "Merge to long integers into a morton number"},
    {}};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    MODULE_NAME_S,
    NULL,
    -1, // Per module state
    utilMethods,
    // NULL,
    // myextension_traverse,
    // myextension_clear,
    // NULL
};
#endif
#define G_HELPER(x, y) x##y
#define GLUE(x, y) G_HELPER(x, y)

static PyObject *moduleinit(void) {
  PyObject *m;

/* Init the global methods */
#if PY_MAJOR_VERSION >= 3
  m = PyModule_Create(&moduledef);
#else
  m = Py_InitModule(MODULE_NAME_S, utilMethods);
#endif

  return m;
}

#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC GLUE(PyInit_, MODULE_NAME)(void) { return moduleinit(); }
#else
PyMODINIT_FUNC GLUE(init, MODULE_NAME)(void) { moduleinit(); }
#endif
