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

static PyObject *morton_number_pdep32(PyObject *Py_UNUSED(self),
                                      PyObject *args) {
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

static PyObject *morton_number_pdep64(PyObject *Py_UNUSED(self),
                                      PyObject *args) {
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

static const uint16_t MortonTable256[] = {
    0x0000, 0x0001, 0x0004, 0x0005, 0x0010, 0x0011, 0x0014, 0x0015, 0x0040,
    0x0041, 0x0044, 0x0045, 0x0050, 0x0051, 0x0054, 0x0055, 0x0100, 0x0101,
    0x0104, 0x0105, 0x0110, 0x0111, 0x0114, 0x0115, 0x0140, 0x0141, 0x0144,
    0x0145, 0x0150, 0x0151, 0x0154, 0x0155, 0x0400, 0x0401, 0x0404, 0x0405,
    0x0410, 0x0411, 0x0414, 0x0415, 0x0440, 0x0441, 0x0444, 0x0445, 0x0450,
    0x0451, 0x0454, 0x0455, 0x0500, 0x0501, 0x0504, 0x0505, 0x0510, 0x0511,
    0x0514, 0x0515, 0x0540, 0x0541, 0x0544, 0x0545, 0x0550, 0x0551, 0x0554,
    0x0555, 0x1000, 0x1001, 0x1004, 0x1005, 0x1010, 0x1011, 0x1014, 0x1015,
    0x1040, 0x1041, 0x1044, 0x1045, 0x1050, 0x1051, 0x1054, 0x1055, 0x1100,
    0x1101, 0x1104, 0x1105, 0x1110, 0x1111, 0x1114, 0x1115, 0x1140, 0x1141,
    0x1144, 0x1145, 0x1150, 0x1151, 0x1154, 0x1155, 0x1400, 0x1401, 0x1404,
    0x1405, 0x1410, 0x1411, 0x1414, 0x1415, 0x1440, 0x1441, 0x1444, 0x1445,
    0x1450, 0x1451, 0x1454, 0x1455, 0x1500, 0x1501, 0x1504, 0x1505, 0x1510,
    0x1511, 0x1514, 0x1515, 0x1540, 0x1541, 0x1544, 0x1545, 0x1550, 0x1551,
    0x1554, 0x1555, 0x4000, 0x4001, 0x4004, 0x4005, 0x4010, 0x4011, 0x4014,
    0x4015, 0x4040, 0x4041, 0x4044, 0x4045, 0x4050, 0x4051, 0x4054, 0x4055,
    0x4100, 0x4101, 0x4104, 0x4105, 0x4110, 0x4111, 0x4114, 0x4115, 0x4140,
    0x4141, 0x4144, 0x4145, 0x4150, 0x4151, 0x4154, 0x4155, 0x4400, 0x4401,
    0x4404, 0x4405, 0x4410, 0x4411, 0x4414, 0x4415, 0x4440, 0x4441, 0x4444,
    0x4445, 0x4450, 0x4451, 0x4454, 0x4455, 0x4500, 0x4501, 0x4504, 0x4505,
    0x4510, 0x4511, 0x4514, 0x4515, 0x4540, 0x4541, 0x4544, 0x4545, 0x4550,
    0x4551, 0x4554, 0x4555, 0x5000, 0x5001, 0x5004, 0x5005, 0x5010, 0x5011,
    0x5014, 0x5015, 0x5040, 0x5041, 0x5044, 0x5045, 0x5050, 0x5051, 0x5054,
    0x5055, 0x5100, 0x5101, 0x5104, 0x5105, 0x5110, 0x5111, 0x5114, 0x5115,
    0x5140, 0x5141, 0x5144, 0x5145, 0x5150, 0x5151, 0x5154, 0x5155, 0x5400,
    0x5401, 0x5404, 0x5405, 0x5410, 0x5411, 0x5414, 0x5415, 0x5440, 0x5441,
    0x5444, 0x5445, 0x5450, 0x5451, 0x5454, 0x5455, 0x5500, 0x5501, 0x5504,
    0x5505, 0x5510, 0x5511, 0x5514, 0x5515, 0x5540, 0x5541, 0x5544, 0x5545,
    0x5550, 0x5551, 0x5554, 0x5555};

static PyObject *morton_number_lut(PyObject *Py_UNUSED(self), PyObject *args) {
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
  int words = (bits_to_read / 8) + 1;
  uint8_t a_b[words];
  uint8_t b_b[words];
  uint16_t r_b[words];

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
    r_b[i] =
        (MortonTable256[b_b[i] & 0xFF] << 1) | MortonTable256[a_b[i] & 0xFF];
  }
  Py_DECREF(la);
  Py_DECREF(lb);
  PyObject *res =
      _PyLong_FromByteArray((unsigned char *)r_b, sizeof(r_b), 1, 0);
  return res;
}

static PyMethodDef utilMethods[] = {
    {"morton_number", morton_number_pdep64, METH_VARARGS,
     "Interleave two long integers into a morton number, using the fastest "
     "method avaliable"},
    {"morton_number_pdep32", morton_number_pdep32, METH_VARARGS,
     "Interleave two long integers into a morton number, using the pdep32 "
     "instruction"},
    {"morton_number_pdep64", morton_number_pdep64, METH_VARARGS,
     "Interleave two long integers into a morton number, using the pdep64 "
     "instruction"},
    {"morton_number_lut", morton_number_lut, METH_VARARGS,
     "Interleave two long integers into a morton number, using a lookup table"},
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
  if (!__builtin_cpu_supports("bmi2")) {
    // Make sure the default doesn't use a missing instruction
    utilMethods[0].ml_meth = morton_number_lut;
  }
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
