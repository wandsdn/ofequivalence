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
#include <cudd.h>
#include <cuddInt.h>
#include <longintrepr.h>
#include <structmember.h>

/* TODO Update globals to the new Python3 style */

#define MODULE_NAME _cudd
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

// Py_TPFLAGS_HAVE_ITER removed in python 3/just set 0
#ifndef Py_TPFLAGS_HAVE_ITER
#define Py_TPFLAGS_HAVE_ITER 0
#endif

/* Define options modify setup.py extra_flags with -D to
 * add a define.
 */

// A large number stored in BDDTERM to represent the end of processing
// Making it large typically also means it works with the normal logic
#define NULL2NONE(x) ((x) ? (x) : Py_None)
#define NONE2NULL(x) ((x != Py_None) ? (x) : NULL)

static DdManager *cudd_manager;
static DdNode *BK;

typedef struct _BDD BDD;
typedef struct _BDD { PyObject_HEAD DdNode *root; } BDD;

typedef struct _BDDIterator {
  PyObject_HEAD DdGen *gen;
  BDD *root;
  PyObject *wc;
  long bits;
} BDDIterator;

static PyObject *PyLong1 = NULL, *PyLong2 = NULL;

#define Cudd_IsConstant cuddIsConstant
#define Cudd_T cuddT
#define Cudd_E cuddE
#define Cudd_V cuddV
#define Cudd_Ref cuddRef

// Cudd stores terminals as doubles, we have 52 bits of number,
// so can store 2 26 bit integers, without loss of precision.
// We cannot simply reinterpret a integer to a double as cudd uses
// epsilon comparisons
#define ENCODE_TERMINAL(a, b) ((double)((uint64_t)(a) | ((uint64_t)(b)) << 26))
#define DECODE_TERMINAL(t, a, b)                                               \
  a = (int)((uint64_t)(t)) & 0x3FFFFFF;                                        \
  b = (int)(((uint64_t)(t)) >> 26) & 0x3FFFFFF;

#define READY_BDD_TYPE(x)                                                      \
  if (!PyObject_IsInstance((PyObject *)(x), (PyObject *)&BDDType)) {           \
    if ((PyObject *)(x) == Py_None) {                                          \
      (x) = NULL;                                                              \
    } else {                                                                   \
      PyErr_BadArgument();                                                     \
      return NULL;                                                             \
    }                                                                          \
  }

static PyMemberDef BDD_members[] = {{0}};

static void BDD_dealloc(BDD *self);
static PyObject *BDD_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static int BDD_init(PyObject *_self, PyObject *args, PyObject *kwds);
static PyObject *BDD_richcmp(PyObject *a, PyObject *b, int op);
static PyObject *bmeld_recursive(PyObject *a, PyObject *b);
static PyObject *osubtract_recursive(PyObject *self, PyObject *args);

static PyObject *ointersection_recursive(PyObject *self, PyObject *args);
static PyObject *odifference_recursive(PyObject *self, PyObject *args);
static PyObject *odifftagged_recursive(PyObject *self, PyObject *args);
static Py_ssize_t BDD_len(PyObject *);
static int BDD_bool(PyObject *);

static PyMethodDef BDD_methods[] = {
    {"subtract", osubtract_recursive, METH_VARARGS, "Subtract BDDs"},
    {"difference", odifference_recursive, METH_VARARGS, "Difference BDDs"},
    {"difftagged", odifftagged_recursive, METH_VARARGS,
     "Tagged Difference BDDs"},
    {"intersection", ointersection_recursive, METH_VARARGS,
     "Intersection of BDDs"},
    {0}};

#if PY_MAJOR_VERSION >= 3
static PyNumberMethods BDDNumType = {.nb_add = bmeld_recursive,
                                     .nb_bool = BDD_bool};
#else
static PyNumberMethods BDDNumType = {.nb_add = bmeld_recursive,
                                     .nb_nonzero = BDD_bool};
#endif
static PySequenceMethods BDDSeqType = {.sq_length = BDD_len};
static PyTypeObject BDDType = {
    PyVarObject_HEAD_INIT(NULL, 0) MODULE_NAME_S ".BDD", /* tp_name */
    sizeof(BDD),                                         /* tp_basicsize */
    0,                                                   /* tp_itemsize */
    (destructor)BDD_dealloc,                             /* tp_dealloc */
    0,                                                   /* tp_print */
    0,                                                   /* tp_getattr */
    0,                                                   /* tp_setattr */
    0,                                                   /* tp_compare */
    0,                                                   /* tp_repr */
    &BDDNumType,                                         /* tp_as_number */
    &BDDSeqType,                                         /* tp_as_sequence */
    0,                                                   /* tp_as_mapping */
    0,                                                   /* tp_hash */
    0,                                                   /* tp_call */
    0,                                                   /* tp_str */
    0,                                                   /* tp_getattro */
    0,                                                   /* tp_setattro */
    0,                                                   /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                                  /* tp_flags */
    "A BDD",                                             /* tp_doc */
    0,                                                   /* tp_traverse */
    0,                                                   /* tp_clear */
    BDD_richcmp,                                         /* tp_richcompare */
    0,                                                   /* tp_weaklistoffset */
    0,                                                   /* tp_iter */
    0,                                                   /* tp_iternext */
    BDD_methods,                                         /* tp_methods */
    BDD_members,                                         /* tp_members */
    0,                                                   /* tp_getset */
    0,                                                   /* tp_base */
    0,                                                   /* tp_dict */
    0,                                                   /* tp_descr_get */
    0,                                                   /* tp_descr_set */
    0,                                                   /* tp_dictoffset */
    (initproc)BDD_init,                                  /* tp_init */
    0,                                                   /* tp_alloc */
    BDD_new,                                             /* tp_new */
};

static void BDD_dealloc(BDD *self) {
  if (self->root)
    Cudd_RecursiveDeref(cudd_manager, self->root);
  Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *BDD_new(PyTypeObject *type, PyObject *Py_UNUSED(args),
                         PyObject *Py_UNUSED(kwds)) {
  BDD *self;

  self = (BDD *)type->tp_alloc(type, 0);
  if (self != NULL) {
    self->root = NULL;
  }
  return (PyObject *)self;
}

static int BDD_init(PyObject *_self, PyObject *args, PyObject *kwds) {
  BDD *self = (BDD *)_self;
  int action = 0;
  static char *kwlist[] = {"action", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist, &action))
    return -1;
  self->root = Cudd_addConst(cudd_manager, ENCODE_TERMINAL(action, 0));
  Cudd_Ref(self->root);
  return 0;
}

static PyObject *BDD_richcmp(PyObject *a, PyObject *b, int op) {
  PyObject *res = Py_NotImplemented;

  if (op == Py_EQ && PyObject_IsInstance(b, (PyObject *)&BDDType)) {
    BDD *_a = (BDD *)a, *_b = (BDD *)b;
    if (_a->root == _b->root)
      res = Py_True;
    else
      res = Py_False;
  }
  if (op == Py_NE && PyObject_IsInstance(b, (PyObject *)&BDDType)) {
    BDD *_a = (BDD *)a, *_b = (BDD *)b;
    if (_a->root == _b->root)
      res = Py_False;
    else
      res = Py_True;
  }
  Py_INCREF(res);
  return res;
}

static void BDDIterator_dealloc(BDDIterator *self);
static PyObject *BDDIterator_new(PyTypeObject *type, PyObject *args,
                                 PyObject *kwds);
static int BDDIterator_init(PyObject *_self, PyObject *args, PyObject *kwds);
static PyObject *BDDIterator_iter(PyObject *self);
static PyObject *BDDIterator_next(PyObject *self);
static Py_ssize_t BDDIterator_len(PyObject *a);

static PySequenceMethods BDDIterSeqType = {.sq_length = BDDIterator_len};
static PyTypeObject BDDIteratorType = {
    PyVarObject_HEAD_INIT(NULL, 0) MODULE_NAME_S ".BDDIterator", /* tp_name */
    sizeof(BDDIterator),                       /* tp_basicsize */
    0,                                         /* tp_itemsize */
    (destructor)BDDIterator_dealloc,           /* tp_dealloc */
    0,                                         /* tp_print */
    0,                                         /* tp_getattr */
    0,                                         /* tp_setattr */
    0,                                         /* tp_compare */
    0,                                         /* tp_repr */
    0,                                         /* tp_as_number */
    &BDDIterSeqType,                           /* tp_as_sequence */
    0,                                         /* tp_as_mapping */
    0,                                         /* tp_hash */
    0,                                         /* tp_call */
    0,                                         /* tp_str */
    0,                                         /* tp_getattro */
    0,                                         /* tp_setattro */
    0,                                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER, /* tp_flags */
    "A BDDIterator",                           /* tp_doc */
    0,                                         /* tp_traverse */
    0,                                         /* tp_clear */
    0,                                         /* tp_richcompare */
    0,                                         /* tp_weaklistoffset */
    BDDIterator_iter,                          /* tp_iter */
    BDDIterator_next,                          /* tp_iternext */
    0,                                         /* tp_methods */
    0,                                         /* tp_members */
    0,                                         /* tp_getset */
    0,                                         /* tp_base */
    0,                                         /* tp_dict */
    0,                                         /* tp_descr_get */
    0,                                         /* tp_descr_set */
    0,                                         /* tp_dictoffset */
    (initproc)BDDIterator_init,                /* tp_init */
    0,                                         /* tp_alloc */
    BDDIterator_new,                           /* tp_new */
};

static void BDDIterator_dealloc(BDDIterator *self) {
  Py_XDECREF(self->root);
  Py_XDECREF(self->wc);
  if (self->gen) {
    Cudd_GenFree(self->gen);
    self->gen = NULL;
  }
  Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *BDDIterator_new(PyTypeObject *type, PyObject *Py_UNUSED(args),
                                 PyObject *Py_UNUSED(kwds)) {
  BDDIterator *self;

  self = (BDDIterator *)type->tp_alloc(type, 0);
  self->gen = NULL;
  self->root = NULL;
  self->wc = NULL;
  self->bits = 0;
  return (PyObject *)self;
}

static int BDDIterator_init(PyObject *_self, PyObject *args, PyObject *kwds) {
  BDDIterator *self = (BDDIterator *)_self;
  BDD *root = NULL;
  PyObject *wc = NULL;
  long bits = 0;
  static char *kwlist[] = {"bdd", "wc", "bits", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOl", kwlist, &root, &wc,
                                   &bits))
    return -1;
  self->root = root;
  self->wc = wc;
  self->bits = bits;
  Py_INCREF(root);
  Py_INCREF(wc);
  return 0;
}

static PyObject *BDDIterator_iter(PyObject *_self) {
  BDDIterator *self = (BDDIterator *)_self;
  if (self->gen != NULL) {
    Cudd_GenFree(self->gen);
    self->gen = NULL;
  }
  Py_INCREF(self);
  return (PyObject *)self;
}

static PyObject *BDDIterator_next(PyObject *_self) {
  BDDIterator *self = (BDDIterator *)_self;
  int *cube = NULL;
  int size;
  CUDD_VALUE_TYPE v = 0;

  if (self->gen == NULL) {
    self->gen = Cudd_FirstCube(cudd_manager, self->root->root, &cube, &v);
    if (self->gen == NULL)
      return PyErr_NoMemory(); // Likely a memory issue
  } else {
    Cudd_NextCube(self->gen, &cube, &v);
  }
  if (Cudd_IsGenEmpty(self->gen)) {
    Cudd_GenFree(self->gen);
    self->gen = NULL;
    PyErr_SetNone(PyExc_StopIteration);
    return NULL;
  }
  size = Cudd_ReadSize(cudd_manager);
  PyObject *n_num, *wcn, *tmp, *wc;
  wc = self->wc;
  Py_INCREF(wc);
  for (int i = 0; i < size; i++) {
    switch (cube[i]) {
    case 0: // False
      n_num = PyLong_FromLong((self->bits - (long)i) * 2);
      wcn = PyNumber_Lshift(PyLong2, n_num);
      tmp = PyNumber_Invert(wcn);
      Py_DECREF(wcn);
      wcn = PyNumber_And(wc, tmp);
      Py_DECREF(tmp);
      Py_DECREF(wc);
      wc = wcn;
      wcn = NULL;
      Py_DECREF(n_num);
      break;
    case 1: // True
      n_num = PyLong_FromLong((self->bits - (long)i) * 2);
      wcn = PyNumber_Lshift(PyLong1, n_num);
      tmp = PyNumber_Invert(wcn);
      Py_DECREF(wcn);
      wcn = PyNumber_And(wc, tmp);
      Py_DECREF(tmp);
      Py_DECREF(wc);
      wc = wcn;
      wcn = NULL;
      Py_DECREF(n_num);
      break;
    case 2: // Don't care
      break;
    }
  }
  int x, y;
  DECODE_TERMINAL(v, x, y);
  PyObject *a = Py_BuildValue("(Nii)", wc, x, y);
  return a;
}

static Py_ssize_t size_rec(DdNode *n) {
  if (n == BK) {
    return 0;
  } else if (Cudd_IsConstant(n)) {
    return 1;
  } else
    return size_rec(Cudd_E(n)) + size_rec(Cudd_T(n));
}

static Py_ssize_t BDDIterator_len(PyObject *a) {
  BDDIterator *self = (BDDIterator *)a;
  if (self->root == NULL || self->root->root == NULL) {
    return 0;
  } else {
    return size_rec(self->root->root);
  }
}

static void _BDD_to_wcs(DdNode *node, PyObject *wc, PyObject *res, long bits) {
  if (Cudd_IsConstant(node)) {
    int x, y;
    if (node == BK) {
      return;
    }
    DECODE_TERMINAL(Cudd_V(node), x, y)
    PyObject *a = Py_BuildValue("(Oii)", wc, x, y);
    PyList_Append(res, a); // == 0 success
    Py_DECREF(a);
    return;
  }
  PyObject *wcz, *wco, *tmp, *n_num;
  // False or E
  n_num = PyLong_FromLong((bits - (long)Cudd_NodeReadIndex(node)) * 2);
  wcz = PyNumber_Lshift(PyLong2, n_num);
  tmp = PyNumber_Invert(wcz);
  Py_DECREF(wcz);
  wcz = PyNumber_And(wc, tmp);
  Py_DECREF(tmp);
  _BDD_to_wcs(Cudd_E(node), wcz, res, bits);
  Py_DECREF(wcz);

  // True of T
  wco = PyNumber_Lshift(PyLong1, n_num);
  tmp = PyNumber_Invert(wco);
  Py_DECREF(wco);
  wco = PyNumber_And(wc, tmp);
  Py_DECREF(tmp);
  _BDD_to_wcs(Cudd_T(node), wco, res, bits);
  Py_DECREF(wco);
  Py_DECREF(n_num);
}

static PyObject *BDD_to_wcs(PyObject *Py_UNUSED(self), PyObject *args) {
  PyObject *bdd = NULL, *wc = NULL;
  long bits;
  if (!PyArg_ParseTuple(args, "OOl", &bdd, &wc, &bits))
    return NULL;
  PyObject *res = PyList_New(0);
  if (res == NULL)
    return NULL;
  DdNode *root = ((BDD *)bdd)->root;
  _BDD_to_wcs(root, wc, res, bits);
  return res;
}

static Py_ssize_t BDD_len(PyObject *_self) {
  BDD *self = (BDD *)_self;
  if (self->root == NULL) {
    return 0;
  } else {
    // Don't count BK for consistency with old code
    DdNode *roots[2] = {self->root, BK};
    return (Py_ssize_t)Cudd_SharingSize(roots, 2) - 1;
  }
}

static int BDD_bool(PyObject *_self) {
  BDD *self = (BDD *)_self;
  if (self->root == NULL)
    return 0;
  return self->root != BK;
}

static PyObject *BDD_shared_size(PyObject *Py_UNUSED(self), PyObject *args) {
  PyObject *bdds = NULL;
  if (!PyArg_ParseTuple(args, "O", &bdds))
    return NULL;
  if (PyList_Check(bdds)) {
    Py_ssize_t len = PyList_Size(bdds);
    DdNode *nodes[len];
    for (Py_ssize_t i = 0; i < len; i++) {
      PyObject *o = PyList_GetItem(bdds, i);
      READY_BDD_TYPE(o);
      if (o == NULL)
        return NULL;
      if (((BDD *)o)->root == NULL)
        nodes[i] = BK;
      else
        nodes[i] = ((BDD *)o)->root;
    }
    return Py_BuildValue("i", Cudd_SharingSize(nodes, len));
  } else {
    return NULL;
  }
}

DdNode *Cudd_addMeld(DdManager *Py_UNUSED(dd), DdNode **f, DdNode **g) {
  DdNode *F, *G;
  F = *f;
  G = *g;
  if (F == G || F == BK)
    return G;
  if (Cudd_IsConstant(F) || G == BK)
    return F;
  return NULL;
}

DdNode *Cudd_addSubtract(DdManager *Py_UNUSED(dd), DdNode **f, DdNode **g) {
  DdNode *F, *G;
  F = *f;
  G = *g;

  if (F == G)
    return BK;
  if (Cudd_IsConstant(F) && Cudd_IsConstant(G))
    return F;
  return NULL;
}

static DdNode *DIFFERS = NULL;

DdNode *Cudd_addDifference(DdManager *Py_UNUSED(dd), DdNode **f, DdNode **g) {
  DdNode *F, *G;
  F = *f;
  G = *g;

  if (F == G)
    return BK;
  if (F == BK)
    return DIFFERS; // NOT SURE ABOUT THIS CASE - DON'T think we need it.
  if (Cudd_IsConstant(F) && Cudd_IsConstant(G))
    return DIFFERS;
  return NULL;
}

DdNode *Cudd_addDiffTagged(DdManager *Py_UNUSED(dd), DdNode **f, DdNode **g) {
  DdNode *F, *G;
  F = *f;
  G = *g;

  if (F == G)
    return BK;
  if (Cudd_IsConstant(F) && Cudd_IsConstant(G)) {
    return Cudd_addConst(cudd_manager, ENCODE_TERMINAL(Cudd_V(F), Cudd_V(G)));
  }
  return NULL;
}

DdNode *Cudd_addIntersection(DdManager *Py_UNUSED(dd), DdNode **f, DdNode **g) {
  DdNode *F, *G;
  F = *f;
  G = *g;

  if (F == G)
    return F;
  if (Cudd_IsConstant(F) && Cudd_IsConstant(G))
    return BK;
  return NULL;
}

static PyObject *bmeld_recursive(PyObject *a, PyObject *b) {
  BDD *bdd;
  READY_BDD_TYPE(a);
  READY_BDD_TYPE(b);
  DdNode *ret = Cudd_addApply(cudd_manager, Cudd_addMeld, ((BDD *)a)->root,
                              ((BDD *)b)->root);
  Cudd_Ref(ret);
  bdd = (BDD *)PyObject_CallObject((PyObject *)&BDDType, NULL);
  Cudd_Deref(bdd->root);
  bdd->root = ret;
  return (PyObject *)bdd;
}

/** Meld two BDDs together
 *
 * This wraps the internal version into the python interface.
 * Accepts two arguments, and returns the result of merging the second
 * in to the first. With the first taking priority.
 */
static PyObject *meld_recursive(PyObject *Py_UNUSED(self), PyObject *args) {
  PyObject *a = NULL, *b = NULL;
  if (!PyArg_ParseTuple(args, "OO", &a, &b))
    return NULL;
  return bmeld_recursive(a, b);
}

static PyObject *bdifference_recursive(PyObject *a, PyObject *b) {
  BDD *bdd;
  READY_BDD_TYPE(a);
  READY_BDD_TYPE(b);
  DdNode *ret = Cudd_addApply(cudd_manager, Cudd_addDifference,
                              ((BDD *)a)->root, ((BDD *)b)->root);
  Cudd_Ref(ret);
  bdd = (BDD *)PyObject_CallObject((PyObject *)&BDDType, NULL);
  Cudd_Deref(bdd->root);
  bdd->root = ret;
  return (PyObject *)bdd;
}

static PyObject *difference_recursive(PyObject *Py_UNUSED(self),
                                      PyObject *args) {
  PyObject *a = NULL, *b = NULL;
  if (!PyArg_ParseTuple(args, "OO", &a, &b))
    return NULL;
  return bdifference_recursive(a, b);
}

static PyObject *odifference_recursive(PyObject *self, PyObject *args) {
  PyObject *b = NULL;
  if (!PyArg_ParseTuple(args, "O", &b))
    return NULL;
  return bdifference_recursive(self, b);
}

static PyObject *bsubtract_recursive(PyObject *a, PyObject *b) {
  BDD *bdd;
  READY_BDD_TYPE(a);
  READY_BDD_TYPE(b);
  DdNode *ret = Cudd_addApply(cudd_manager, Cudd_addSubtract, ((BDD *)a)->root,
                              ((BDD *)b)->root);
  Cudd_Ref(ret);
  bdd = (BDD *)PyObject_CallObject((PyObject *)&BDDType, NULL);
  Cudd_Deref(bdd->root);
  bdd->root = ret;
  return (PyObject *)bdd;
}

static PyObject *subtract_recursive(PyObject *Py_UNUSED(self), PyObject *args) {
  PyObject *a = NULL, *b = NULL;
  if (!PyArg_ParseTuple(args, "OO", &a, &b))
    return NULL;
  return bsubtract_recursive(a, b);
}

static PyObject *osubtract_recursive(PyObject *self, PyObject *args) {
  PyObject *b = NULL;
  if (!PyArg_ParseTuple(args, "O", &b))
    return NULL;
  return bsubtract_recursive(self, b);
}

static PyObject *bdifftagged_recursive(PyObject *a, PyObject *b) {
  BDD *bdd;
  READY_BDD_TYPE(a);
  READY_BDD_TYPE(b);
  DdNode *ret = Cudd_addApply(cudd_manager, Cudd_addDiffTagged,
                              ((BDD *)a)->root, ((BDD *)b)->root);
  Cudd_Ref(ret);
  bdd = (BDD *)PyObject_CallObject((PyObject *)&BDDType, NULL);
  Cudd_Deref(bdd->root);
  bdd->root = ret;
  return (PyObject *)bdd;
}

static PyObject *difftagged_recursive(PyObject *Py_UNUSED(self),
                                      PyObject *args) {
  PyObject *a = NULL, *b = NULL;
  if (!PyArg_ParseTuple(args, "OO", &a, &b))
    return NULL;
  return bdifftagged_recursive(a, b);
}

static PyObject *odifftagged_recursive(PyObject *self, PyObject *args) {
  PyObject *b = NULL;
  if (!PyArg_ParseTuple(args, "O", &b))
    return NULL;
  return bdifftagged_recursive(self, b);
}

static PyObject *bintersection_recursive(PyObject *a, PyObject *b) {
  BDD *bdd;
  READY_BDD_TYPE(a);
  READY_BDD_TYPE(b);
  DdNode *ret = Cudd_addApply(cudd_manager, Cudd_addIntersection,
                              ((BDD *)a)->root, ((BDD *)b)->root);
  Cudd_Ref(ret);
  bdd = (BDD *)PyObject_CallObject((PyObject *)&BDDType, NULL);
  Cudd_Deref(bdd->root);
  bdd->root = ret;
  return (PyObject *)bdd;
}

static PyObject *intersection_recursive(PyObject *Py_UNUSED(self),
                                        PyObject *args) {
  PyObject *a = NULL, *b = NULL;
  if (!PyArg_ParseTuple(args, "OO", &a, &b))
    return NULL;
  return bintersection_recursive(a, b);
}

static PyObject *ointersection_recursive(PyObject *self, PyObject *args) {
  PyObject *b = NULL;
  if (!PyArg_ParseTuple(args, "O", &b))
    return NULL;
  return bintersection_recursive(self, b);
}

#if PyLong_SHIFT % 2 != 0
#error "This code assumes PyLong_SHIFT is even (likely = 30), but it is " PyLong_SHIFT
#endif

static PyObject *wc_to_BDD(PyObject *Py_UNUSED(self), PyObject *args) {
  PyObject *_wc;
  int term;
  long tot_bits, offset = 0;
  DdNode *f, *tmp;
  if (!PyArg_ParseTuple(args, "Oil", &_wc, &term, &tot_bits))
    return NULL;
  // Python longs are variable sized objects the
  // sign is housed in the size
  // The number is split into PyLong_SHIFT sized chunks
  // So some space is wasted.
  // -.ob_digit houses the start of the variable sized digits
  assert(tot_bits * 2 / PyLong_SHIFT == Py_Size(wc) ||
         (tot_bits * 2 / PyLong_SHIFT) + 1 == Py_Size(wc));

  PyLongObject *wc = (PyLongObject *)_wc;
  f = Cudd_addConst(cudd_manager,
                    ENCODE_TERMINAL(term, 0)); // Get a BDD pointing to term
  Cudd_Ref(f);
  for (; tot_bits;) {
    tot_bits--;
    digit d = wc->ob_digit[(offset * 2) / PyLong_SHIFT];
    d = d >> ((offset * 2) % PyLong_SHIFT);
    d &= 0x3;
    if (d == 0x1) {
      tmp = cuddUniqueInter(cudd_manager, tot_bits, BK, f);
      Cudd_Ref(tmp); // TODO should we be increasing the Ref here
      f = tmp;       // I think maybe not until the end?
    } else if (d == 0x2) {
      tmp = cuddUniqueInter(cudd_manager, tot_bits, f, BK);
      Cudd_Ref(tmp);
      f = tmp;
    }
    offset++;
  }
  BDD *bdd;
  bdd = (BDD *)PyObject_CallObject((PyObject *)&BDDType, NULL);
  Cudd_Deref(bdd->root); // Always NULL noop right?
  bdd->root = f;
  return (PyObject *)bdd;
}

static PyObject *print_info(PyObject *Py_UNUSED(self),
                            PyObject *Py_UNUSED(args)) {
  Cudd_PrintInfo(cudd_manager, stderr);
  Py_RETURN_NONE;
}

static PyObject *max_memory(PyObject *Py_UNUSED(self),
                            PyObject *Py_UNUSED(args)) {
  unsigned long a = Cudd_ReadMaxMemory(cudd_manager);
  return Py_BuildValue("k", a);
}

static PyObject *set_maxcache(PyObject *Py_UNUSED(self), PyObject *args) {
  unsigned int a;
  if (!PyArg_ParseTuple(args, "I", &a))
    return NULL;

  Cudd_SetMaxCacheHard(cudd_manager, a);
  Py_RETURN_NONE;
}

static PyMethodDef cBDDMethods[] = {
    {"meld_recursive", meld_recursive, METH_VARARGS, "Merge BDDs"},
    {"difference_recursive", difference_recursive, METH_VARARGS,
     "Returns a BDD of the difference between two BDDs.\n\n"
     "The returned BDD has the differing portion set to DIFFERS,"
     "otherwise NULL."},
    {"difftagged_recursive", difftagged_recursive, METH_VARARGS,
     "Returns a tagged BDD of the difference between two BDDs.\n\n"
     "The returned BDD encodes differing portions with both "
     "conflicting actions. While matching portions are NULL."},
    {"subtract_recursive", subtract_recursive, METH_VARARGS, "Subtract BDDs"},
    {"intersection_recursive", intersection_recursive, METH_VARARGS,
     "Intersect BDDs"},
    {"print_info", print_info, METH_NOARGS, "Prints info from cudd"},
    {"max_memory", max_memory, METH_NOARGS,
     "Reads the max memory set for CUDD"},
    {"set_maxcache", set_maxcache, METH_VARARGS, "Set the maximum cache size"},
    {"wc_to_BDD", wc_to_BDD, METH_VARARGS, "WC to BDD"},
    {"BDD_to_wcs", BDD_to_wcs, METH_VARARGS, "BDD to WCS"},
    {"shared_size", BDD_shared_size, METH_VARARGS,
     "Returns the node count of a list of nodes"},
    {0}};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    MODULE_NAME_S,
    NULL,
    -1, // Per module state
    cBDDMethods,
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
  m = Py_InitModule(MODULE_NAME_S, cBDDMethods);
#endif
  if (PyType_Ready(&BDDType) < 0)
    return NULL;
  Py_INCREF(&BDDType);

  PyModule_AddObject(m, "BDD", (PyObject *)&BDDType);

  if (PyType_Ready(&BDDIteratorType) < 0)
    return NULL;
  Py_INCREF(&BDDIteratorType);
  PyModule_AddObject(m, "BDDIterator", (PyObject *)&BDDIteratorType);

  /* Init CUDD TODO change number of vars to match with length from
   * python */
  cudd_manager =
      Cudd_Init(0,                 // Number of vars
                0,                 // Vars for ZDD
                CUDD_UNIQUE_SLOTS, // Node cache size, will auto grow
                CUDD_CACHE_SLOTS,  // Operation cache size, will auto grow
                0 // maxMemory - 0 = CUDD will guess from available memory
                );
  // Create a ADD node number 1 pointing true to 1 and false to 0
  DIFFERS = Cudd_addConst(cudd_manager, ENCODE_TERMINAL(1, 0));
  Cudd_Ref(DIFFERS);
  PyLong1 = PyLong_FromLong(1);
  PyLong2 = PyLong_FromLong(2);
  BK = Cudd_ReadBackground(cudd_manager);
  return m;
}

#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC GLUE(PyInit_, MODULE_NAME)(void) { return moduleinit(); }
#else
PyMODINIT_FUNC GLUE(init, MODULE_NAME)(void) { moduleinit(); }
#endif
