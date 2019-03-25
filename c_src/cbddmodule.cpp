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
#include <structmember.h>
#include <unordered_set>
#include <vector>

/* TODO Update globals to the new Python3 style */

#define MODULE_NAME _cbdd
#define _STRINGIZE(a) #a
#define STRINGIZE(a) _STRINGIZE(a)
#define MODULE_NAME_S STRINGIZE(MODULE_NAME)

/* Define options modify setup.py extra_flags with -D to
 * add a define.
 */
// Enable the meld cache?
#ifndef MC
#define MC 1
#endif
// Enable difference cache?
#ifndef DC
#define DC 1
#endif
// Enable intersection cache?
#ifndef IC
#define IC 1
#endif

#ifndef AUTO_CLEANUP
#define AUTO_CLEANUP 1
#endif

// A large number stored in BDDTERM to represent the end of processing
// Making it large typically also means it works with the normal logic
#define BDDTERM_NUM 1000000000000L
#define NULL2NONE(x) ((x) ? (x) : Py_None)
#define NONE2NULL(x) ((x != Py_None) ? (x) : NULL)

#ifndef Py_UNUSED /* This is already defined for Python 3.4 onwards */
#ifdef __GNUC__
#define Py_UNUSED(name) _unused_##name __attribute__((unused))
#else
#define Py_UNUSED(name) _unused_##name
#endif
#endif

/* !!! Create a BDDNode type !!! */
typedef struct _BDDNODE BDDNode;
typedef struct _BDDNODE {
  PyObject_HEAD BDDNode *zero;
  BDDNode *one;
  long num;
  char has_none;
} BDDNode;

static PyMemberDef BDDNode_members[] = {
    {"zero", T_OBJECT, offsetof(BDDNode, zero), 0, "zero"},
    {"one", T_OBJECT, offsetof(BDDNode, one), 0, "one"},
    {"num", T_LONG, offsetof(BDDNode, num), 0, "num"},
    {"has_none", T_BOOL, offsetof(BDDNode, has_none), 0, "has_zero"},
    {}};

static void BDDNode_dealloc(BDDNode *self);
static PyObject *BDDNode_new(PyTypeObject *type, PyObject *args,
                             PyObject *kwds);
static int BDDNode_init(BDDNode *self, PyObject *args, PyObject *kwds);
static long BDDNode_hash(PyObject *self);
static PyObject *BDDNode_richcmp(PyObject *a, PyObject *b, int op);

// 1m seems decent, this tends to come down to approx 200k once cleaned
static Py_ssize_t cleanup_threshold = 1000000;
static PyObject *NODE_CACHE = NULL;
static PyObject *RULE_CACHE = NULL;
static PyObject *MERGE_CACHE = NULL;
static PyObject *DIFFERENCE_CACHE = NULL;
static PyObject *INTERSECTION_CACHE = NULL;
static BDDNode *IS_DIFFERING = NULL;

static PyTypeObject BDDNodeType = {
    PyVarObject_HEAD_INIT(NULL, 0) MODULE_NAME_S ".BDDNode", /* tp_name */
    sizeof(BDDNode),                                         /* tp_basicsize */
    0,                                                       /* tp_itemsize */
    (destructor)BDDNode_dealloc,                             /* tp_dealloc */
    0,                                                       /* tp_print */
    0,                                                       /* tp_getattr */
    0,                                                       /* tp_setattr */
    0,                                                       /* tp_compare */
    0,                                                       /* tp_repr */
    0,                                                       /* tp_as_number */
    0,                      /* tp_as_sequence */
    0,                      /* tp_as_mapping */
    BDDNode_hash,           /* tp_hash */
    0,                      /* tp_call */
    0,                      /* tp_str */
    0,                      /* tp_getattro */
    0,                      /* tp_setattro */
    0,                      /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,     /* tp_flags */
    "A BDDNode",            /* tp_doc */
    0,                      /* tp_traverse */
    0,                      /* tp_clear */
    BDDNode_richcmp,        /* tp_richcompare */
    0,                      /* tp_weaklistoffset */
    0,                      /* tp_iter */
    0,                      /* tp_iternext */
    0,                      /* tp_methods */
    BDDNode_members,        /* tp_members */
    0,                      /* tp_getset */
    0,                      /* tp_base */
    0,                      /* tp_dict */
    0,                      /* tp_descr_get */
    0,                      /* tp_descr_set */
    0,                      /* tp_dictoffset */
    (initproc)BDDNode_init, /* tp_init */
    0,                      /* tp_alloc */
    BDDNode_new,            /* tp_new */
};

static void BDDNode_dealloc(BDDNode *self) {
  // printf("Dalloc Node\n");
  Py_XDECREF((PyObject *)self->zero);
  Py_XDECREF((PyObject *)self->one);
  Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *BDDNode_new(PyTypeObject *type, PyObject *Py_UNUSED(args),
                             PyObject *Py_UNUSED(kwds)) {
  BDDNode *self;

  self = (BDDNode *)type->tp_alloc(type, 0);
  if (self != NULL) {
    self->zero = NULL;
    self->one = NULL;
    self->num = -1;
    self->has_none = -1;
  }
  return (PyObject *)self;
}

static int BDDNode_init(BDDNode *self, PyObject *args, PyObject *kwds) {
  PyObject *zero = NULL, *one = NULL, *tmp;
  long num;

  static const char *kwlist[] = {"num", "zero", "one", NULL};
  if (!PyArg_ParseTupleAndKeywords(
          args, kwds, "l|OO", const_cast<char **>(kwlist), &num, &zero, &one))
    return -1;

  if (zero == Py_None)
    zero = NULL;
  if (one == Py_None)
    one = NULL;

  if (zero) {
    if (PyObject_IsInstance(zero, (PyObject *)&BDDNodeType) != 1)
      return -1;
    tmp = (PyObject *)self->zero;
    Py_INCREF(zero);
    self->zero = (BDDNode *)zero;
    Py_XDECREF(tmp);
  }
  if (one) {
    if (PyObject_IsInstance(one, (PyObject *)&BDDNodeType) != 1)
      return -1;
    tmp = (PyObject *)self->one;
    Py_INCREF(one);
    self->one = (BDDNode *)one;
    Py_XDECREF(tmp);
  }
  self->num = num;
  self->has_none =
      (zero ? self->zero->has_none : 1) | (one ? self->one->has_none : 1);
  return 0;
}

#define LONG_HASH(x) ((x) == -1L ? -2L : (x))
static long BDDNode_hash(PyObject *self) {
  /* hash((num, id(zero), id(one)) */
  BDDNode *s = (BDDNode *)self;
  long x = 0x345678L;

  /* Use the tuple method inline */
  x = (x ^ LONG_HASH(s->num)) * 1000003L;
  x = (x ^ LONG_HASH((long)s->zero)) * 1082527L;
  x = (x ^ LONG_HASH((long)s->one)) * 1165049L;

  x += 97531L;
  return LONG_HASH(x);
}

static PyObject *BDDNode_richcmp(PyObject *a, PyObject *b, int op) {
  PyObject *res = Py_NotImplemented;

  if (op == Py_EQ && PyObject_IsInstance(b, (PyObject *)&BDDNodeType)) {
    BDDNode *_a = (BDDNode *)a, *_b = (BDDNode *)b;
    if (_a->num == _b->num && _a->zero == _b->zero && _a->one == _b->one)
      res = Py_True;
    else
      res = Py_False;
  }
  if (op == Py_NE && PyObject_IsInstance(b, (PyObject *)&BDDNodeType)) {
    BDDNode *_a = (BDDNode *)a, *_b = (BDDNode *)b;
    if (_a->num == _b->num && _a->zero == _b->zero && _a->one == _b->one)
      res = Py_False;
    else
      res = Py_True;
  }
  Py_INCREF(res);
  return res;
}

/* !!! Create a BDDTermination type !!! */
typedef struct _BDDTERM {
  BDDNode node;
  PyObject *action;
  PyObject *friendly;
} BDDTerm;

static PyMemberDef BDDTerm_members[] = {
    //	{"zero", T_OBJECT, offsetof(BDDNode, zero), 0, "zero"},
    //	{"one", T_OBJECT, offsetof(BDDNode, one), 0, "one"},
    //	{"num", T_LONG, offsetof(BDDNode, num), 0, "num"},
    //	{"has_none", T_BOOL, offsetof(BDDNode, has_none), 0, "has_zero"},
    {"action", T_OBJECT_EX, offsetof(BDDTerm, action), 0, "action"},
    {"friendly", T_OBJECT_EX, offsetof(BDDTerm, friendly), 0, "friendly"},
    {}};

static void BDDTerm_dealloc(BDDTerm *self);
static PyObject *BDDTerm_new(PyTypeObject *type, PyObject *args,
                             PyObject *kwds);
static int BDDTerm_init(BDDTerm *self, PyObject *args, PyObject *kwds);
static long BDDTerm_hash(PyObject *self);
static PyObject *BDDTerm_richcmp(PyObject *a, PyObject *b, int op);

static PyTypeObject BDDTermType = {
    PyVarObject_HEAD_INIT(NULL, 0) MODULE_NAME_S
    ".BDDTermination",           /* tp_name */
    sizeof(BDDTerm),             /* tp_basicsize */
    0,                           /* tp_itemsize */
    (destructor)BDDTerm_dealloc, /* tp_dealloc */
    0,                           /* tp_print */
    0,                           /* tp_getattr */
    0,                           /* tp_setattr */
    0,                           /* tp_compare */
    0,                           /* tp_repr */
    0,                           /* tp_as_number */
    0,                           /* tp_as_sequence */
    0,                           /* tp_as_mapping */
    BDDTerm_hash,                /* tp_hash */
    0,                           /* tp_call */
    0,                           /* tp_str */
    0,                           /* tp_getattro */
    0,                           /* tp_setattro */
    0,                           /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,          /* tp_flags */
    "A BDDNode",                 /* tp_doc */
    0,                           /* tp_traverse */
    0,                           /* tp_clear */
    BDDTerm_richcmp,             /* tp_richcompare */
    0,                           /* tp_weaklistoffset */
    0,                           /* tp_iter */
    0,                           /* tp_iternext */
    0,                           /* tp_methods */
    BDDTerm_members,             /* tp_members */
    0,                           /* tp_getset */
    &BDDNodeType,                /* tp_base */
    0,                           /* tp_dict */
    0,                           /* tp_descr_get */
    0,                           /* tp_descr_set */
    0,                           /* tp_dictoffset */
    (initproc)BDDTerm_init,      /* tp_init */
    0,                           /* tp_alloc */
    BDDTerm_new,                 /* tp_new */
};

static void BDDTerm_dealloc(BDDTerm *self) {
  // printf("Dalloc Term\n");
  Py_XDECREF((PyObject *)self->action);
  Py_XDECREF((PyObject *)self->friendly);
  Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *BDDTerm_new(PyTypeObject *type, PyObject *Py_UNUSED(args),
                             PyObject *Py_UNUSED(kwds)) {
  BDDTerm *self;

  self = (BDDTerm *)type->tp_alloc(type, 0);
  if (self != NULL) {
    self->node.zero = NULL;
    self->node.one = NULL;
    self->node.num = BDDTERM_NUM;
    self->node.has_none = 0;
    self->action = NULL;
    self->friendly = NULL;
  }
  return (PyObject *)self;
}

static int BDDTerm_init(BDDTerm *self, PyObject *args, PyObject *kwds) {
  PyObject *action = NULL, *friendly = NULL, *tmp;

  static const char *kwlist[] = {"action", "friendly", NULL};
  if (!PyArg_ParseTupleAndKeywords(
          args, kwds, "OO", const_cast<char **>(kwlist), &action, &friendly))
    return -1;

  if (action) {
    tmp = self->action;
    Py_INCREF(action);
    self->action = action;
    Py_XDECREF(tmp);
  }
  if (friendly) {
    tmp = self->friendly;
    Py_INCREF(friendly);
    self->friendly = friendly;
    Py_XDECREF(tmp);
  }
  return 0;
}

static long BDDTerm_hash(PyObject *self) {
  /* No hash return 0, hash object if possible */
  BDDTerm *s = (BDDTerm *)self;
  long hash = PyObject_Hash(s->action);
  if (hash != -1) {
    return hash;
  } else {
    hash = PyObject_Hash(s->friendly);
    PyErr_Clear();
    return hash = -1 ? 0 : hash;
  }
}

static PyObject *BDDTerm_richcmp(PyObject *a, PyObject *b, int op) {
  PyObject *res = Py_NotImplemented;

  if ((op == Py_EQ || op == Py_NE) &&
      PyObject_IsInstance(b, (PyObject *)&BDDTermType)) {
    BDDTerm *_a = (BDDTerm *)a, *_b = (BDDTerm *)b;
    return PyObject_RichCompare(_a->action, _b->action, op);
  }
  Py_INCREF(res);
  return res;
}

struct HashBDDNode {
  size_t operator()(BDDNode *const &a) const {
    if (Py_TYPE(a) == &BDDNodeType)
      return BDDNode_hash((PyObject *)a);
    else
      return BDDTerm_hash((PyObject *)a);
  }
};
struct EqualBDDNode {
  bool operator()(BDDNode *const &a, BDDNode *const &b) const {
    if (Py_TYPE(a) != Py_TYPE(b))
      return false;
    if (Py_TYPE(a) == &BDDNodeType)
      return a->zero == b->zero && a->one == b->one && a->num == b->num;
    else
      return BDDTerm_richcmp((PyObject *)a, (PyObject *)b, Py_EQ);
  }
};
static std::unordered_set<BDDNode *, HashBDDNode, EqualBDDNode> node_cache;

/* Returns a BDD node
 *
 * BORROWED REFERENCE
 */
static BDDNode *get_node(long num, BDDNode *zero, BDDNode *one) {
  if (zero == one) {
    return zero;
  }
  static BDDNode tmp = {PyObject_HEAD_INIT(&BDDNodeType) NULL, NULL, 0, 0};
  tmp.num = num;
  tmp.zero = zero;
  tmp.one = one;

  PyObject *r;
  // Make a node
  /*
  auto found = node_cache.find(&tmp);
  if (found != node_cache.end()) {
          return *found;
  } else {
          BDDNode *n;
          n = PyObject_New(BDDNode, &BDDNodeType);
          n->num = num;
          n->zero = zero;
          n->one = one;
          Py_XINCREF(zero);
          Py_XINCREF(one);
          // Make sure we populate has_none
          n->has_none = (zero ? n->zero->has_none : 1) |
                        (one ? n->one->has_none : 1);
          node_cache.emplace(n);
          // Ensure our cache always has a ref so don't throw it
          return n;
  }*/

  r = PyDict_GetItem(NODE_CACHE, (PyObject *)&tmp);
  if (r) {
    // Py_DECREF((PyObject *) n);
    return (BDDNode *)r;
  } else {
    BDDNode *n;
    n = PyObject_New(BDDNode, &BDDNodeType);
    n->num = num;
    n->zero = zero;
    n->one = one;
    Py_XINCREF(zero);
    Py_XINCREF(one);
    // Make sure we populate has_none
    n->has_none = (zero ? n->zero->has_none : 1) | (one ? n->one->has_none : 1);
    PyDict_SetItem(NODE_CACHE, (PyObject *)n, (PyObject *)n);
    // The dict grabs 2 refs, we undo our original ref
    Py_DECREF((PyObject *)n);
    return n;
  }
}

/* Returns a BDDNode with the meld applied
 * For internal usage, a and b must not be set to Py_None instead they should be
 * converted
 * to NULL before calling. They can however be either BDDNodes or Terminations.
 *
 * This returns a Borrowed Reference (increase it before returning to the user).
 * This is safe as the NODE_CACHE always holds two references.
 */
static BDDNode *_meld_recursive(BDDNode *a, BDDNode *b) {
  BDDNode *n;
  // Termination conditions
  if (a == NULL)
    return b;
  if (b == NULL)
    return a;
  if (!a->has_none)
    return a;
#if MC
  PyObject *key =
      Py_BuildValue("(OO)", NULL2NONE((PyObject *)a), NULL2NONE((PyObject *)b));
  PyObject *cached = PyObject_GetItem(MERGE_CACHE, key);
  if (cached != NULL) {
    Py_DECREF(key); // No longer in use
    // DECREF to ensure we return a borrowed reference.
    Py_DECREF(cached);
    return (BDDNode *)NONE2NULL(cached);
  }
  // PyObject_GetItem will set an error if not found so clear it.
  PyErr_Clear();
#endif

  if (a->num == b->num) {
    n = get_node(a->num, _meld_recursive(a->zero, b->zero),
                 _meld_recursive(a->one, b->one));
#if MC
    PyObject_SetItem(MERGE_CACHE, key, NULL2NONE((PyObject *)n));
    Py_DECREF(key);
#endif
    return n;
  } else if (a->num < b->num) {
    n = get_node(a->num, _meld_recursive(a->zero, b),
                 _meld_recursive(a->one, b));
#if MC
    PyObject_SetItem(MERGE_CACHE, key, NULL2NONE((PyObject *)n));
    Py_DECREF(key);
#endif
    return n;
  } else {
    assert(a->num > b->num);
    assert(b->num < BDDTERM_NUM);
    n = get_node(b->num, _meld_recursive(a, b->zero),
                 _meld_recursive(a, b->one));
#if MC
    PyObject_SetItem(MERGE_CACHE, key, NULL2NONE((PyObject *)n));
    Py_DECREF(key);
#endif
    return n;
  }
  printf("Unreachable!!\n");
}

static BDDNode *_difference_recursive(BDDNode *a, BDDNode *b) {
  BDDNode *n;
  // Termination conditions
  // Remove identical portions, this also handles a == NULL, b == NULL
  if (a == b)
    return NULL;
  if (a == NULL)
    // TODO Should we not duplicate out B?
    return IS_DIFFERING;
  // B is NULL (obviously different), so continue walking down the tree to
  // duplicate out the A side
  if (b == NULL) {
    if (a->num == BDDTERM_NUM) {
      return IS_DIFFERING;
    }
  } else {
    // At different terminals
    if (a->num == BDDTERM_NUM && b->num == BDDTERM_NUM)
      return IS_DIFFERING;
  }

#if DC
  PyObject *key =
      Py_BuildValue("(OO)", NULL2NONE((PyObject *)a), NULL2NONE((PyObject *)b));
  // PyObject *key = Py_BuildValue("(ll)", (long) a, (long) b);
  PyObject *cached = PyObject_GetItem(DIFFERENCE_CACHE, key);
  if (cached != NULL) {
    Py_DECREF(key); // No longer in use
    // DECREF to ensure we return a borrowed reference.
    Py_DECREF(cached);
    return (BDDNode *)NONE2NULL(cached);
  }
  // PyObject_GetItem will set an error if not found so clear it.
  PyErr_Clear();
#endif
  if (b == NULL) { /* B == NULL and A is not a terminal or NULL */
    n = get_node(a->num, _difference_recursive(a->zero, NULL),
                 _difference_recursive(a->one, NULL));
#if DC
    PyObject_SetItem(DIFFERENCE_CACHE, key, NULL2NONE((PyObject *)n));
    Py_DECREF(key);
#endif
    return n;
  }

  if (a->num == b->num) {
    n = get_node(a->num, _difference_recursive(a->zero, b->zero),
                 _difference_recursive(a->one, b->one));
#if DC
    PyObject_SetItem(DIFFERENCE_CACHE, key, NULL2NONE((PyObject *)n));
    Py_DECREF(key);
#endif
    return n;
  } else if (a->num < b->num) {
    n = get_node(a->num, _difference_recursive(a->zero, b),
                 _difference_recursive(a->one, b));
#if DC
    PyObject_SetItem(DIFFERENCE_CACHE, key, NULL2NONE((PyObject *)n));
    Py_DECREF(key);
#endif
    return n;
  } else {
    assert(a->num > b->num);
    assert(b->num < BDDTERM_NUM);
    n = get_node(b->num, _difference_recursive(a, b->zero),
                 _difference_recursive(a, b->one));
#if DC
    PyObject_SetItem(DIFFERENCE_CACHE, key, NULL2NONE((PyObject *)n));
    Py_DECREF(key);
#endif
    return n;
  }
  printf("Unreachable!!\n");
}

#define SC 0
static BDDNode *_subtract_recursive(BDDNode *a, BDDNode *b) {
  BDDNode *n;
  // Termination conditions
  // Remove identical portions, this also handles a == NULL, b == NULL
  if (a == b)
    return NULL;
  if (a == NULL)
    // As A is empty, there is nothing in A that is not in B
    // However, could still be something in B not in A.
    return NULL;
  // B is NULL (obviously different), so continue return the A side
  if (b == NULL) {
    return a;
  } else {
    // At different terminals, return A as it is in A not B
    if (a->num == BDDTERM_NUM && b->num == BDDTERM_NUM)
      return a;
  }

#if SC
  PyObject *key =
      Py_BuildValue("(OO)", NULL2NONE((PyObject *)a), NULL2NONE((PyObject *)b));
  // PyObject *key = Py_BuildValue("(ll)", (long) a, (long) b);
  PyObject *cached = PyObject_GetItem(SUBTRACT_CACHE, key);
  if (cached != NULL) {
    Py_DECREF(key); // No longer in use
    // DECREF to ensure we return a borrowed reference.
    Py_DECREF(cached);
    return (BDDNode *)NONE2NULL(cached);
  }
  // PyObject_GetItem will set an error if not found so clear it.
  PyErr_Clear();
#endif

  if (a->num == b->num) {
    n = get_node(a->num, _subtract_recursive(a->zero, b->zero),
                 _subtract_recursive(a->one, b->one));
#if SC
    PyObject_SetItem(SUBTRACT_CACHE, key, NULL2NONE((PyObject *)n));
    Py_DECREF(key);
#endif
    return n;
  } else if (a->num < b->num) {
    n = get_node(a->num, _subtract_recursive(a->zero, b),
                 _subtract_recursive(a->one, b));
#if SC
    PyObject_SetItem(SUBTRACT_CACHE, key, NULL2NONE((PyObject *)n));
    Py_DECREF(key);
#endif
    return n;
  } else {
    assert(a->num > b->num);
    assert(b->num < BDDTERM_NUM);
    n = get_node(b->num, _subtract_recursive(a, b->zero),
                 _subtract_recursive(a, b->one));
#if SC
    PyObject_SetItem(SUBTRACT_CACHE, key, NULL2NONE((PyObject *)n));
    Py_DECREF(key);
#endif
    return n;
  }
  printf("Unreachable!!\n");
}

static BDDNode *_intersection_recursive(BDDNode *a, BDDNode *b) {
  BDDNode *n;
  // Termination conditions
  if (a == NULL || b == NULL)
    return NULL;
  if (a == b)
    return a;

#if IC
  PyObject *key =
      Py_BuildValue("(OO)", NULL2NONE((PyObject *)a), NULL2NONE((PyObject *)b));
  // PyObject *key = Py_BuildValue("(ll)", (long) a, (long) b);
  PyObject *cached = PyObject_GetItem(INTERSECTION_CACHE, key);
  if (cached != NULL) {
    Py_DECREF(key); // No longer in use
    // DECREF to ensure we return a borrowed reference.
    Py_DECREF(cached);
    return (BDDNode *)NONE2NULL(cached);
  }
  // PyObject_GetItem will set an error if not found so clear it.
  PyErr_Clear();
#endif

  if (a->num == b->num) {
    n = get_node(a->num, _intersection_recursive(a->zero, b->zero),
                 _intersection_recursive(a->one, b->one));
#if IC
    PyObject_SetItem(INTERSECTION_CACHE, key, NULL2NONE((PyObject *)n));
    Py_DECREF(key);
#endif
    return n;
  } else if (a->num < b->num) {
    n = get_node(a->num, _intersection_recursive(a->zero, b),
                 _intersection_recursive(a->one, b));
#if IC
    PyObject_SetItem(INTERSECTION_CACHE, key, NULL2NONE((PyObject *)n));
    Py_DECREF(key);
#endif
    return n;
  } else {
    assert(a->num > b->num);
    assert(b->num < BDDTERM_NUM);
    n = get_node(b->num, _intersection_recursive(a, b->zero),
                 _intersection_recursive(a, b->one));
#if IC
    PyObject_SetItem(INTERSECTION_CACHE, key, NULL2NONE((PyObject *)n));
    Py_DECREF(key);
#endif
    return n;
  }
  printf("Unreachable!!\n");
}

// Check the type is correct and convert Py_None to NULL
#define READY_BDD_TYPE(x)                                                      \
  if (!PyObject_IsInstance((PyObject *)(x), (PyObject *)&BDDNodeType)) {       \
    if ((PyObject *)(x) == Py_None) {                                          \
      (x) = NULL;                                                              \
    } else {                                                                   \
      PyErr_BadArgument();                                                     \
      return NULL;                                                             \
    }                                                                          \
  }

// Returns a BDDNode, Py_None, or an error as appropriate
#define RETURN_BDD_NODE(x)                                                     \
  if (PyErr_Occurred()) {                                                      \
    return NULL;                                                               \
  } else if ((x) == NULL) {                                                    \
    (x) = Py_None;                                                             \
  }                                                                            \
  Py_INCREF((x));                                                              \
  return (x);

static PyObject *gc_node_cache(PyObject *Py_UNUSED(self),
                               PyObject *Py_UNUSED(args)) {
  PyObject *key, *value;
  Py_ssize_t pos = 0;
  std::vector<BDDNode *> to_remove;
  std::vector<BDDNode *> to_remove_next;
  int removed = 0;

  while (PyDict_Next(NODE_CACHE, &pos, &key, &value)) {
    /* Collect all nodes with only 2 ref counts */
    assert(key == value);
    if (Py_REFCNT(key) == 2) {
      to_remove_next.push_back((BDDNode *)key);
    }
  }

  while (to_remove_next.size()) {
    std::swap(to_remove, to_remove_next);
    for (BDDNode *x : to_remove) {
      assert(Py_REFCNT(x) == 2);
      if (x->zero && Py_REFCNT(x->zero) == 3) {
        to_remove_next.push_back(x->zero);
      }
      if (x->one && Py_REFCNT(x->one) == 3) {
        to_remove_next.push_back(x->one);
      }
      // x->zero == x->one is not possible as this node
      // would be omitted
      PyDict_DelItem(NODE_CACHE, (PyObject *)x);
      removed++;
    }
    to_remove.clear();
  }
  printf("Removed %d nodes now %d\n", removed, (int)PyDict_Size(NODE_CACHE));
  Py_RETURN_NONE;
}

static inline void memory_cleanup() {
#if AUTO_CLEANUP
  if (cleanup_threshold && PyDict_Size(NODE_CACHE) > cleanup_threshold) {
    Py_DECREF(gc_node_cache(NULL, NULL));
  }
#endif
}

/** Meld two BDDs together
 *
 * This wraps the internal version into the python interface.
 * Accepts two arguments, and returns the result of merging the second
 * in to the first. With the first taking priority.
 */
static PyObject *meld_recursive(PyObject *Py_UNUSED(self), PyObject *args) {
  BDDNode *a = NULL, *b = NULL;
  PyObject *res;
  if (!PyArg_ParseTuple(args, "OO", &a, &b))
    return NULL;
  READY_BDD_TYPE(a);
  READY_BDD_TYPE(b);
  memory_cleanup();
  res = (PyObject *)_meld_recursive((BDDNode *)a, (BDDNode *)b);
  RETURN_BDD_NODE(res);
}

static PyObject *difference_recursive(PyObject *Py_UNUSED(self),
                                      PyObject *args) {
  BDDNode *a = NULL, *b = NULL;
  PyObject *res;
  if (!PyArg_ParseTuple(args, "OO", &a, &b))
    return NULL;
  READY_BDD_TYPE(a);
  READY_BDD_TYPE(b);
  memory_cleanup();
  res = (PyObject *)_difference_recursive((BDDNode *)a, (BDDNode *)b);
  RETURN_BDD_NODE(res);
}

static PyObject *subtract_recursive(PyObject *Py_UNUSED(self), PyObject *args) {
  /* Return packets in A but not in B
      Things to note if a path in B has a different result it will be
      detected.
  */
  BDDNode *a = NULL, *b = NULL;
  PyObject *res;
  if (!PyArg_ParseTuple(args, "OO", &a, &b))
    return NULL;
  READY_BDD_TYPE(a);
  READY_BDD_TYPE(b);
  memory_cleanup();
  res = (PyObject *)_subtract_recursive((BDDNode *)a, (BDDNode *)b);
  RETURN_BDD_NODE(res);
}

static PyObject *intersection_recursive(PyObject *Py_UNUSED(self),
                                        PyObject *args) {
  BDDNode *a = NULL, *b = NULL;
  PyObject *res;
  if (!PyArg_ParseTuple(args, "OO", &a, &b))
    return NULL;
  READY_BDD_TYPE(a);
  READY_BDD_TYPE(b);
  memory_cleanup();
  res = (PyObject *)_intersection_recursive((BDDNode *)a, (BDDNode *)b);
  RETURN_BDD_NODE(res);
}

#if PyLong_SHIFT % 2 != 0
#error "This code assumes PyLong_SHIFT is even (likely = 30), but it is " PyLong_SHIFT
#endif

static PyObject *wc_to_BDD(PyObject *Py_UNUSED(self), PyObject *args) {
  PyObject *_wc, *term;
  long tot_bits, offset = 0;
  if (!PyArg_ParseTuple(args, "OOl", &_wc, &term, &tot_bits))
    return NULL;
  // Python longs are variable sized objects the
  // sign is housed in the size
  // The number is split into PyLong_SHIFT sized chunks
  // So some space is wasted.
  // -.ob_digit houses the start of the variable sized digits
  assert(tot_bits * 2 / PyLong_SHIFT == Py_Size(wc) ||
         (tot_bits * 2 / PyLong_SHIFT) + 1 == Py_Size(wc));

  PyLongObject *wc = (PyLongObject *)_wc;
  BDDNode *cnode = (BDDNode *)term;
  for (; tot_bits;) {
    tot_bits--;
    digit d = wc->ob_digit[(offset * 2) / PyLong_SHIFT];
    d = d >> ((offset * 2) % PyLong_SHIFT);
    d &= 0x3;
    if (d == 0x1) {
      cnode = get_node(tot_bits, cnode, NULL);
    } else if (d == 0x2) {
      cnode = get_node(tot_bits, NULL, cnode);
    }
    offset++;
  };
  Py_INCREF((PyObject *)cnode);
  return (PyObject *)cnode;
}

static PyObject *set_cleanup_threshold(PyObject *Py_UNUSED(self),
                                       PyObject *args) {
  if (!PyArg_ParseTuple(args, "n", &cleanup_threshold))
    return NULL;
  if (cleanup_threshold < 0) {
    PyErr_SetString(PyExc_ValueError, "The threshold must be positive");
    return NULL;
  }
  Py_RETURN_NONE;
}

static PyObject *get_cleanup_threshold(PyObject *Py_UNUSED(self),
                                       PyObject *Py_UNUSED(unused)) {
  return PyLong_FromSsize_t(cleanup_threshold);
}

static PyMethodDef cBDDMethods[] = {
    {"meld_recursive", meld_recursive, METH_VARARGS, "Merge BDDs"},
    {"difference_recursive", difference_recursive, METH_VARARGS,
     "Difference BDDs"},
    {"subtract_recursive", subtract_recursive, METH_VARARGS, "Subtract BDDs"},
    {"intersection_recursive", intersection_recursive, METH_VARARGS,
     "Intersect BDDs"},
    {"wc_to_BDD", wc_to_BDD, METH_VARARGS, "WC to BDD"},
    {"gc_node_cache", gc_node_cache, METH_VARARGS,
     "Run an internal garbage collection on the node cache.\n\n"
     "Takes no arguments."},
#if AUTO_CLEANUP
    {"set_cleanup_threshold", set_cleanup_threshold, METH_VARARGS,
     "Configure the NODE_CACHE size at which a cleanup is triggered.\n"
     "\n"
     "Expects a single integer argument\n."
     "More specifically calls to meld/intersect/difference_recursive will\n"
     "run gc_node_cache if this threshold is met. Setting to 0 disables "
     "automatic\n"
     "cleanup.\n"},
    {"get_cleanup_threshold", get_cleanup_threshold, METH_NOARGS, ""},
#endif
    {}};

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

  if (PyType_Ready(&BDDNodeType) < 0)
    return NULL;
  if (PyType_Ready(&BDDTermType) < 0)
    return NULL;

  Py_INCREF(&BDDNodeType);
  Py_INCREF(&BDDTermType);
  PyModule_AddObject(m, "BDDNode", (PyObject *)&BDDNodeType);
  PyModule_AddObject(m, "BDDTermination", (PyObject *)&BDDTermType);
  NODE_CACHE = PyDict_New();
  Py_INCREF(NODE_CACHE);
  PyModule_AddObject(m, "NODE_CACHE", NODE_CACHE);

  PyObject *lru;
  lru = PyImport_ImportModule("lru");
  PyObject *mdict = PyModule_GetDict(lru);
  PyObject *LRU = PyDict_GetItemString(mdict, "LRU");
  PyModule_AddObject(m, "LRU", LRU);
  PyObject *argCacheSize = Py_BuildValue("(i)", 100000);

  MERGE_CACHE = PyObject_CallObject(LRU, argCacheSize);
  Py_INCREF(MERGE_CACHE);
  PyModule_AddObject(m, "MERGE_CACHE", MERGE_CACHE);

  DIFFERENCE_CACHE = PyObject_CallObject(LRU, argCacheSize);
  Py_INCREF(DIFFERENCE_CACHE);
  PyModule_AddObject(m, "DIFFERENCE_CACHE", DIFFERENCE_CACHE);

  INTERSECTION_CACHE = PyObject_CallObject(LRU, argCacheSize);
  Py_INCREF(INTERSECTION_CACHE);
  PyModule_AddObject(m, "INTERSECTION_CACHE", INTERSECTION_CACHE);

  RULE_CACHE = PyObject_CallObject(LRU, argCacheSize);
  Py_INCREF(RULE_CACHE);
  PyModule_AddObject(m, "RULE_CACHE", RULE_CACHE);

  Py_DECREF(argCacheSize);
  argCacheSize = Py_BuildValue("ss", "DIFFERS", "This is different");
  IS_DIFFERING =
      (BDDNode *)PyObject_CallObject((PyObject *)&BDDTermType, argCacheSize);
  Py_INCREF(IS_DIFFERING);
  PyModule_AddObject(m, "IS_DIFFERING", (PyObject *)IS_DIFFERING);
  PyDict_SetItem(NODE_CACHE, (PyObject *)IS_DIFFERING,
                 (PyObject *)IS_DIFFERING);
  Py_DECREF(argCacheSize);
  return m;
}

#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC GLUE(PyInit_, MODULE_NAME)(void) { return moduleinit(); }
#else
PyMODINIT_FUNC GLUE(init, MODULE_NAME)(void) { moduleinit(); }
#endif
