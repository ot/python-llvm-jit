/* -*- c-basic-offset: 4; indent-tabs-mode: nil; mode: c++ -*- */

#include <assert.h>

#include "Python.h"
#include "opcode.h"
#include "code.h"
#include "frameobject.h"

#include <stdlib.h>

/* Status code for main loop (reason for stack unwind) */
enum why_code {
		WHY_NOT =	0x0001,	/* No error */
		WHY_EXCEPTION = 0x0002,	/* Exception occurred */
		WHY_RERAISE =	0x0004,	/* Exception re-raised by 'finally' */
		WHY_RETURN =	0x0008,	/* 'return' statement */
		WHY_BREAK =	0x0010,	/* 'break' statement */
		WHY_CONTINUE =	0x0020,	/* 'continue' statement */
		WHY_YIELD =	0x0040	/* 'yield' operator */
};

#define OPCODE(OPCODENAME)                                                  \
    void opcode_##OPCODENAME (PyFrameObject* f, int opcode, int oparg, int* err_out, int* why_out, PyObject** retval_out) { \
        PyObject* v = 0;                                                \
        PyObject* x = Py_None;                                          \
        PyObject* y = 0;                                                \
        PyObject* w = 0;                                                \
        PyObject* z = 0;                                                \
        PyObject* stream = 0;                                           \
        int err = 0, why = 0;                                           \
        PyObject* retval = 0;                                           \
        PyCodeObject *co = f->f_code;                                   \
        PyObject* names = co->co_names;                                 \
        PyObject* consts = co->co_consts;                               \
        PyObject **stack_pointer = f->f_stacktop;                       \
        printf("Executing opcode %d, oparg %d\n", opcode, oparg);       \
        fflush(stdout);                                                 \
        /**/

#define END_OPCODE                                                      \
        *err_out = err;                                                 \
        *why_out = why;                                                 \
        *retval_out = retval;                                           \
        f->f_stacktop = stack_pointer;                                  \
        /* to silent down the warnings */                               \
        (void)v; (void)x; (void)y; (void)w; (void)z;                    \
        (void)stream;                                                   \
        (void)names; (void)consts;                                      \
    }                                                                   \
    /**/

#define POP() (*--stack_pointer)
#define PUSH(v)	(*stack_pointer++ = (v))
//#define GETITEM(v, i) PyTuple_GET_ITEM((PyTupleObject *)(v), (i))
#define GETITEM(v, i) PyTuple_GetItem((v), (i)) // XXX Use macro

OPCODE(UNIMPLEMENTED) {
    printf("Unsupported opcode %d\n", opcode);
} END_OPCODE

void check_err(int* err) {
    if (*err != 0) {
        printf("Error %d!!\n", *err);
        fflush(stdout);
    }
}

OPCODE(STORE_NAME) {
    w = GETITEM(names, oparg);
    if ((x = f->f_locals) != NULL) {
        if (PyDict_CheckExact(x)) {
            err = PyDict_SetItem(x, w, v);
        } else
            err = PyObject_SetItem(x, w, v);
        Py_DECREF(v);
        return;
    }
    PyErr_Format(PyExc_SystemError,
                 "no locals found when storing %s",
                 PyObject_REPR(w));
} END_OPCODE

OPCODE(LOAD_CONST) {
    x = GETITEM(consts, oparg);
    assert(x != 0);
    Py_INCREF(x);
    PUSH(x);
} END_OPCODE


OPCODE(RETURN_VALUE) {
    retval = POP();
    why = WHY_RETURN;
} END_OPCODE

OPCODE(PRINT_ITEM) {
    v = POP();
    if (stream == NULL || stream == Py_None) {
        w = PySys_GetObject("stdout");
        if (w == NULL) {
            PyErr_SetString(PyExc_RuntimeError,
                            "lost sys.stdout");
            err = -1;
        }
    }
    /* PyFile_SoftSpace() can exececute arbitrary code
       if sys.stdout is an instance with a __getattr__.
       If __getattr__ raises an exception, w will
       be freed, so we need to prevent that temporarily. */
    Py_XINCREF(w);
    if (w != NULL && PyFile_SoftSpace(w, 0))
        err = PyFile_WriteString(" ", w);
    if (err == 0)
        err = PyFile_WriteObject(v, w, Py_PRINT_RAW);
    if (err == 0) {
        /* XXX move into writeobject() ? */
        if (PyString_Check(v)) {
            char *s = PyString_AS_STRING(v);
            Py_ssize_t len = PyString_GET_SIZE(v);
            if (len == 0 ||
                !isspace(Py_CHARMASK(s[len-1])) ||
                s[len-1] == ' ')
                PyFile_SoftSpace(w, 1);
        }
#ifdef Py_USING_UNICODE
        else if (PyUnicode_Check(v)) {
            Py_UNICODE *s = PyUnicode_AS_UNICODE(v);
            Py_ssize_t len = PyUnicode_GET_SIZE(v);
            if (len == 0 ||
                !Py_UNICODE_ISSPACE(s[len-1]) ||
                s[len-1] == ' ')
                PyFile_SoftSpace(w, 1);
        }
#endif
        else
            PyFile_SoftSpace(w, 1);
    }
    Py_XDECREF(w);
    Py_DECREF(v);
    Py_XDECREF(stream);
    stream = NULL;
} END_OPCODE

OPCODE(PRINT_NEWLINE) {
    if (stream == NULL || stream == Py_None) {
        w = PySys_GetObject("stdout");
        if (w == NULL)
            PyErr_SetString(PyExc_RuntimeError,
                            "lost sys.stdout");
    }
    if (w != NULL) {
        err = PyFile_WriteString("\n", w);
        if (err == 0)
            PyFile_SoftSpace(w, 0);
    }
    Py_XDECREF(stream);
    stream = NULL;
} END_OPCODE
