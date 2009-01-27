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
        int err = *err_out, why = *why_out;                             \
        PyObject* retval = *retval_out;                                 \
        PyCodeObject *co = f->f_code;                                   \
        PyObject* names = co->co_names;                                 \
        PyObject* consts = co->co_consts;                               \
        PyObject **stack_pointer = f->f_stacktop;                       \
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

#define STACK_LEVEL()	((int)(stack_pointer - f->f_valuestack))
#define EMPTY()		(STACK_LEVEL() == 0)
#define TOP()		(stack_pointer[-1])
#define SECOND()	(stack_pointer[-2])
#define THIRD() 	(stack_pointer[-3])
#define FOURTH()	(stack_pointer[-4])
#define SET_TOP(v)	(stack_pointer[-1] = (v))
#define SET_SECOND(v)	(stack_pointer[-2] = (v))
#define SET_THIRD(v)	(stack_pointer[-3] = (v))
#define SET_FOURTH(v)	(stack_pointer[-4] = (v))
#define BASIC_STACKADJ(n)	(stack_pointer += n)
#define BASIC_PUSH(v)	(*stack_pointer++ = (v))
#define BASIC_POP()	(*--stack_pointer)

#define POP() BASIC_POP()
#define PUSH(v)	BASIC_PUSH(v)

#define GETITEM(v, i) PyTuple_GET_ITEM((PyTupleObject *)(v), (i))
//#define GETITEM(v, i) PyTuple_GetItem((v), (i)) // XXX Use macro

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
    v = POP();
    if ((x = f->f_locals) != NULL) {
        if (PyDict_CheckExact(x))
            err = PyDict_SetItem(x, w, v);
        else
            err = PyObject_SetItem(x, w, v);
        Py_DECREF(v);
        return;
    }
    PyErr_Format(PyExc_SystemError,
                 "no locals found when storing %s",
                 PyObject_REPR(w));
} END_OPCODE // XXX handle error

#define NAME_ERROR_MSG \
	"name '%.200s' is not defined"
#define GLOBAL_NAME_ERROR_MSG \
	"global name '%.200s' is not defined"
#define UNBOUNDLOCAL_ERROR_MSG \
	"local variable '%.200s' referenced before assignment"
#define UNBOUNDFREE_ERROR_MSG \
	"free variable '%.200s' referenced before assignment" \
        " in enclosing scope"

static void
format_exc_check_arg(PyObject *exc, char *format_str, PyObject *obj)
{
	char *obj_str;

	if (!obj)
		return;

	obj_str = PyString_AsString(obj);
	if (!obj_str)
		return;

	PyErr_Format(exc, format_str, obj_str);
}

OPCODE(LOAD_NAME) {
    w = GETITEM(names, oparg);
    err = 1;
    if ((v = f->f_locals) == NULL) {
        PyErr_Format(PyExc_SystemError,
                     "no locals when loading %s",
                     PyObject_REPR(w));
        return;
    }
    if (PyDict_CheckExact(v)) {
        x = PyDict_GetItem(v, w);
        Py_XINCREF(x);
    }
    else {
        x = PyObject_GetItem(v, w);
        if (x == NULL && PyErr_Occurred()) {
            if (!PyErr_ExceptionMatches(PyExc_KeyError))
                return;
            PyErr_Clear();
        }
    }
    if (x == NULL) {
        x = PyDict_GetItem(f->f_globals, w);
        if (x == NULL) {
            x = PyDict_GetItem(f->f_builtins, w);
            if (x == NULL) {
                format_exc_check_arg(
                                     PyExc_NameError,
                                     NAME_ERROR_MSG ,w);
                return;
            }
        }
        Py_INCREF(x);
    }
    PUSH(x);
    err = 0;
} END_OPCODE 

OPCODE(LOAD_CONST) {
    x = GETITEM(consts, oparg);
    assert(x != 0);
    Py_INCREF(x);
    PUSH(x);
} END_OPCODE // XXX check error


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

static PyObject *
cmp_outcome(int op, register PyObject *v, register PyObject *w)
{
	int res = 0;
	switch (op) {
	case PyCmp_IS:
		res = (v == w);
		break;
	case PyCmp_IS_NOT:
		res = (v != w);
		break;
	case PyCmp_IN:
		res = PySequence_Contains(w, v);
		if (res < 0)
			return NULL;
		break;
	case PyCmp_NOT_IN:
		res = PySequence_Contains(w, v);
		if (res < 0)
			return NULL;
		res = !res;
		break;
	case PyCmp_EXC_MATCH:
		res = PyErr_GivenExceptionMatches(v, w);
		break;
	default:
		return PyObject_RichCompare(v, w, op);
	}
	v = res ? Py_True : Py_False;
	Py_INCREF(v);
	return v;
}

OPCODE(COMPARE_OP) {
    w = POP();
    v = TOP();
    if (PyInt_CheckExact(w) && PyInt_CheckExact(v)) {
        /* INLINE: cmp(int, int) */
        register long a, b;
        register int res;
        a = PyInt_AS_LONG(v);
        b = PyInt_AS_LONG(w);
        switch (oparg) {
        case PyCmp_LT: res = a <  b; break;
        case PyCmp_LE: res = a <= b; break;
        case PyCmp_EQ: res = a == b; break;
        case PyCmp_NE: res = a != b; break;
        case PyCmp_GT: res = a >  b; break;
        case PyCmp_GE: res = a >= b; break;
        case PyCmp_IS: res = v == w; break;
        case PyCmp_IS_NOT: res = v != w; break;
        default: goto slow_compare;
        }
        x = res ? Py_True : Py_False;
        Py_INCREF(x);
    }
    else {
    slow_compare:
        x = cmp_outcome(oparg, v, w);
    }
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (!x) err = 1; // XXX 

} END_OPCODE

OPCODE(POP_TOP) {
    v = POP();
    Py_DECREF(v);
} END_OPCODE

int is_top_true(PyFrameObject* f, int* err) {
    PyObject* w = f->f_stacktop[-1];
    if (w == Py_True)
        return 1;
    else if (w == Py_False) 
        return 0;
    else {
        *err = PyObject_IsTrue(w);
        if (*err > 0) {
            *err = 0;
            return 1;
        } else if (*err == 0) {
            return 0;
        }
    }
    return 0; // err is nonzero
} 
