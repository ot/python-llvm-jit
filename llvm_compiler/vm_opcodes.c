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
    int opcode_##OPCODENAME (PyFrameObject* f, int line, int opcode, int oparg, int* err_out, int* why_out, PyObject** retval_out) { \
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
        int ret = 1;                                                    \
        /**/
        //        printf("Executing opcode %d with oparg %d\n", opcode, oparg); 

#define END_OPCODE                                                      \
    end:                                                                \
        *err_out = err;                                                 \
        *why_out = why;                                                 \
        *retval_out = retval;                                           \
        f->f_stacktop = stack_pointer;                                  \
        f->f_lasti = line;                                              \
        /* to silent down the warnings */                               \
        (void)v; (void)x; (void)y; (void)w; (void)z;                    \
        (void)stream;                                                   \
        (void)names; (void)consts;                                      \
        return ret;                                                     \
        }                                                               \
        /**/                                                                            

#define RETURN(v) do {                            \
        ret = (v);                                \
        goto end;                                 \
    } while(0);                                   \
    /**/

#define BREAK() RETURN(0)
#define CONTINUE() RETURN(1)

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
#define STACKADJ(n) BASIC_STACKADJ(n)

#define INSTR_OFFSET() (line+3)

//#define GETITEM(v, i) PyTuple_GET_ITEM((PyTupleObject *)(v), (i))
#define GETITEM(v, i) PyTuple_GetItem((v), (i)) // XXX Use macro

OPCODE(UNIMPLEMENTED) {
    printf("Unsupported opcode %d\n", opcode);
    CONTINUE();
} END_OPCODE

void check_err(int line, int* err) {
    if (*err != 0) {
        printf("Line %d, error %d!!\n", line, *err);
        fflush(stdout);
        *err = 0;
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
        if (err == 0) CONTINUE();
        BREAK();
    }
    PyErr_Format(PyExc_SystemError,
                 "no locals found when storing %s",
                 PyObject_REPR(w));
    BREAK();
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
    if ((v = f->f_locals) == NULL) {
        PyErr_Format(PyExc_SystemError,
                     "no locals when loading %s",
                     PyObject_REPR(w));
        BREAK();
    }
    if (PyDict_CheckExact(v)) {
        x = PyDict_GetItem(v, w);
        Py_XINCREF(x);
    }
    else {
        x = PyObject_GetItem(v, w);
        if (x == NULL && PyErr_Occurred()) {
            if (!PyErr_ExceptionMatches(PyExc_KeyError))
                BREAK();
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
                BREAK();
            }
        }
        Py_INCREF(x);
    }
    PUSH(x);
    CONTINUE();
} END_OPCODE 

OPCODE(LOAD_CONST) {
    x = GETITEM(consts, oparg);
    Py_INCREF(x);
    PUSH(x);
    CONTINUE();
} END_OPCODE 


OPCODE(RETURN_VALUE) {
    retval = POP();
    why = WHY_RETURN;
    BREAK();
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
    if (err == 0)
        CONTINUE();
    BREAK();
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
    CONTINUE(); // why is this "break" in ceval.c?
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
    if (x == NULL) BREAK();
    CONTINUE();
} END_OPCODE

OPCODE(POP_TOP) {
    v = POP();
    Py_DECREF(v);
    CONTINUE();
} END_OPCODE

OPCODE(DUP_TOP) {
    v = TOP();
    Py_INCREF(v);
    PUSH(v);
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

OPCODE(SETUP_LOOP) {
    PyFrame_BlockSetup(f, opcode, INSTR_OFFSET() + oparg,
                       STACK_LEVEL());
    CONTINUE();
} END_OPCODE

OPCODE(BUILD_LIST) {
    x =  PyList_New(oparg);
    if (x != NULL) {
        for (; --oparg >= 0;) {
            w = POP();
            PyList_SET_ITEM(x, oparg, w);
        }
        PUSH(x);
        CONTINUE();
    } 
    BREAK();
} END_OPCODE

OPCODE(GET_ITER) {
    v = TOP();
    x = PyObject_GetIter(v);
    Py_DECREF(v);
    if (x != NULL) {
        SET_TOP(x);
        CONTINUE();
    }
    STACKADJ(-1);
    BREAK();
} END_OPCODE

OPCODE(FOR_ITER) {
    /* before: [iter]; after: [iter, iter()] *or* [] */
    v = TOP();
    x = (*v->ob_type->tp_iternext)(v);
    if (x != NULL) {
        PUSH(x);
        CONTINUE();
    }
    if (PyErr_Occurred()) {
        if (!PyErr_ExceptionMatches(PyExc_StopIteration)) 
            BREAK();
        PyErr_Clear();
    }
    /* iterator ended normally */
    x = v = POP();
    Py_DECREF(v);
    RETURN(2); // Special value to signal iteration end
} END_OPCODE

OPCODE(POP_BLOCK) {
    PyTryBlock *b = PyFrame_BlockPop(f);
    while (STACK_LEVEL() > b->b_level) {
        v = POP();
        Py_DECREF(v);
    }
    CONTINUE();
} END_OPCODE

static int
call_trace(Py_tracefunc func, PyObject *obj, PyFrameObject *frame,
	   int what, PyObject *arg)
{
	register PyThreadState *tstate = frame->f_tstate;
	int result;
	if (tstate->tracing)
		return 0;
	tstate->tracing++;
	tstate->use_tracing = 0;
	result = func(obj, frame, what, arg);
	tstate->use_tracing = ((tstate->c_tracefunc != NULL)
			       || (tstate->c_profilefunc != NULL));
	tstate->tracing--;
	return result;
}

static void
call_exc_trace(Py_tracefunc func, PyObject *self, PyFrameObject *f)
{
	PyObject *type, *value, *traceback, *arg;
	int err;
	PyErr_Fetch(&type, &value, &traceback);
	if (value == NULL) {
		value = Py_None;
		Py_INCREF(value);
	}
	arg = PyTuple_Pack(3, type, value, traceback);
	if (arg == NULL) {
		PyErr_Restore(type, value, traceback);
		return;
	}
	err = call_trace(func, self, f, PyTrace_EXCEPTION, arg);
	Py_DECREF(arg);
	if (err == 0)
		PyErr_Restore(type, value, traceback);
	else {
		Py_XDECREF(type);
		Py_XDECREF(value);
		Py_XDECREF(traceback);
	}
}

static void
set_exc_info(PyThreadState *tstate,
	     PyObject *type, PyObject *value, PyObject *tb)
{
	PyFrameObject *frame = tstate->frame;
	PyObject *tmp_type, *tmp_value, *tmp_tb;

	assert(type != NULL);
	assert(frame != NULL);
	if (frame->f_exc_type == NULL) {
		assert(frame->f_exc_value == NULL);
		assert(frame->f_exc_traceback == NULL);
		/* This frame didn't catch an exception before. */
		/* Save previous exception of this thread in this frame. */
		if (tstate->exc_type == NULL) {
			/* XXX Why is this set to Py_None? */
			Py_INCREF(Py_None);
			tstate->exc_type = Py_None;
		}
		Py_INCREF(tstate->exc_type);
		Py_XINCREF(tstate->exc_value);
		Py_XINCREF(tstate->exc_traceback);
		frame->f_exc_type = tstate->exc_type;
		frame->f_exc_value = tstate->exc_value;
		frame->f_exc_traceback = tstate->exc_traceback;
	}
	/* Set new exception for this thread. */
	tmp_type = tstate->exc_type;
	tmp_value = tstate->exc_value;
	tmp_tb = tstate->exc_traceback;
	Py_INCREF(type);
	Py_XINCREF(value);
	Py_XINCREF(tb);
	tstate->exc_type = type;
	tstate->exc_value = value;
	tstate->exc_traceback = tb;
	Py_XDECREF(tmp_type);
	Py_XDECREF(tmp_value);
	Py_XDECREF(tmp_tb);
	/* For b/w compatibility */
	PySys_SetObject("exc_type", type);
	PySys_SetObject("exc_value", value);
	PySys_SetObject("exc_traceback", tb);
}


int unwind_stack(PyFrameObject* f, PyThreadState* tstate, int* err_out, int* why_out, PyObject** retval_out, int* jump_to) {
    int ret = 0;
    PyObject** stack_pointer = f->f_stacktop;
    int err = *err_out;
    int why = *why_out;
    PyObject* retval = *retval_out;

    PyObject* v;
    
    if (why == WHY_NOT) {
        why = WHY_EXCEPTION;
        err = 0;
    }
    
    /* Log traceback info if this is a real exception */
    
    if (why == WHY_EXCEPTION) {
        // XXX this is not under fast_block_end
        PyTraceBack_Here(f);
        
        if (tstate->c_tracefunc != NULL)
            call_exc_trace(tstate->c_tracefunc,
                           tstate->c_traceobj, f);
    }

    if (why == WHY_RERAISE)
        why = WHY_EXCEPTION;
    
    // fast_block_end:
    while (why != WHY_NOT && f->f_iblock > 0) {
        PyTryBlock *b = PyFrame_BlockPop(f);

        assert(why != WHY_YIELD);
        if (b->b_type == SETUP_LOOP && why == WHY_CONTINUE) {
            /* For a continue inside a try block,
               don't pop the block for the loop. */
            PyFrame_BlockSetup(f, b->b_type, b->b_handler,
                               b->b_level);
            why = WHY_NOT;
            *jump_to = PyInt_AS_LONG(retval);
            Py_DECREF(retval);
            break;
        }

        while (STACK_LEVEL() > b->b_level) {
            v = POP();
            Py_XDECREF(v);
        }
        if (b->b_type == SETUP_LOOP && why == WHY_BREAK) {
            why = WHY_NOT;
            *jump_to = b->b_handler;
            break;
        }
        if (b->b_type == SETUP_FINALLY ||
            (b->b_type == SETUP_EXCEPT &&
             why == WHY_EXCEPTION)) {
            if (why == WHY_EXCEPTION) {
                PyObject *exc, *val, *tb;
                PyErr_Fetch(&exc, &val, &tb);
                if (val == NULL) {
                    val = Py_None;
                    Py_INCREF(val);
                }
                /* Make the raw exception data
                   available to the handler,
                   so a program can emulate the
                   Python main loop.  Don't do
                   this for 'finally'. */
                if (b->b_type == SETUP_EXCEPT) {
                    PyErr_NormalizeException(
                                             &exc, &val, &tb);
                    set_exc_info(tstate,
                                 exc, val, tb);
                }
                if (tb == NULL) {
                    Py_INCREF(Py_None);
                    PUSH(Py_None);
                } else
                    PUSH(tb);
                PUSH(val);
                PUSH(exc);
            }
            else {
                if (why & (WHY_RETURN | WHY_CONTINUE))
                    PUSH(retval);
                v = PyInt_FromLong((long)why);
                PUSH(v);
            }
            why = WHY_NOT;
            *jump_to = b->b_handler;
            break;
        }
    } /* unwind stack */
    
    if (why == WHY_NOT) {
        CONTINUE();
    }

    assert(why != WHY_YIELD);
    /* Pop remaining stack entries. */
    while (!EMPTY()) {
        v = POP();
        Py_XDECREF(v);
    }

    if (why != WHY_RETURN)
        retval = NULL;

    BREAK();

 end:
    *retval_out = retval;
    *err_out = err;
    *why_out = why;
    f->f_stacktop = stack_pointer;
    return ret;
}
