/* -*- c-basic-offset: 4; indent-tabs-mode: nil; mode: c++ -*- */

#include "JitCompiler.h"

#include "Python.h"
#include "opcode.h"
#include "code.h"
#include "frameobject.h"
#include "pythread.h"

#include <stdlib.h>

extern volatile int _Py_Ticker;
extern int _Py_CheckInterval;

typedef struct {
    PyFrameObject* f;
    PyObject** stack_pointer;
    PyThreadState* tstate;

    PyCodeObject* co;
    PyObject* names;
    PyObject* consts;
    PyObject** fastlocals;

    int why;
    PyObject* retval;
} interpreter_state;

#define F (st->f)
#define STACK_POINTER (st->stack_pointer)
#define TSTATE (st->tstate)

#define CO (st->co)
#define NAMES (st->names)
#define CONSTS (st->consts)
#define FASTLOCALS (st->fastlocals)

#define WHY (st->why)
#define RETVAL (st->retval)

__attribute__((used)) static void
init_interpreter_state(interpreter_state* st, PyFrameObject* f, PyThreadState* tstate) {
    F = f;
    STACK_POINTER = f->f_stacktop;
    f->f_stacktop = 0;

    TSTATE = tstate;

    CO = f->f_code;
    NAMES = st->co->co_names;
    CONSTS = st->co->co_consts;
    FASTLOCALS = f->f_localsplus;
    
    WHY = WHY_NOT;
    RETVAL = 0;
}

#define OPCODE_PREAMBLE \
        int err = 0;                                                    \
        PyObject* v = 0;                                                \
        PyObject* x = Py_None;                                          \
        PyObject* y = 0;                                                \
        PyObject* w = 0;                                                \
        PyObject* z = 0;                                                \
        PyObject* u = 0;                                                \
        PyObject* stream = 0;                                           \
        int ret = 1;                                                    \
        //printf("Executing opcode %d with oparg %d\n", opcode, oparg); 

#define OPCODE(OPCODENAME)                                             \
    __attribute__((used)) static int                                   \
    opcode_##OPCODENAME (interpreter_state* st, int line, int opcode, int oparg) { \
        OPCODE_PREAMBLE                                                \
        /**/

#define FAT_OPCODE(OPCODENAME)                  \
    int fat_opcode_##OPCODENAME;                \
    __attribute__((used)) static int                                   \
    opcode_##OPCODENAME (interpreter_state* st, int line, int opcode, int oparg) { \
        OPCODE_PREAMBLE                                                 \
        if (--_Py_Ticker < 0 && opcode != SETUP_FINALLY)                \
            if (!do_periodic_things(TSTATE)) {                          \
                WHY = WHY_EXCEPTION;                                    \
                BREAK();                                                \
            }                                                           \
        /**/


#define END_OPCODE                                                      \
    end:                                                                \
        /* to silent down the warnings */                               \
        (void)v; (void)x; (void)y; (void)w; (void)z;                    \
        (void)u; (void)stream; (void)err;                               \
        return ret;                                                     \
        }                                                               \
        /**/                                                                            

#define RETURN(v) do {                            \
        ret = (v);                                \
        goto end;                                 \
    } while(0)                                    \
    /**/

#define BREAK() RETURN(0)
#define CONTINUE() RETURN(1)

#define STACK_LEVEL()	((int)((STACK_POINTER) - F->f_valuestack))
#define EMPTY()		(STACK_LEVEL() == 0)
#define TOP()		((STACK_POINTER)[-1])
#define SECOND()	((STACK_POINTER)[-2])
#define THIRD() 	((STACK_POINTER)[-3])
#define FOURTH()	((STACK_POINTER)[-4])
#define SET_TOP(v)	((STACK_POINTER)[-1] = (v))
#define SET_SECOND(v)	((STACK_POINTER)[-2] = (v))
#define SET_THIRD(v)	((STACK_POINTER)[-3] = (v))
#define SET_FOURTH(v)	((STACK_POINTER)[-4] = (v))
#define BASIC_STACKADJ(n)	((STACK_POINTER) += n)
#define BASIC_PUSH(v)	(*(STACK_POINTER)++ = (v))
#define BASIC_POP()	(*--(STACK_POINTER))

#define POP() BASIC_POP()
#define PUSH(v)	BASIC_PUSH(v)
#define STACKADJ(n) BASIC_STACKADJ(n)
#define EXT_POP(STACK_POINTER) (*--(STACK_POINTER))

// XXX THIS IS UGLY
#define INSTR_OFFSET() (line + (HAS_ARG(opcode) ? 3 : 1))
// #define PEEKARG() (f->f_code->co_code[INSTR_OFFSET() + 2] << 8 + 
//     (f->f_code->co_code[INSTR_OFFSET() + 1])
//

#define GETITEM(v, i) PyTuple_GET_ITEM((PyTupleObject *)(v), (i))
//#define GETITEM(v, i) PyTuple_GetItem((v), (i)) // XXX Use macro

#ifdef WITH_TSC
static PyObject * call_function(PyObject ***, int, uint64*, uint64*);
#else
static PyObject * call_function(PyObject ***, int);
#endif
static PyObject * fast_function(PyObject *, PyObject ***, int, int, int);
static PyObject * do_call(PyObject *, PyObject ***, int, int);
static PyObject * update_keyword_args(PyObject *, int, PyObject ***,PyObject *);
static PyObject * update_star_args(int, int, PyObject *, PyObject ***);
static PyObject * load_args(PyObject ***, int);
#define CALL_FLAG_VAR 1
#define CALL_FLAG_KW 2

#define PCALL(x)
#define READ_TIMESTAMP(x)

// don't want to get my hands dirty with pointer arithmetic
PyObject** get_stack_pointer(PyFrameObject* f) {
    return f->f_stacktop; 
}

void set_stack_pointer(PyFrameObject* f, PyObject** sp) {
    f->f_stacktop = sp;
}

int get_lasti (PyFrameObject* f) {
    return f->f_lasti;
}

void set_lasti(PyFrameObject* f, int lasti) {
    f->f_lasti = lasti;
}

void set_why(interpreter_state* st, int why) {
    WHY = why;
}

PyObject* get_retval(interpreter_state* st) {
    return RETVAL;
}

extern volatile int things_to_do;
extern volatile int pendingfirst;
extern volatile int pendinglast;

extern PyThread_type_lock interpreter_lock; /* This is the GIL */
extern long main_thread;

static int do_periodic_things(PyThreadState* tstate) {
    _Py_Ticker = _Py_CheckInterval;
    tstate->tick_counter++;
#ifdef WITH_TSC
    ticked = 1;
#endif
    if (things_to_do) {
        if (Py_MakePendingCalls() < 0) {
//             why = WHY_EXCEPTION;
//             goto on_error;
            return 0;
        }
        if (things_to_do)
            /* MakePendingCalls() didn't succeed.
               Force early re-execution of this
               "periodic" code, possibly after
               a thread switch */
            _Py_Ticker = 0;
    }
#ifdef WITH_THREAD
    if (interpreter_lock) {
        /* Give another thread a chance */

        if (PyThreadState_Swap(NULL) != tstate)
            Py_FatalError("ceval: tstate mix-up");
        PyThread_release_lock(interpreter_lock);

        /* Other threads may run now */

        PyThread_acquire_lock(interpreter_lock, 1);
        if (PyThreadState_Swap(tstate) != NULL)
            Py_FatalError("ceval: orphan tstate");

        /* Check for thread interrupts */

        if (tstate->async_exc != NULL) {
            PyObject* x = tstate->async_exc;
            tstate->async_exc = NULL;
            PyErr_SetNone(x);
            Py_DECREF(x);
//             why = WHY_EXCEPTION;
//             goto on_error;
            return 0;
        }
    }
#endif
    return 1;
}

OPCODE(UNIMPLEMENTED) {
    PyErr_Format(PyExc_SystemError,
                 "Opcode %d not implemented",
                 opcode);
    BREAK();
} END_OPCODE

FAT_OPCODE(STORE_NAME) {
    w = GETITEM(NAMES, oparg);
    v = POP();
    if ((x = F->f_locals) != NULL) {
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
} END_OPCODE 

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

FAT_OPCODE(LOAD_NAME) {
    w = GETITEM(NAMES, oparg);
    if ((v = F->f_locals) == NULL) {
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
        x = PyDict_GetItem(F->f_globals, w);
        if (x == NULL) {
            x = PyDict_GetItem(F->f_builtins, w);
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
    x = GETITEM(CONSTS, oparg);
    Py_INCREF(x);
    PUSH(x);
    CONTINUE();
} END_OPCODE 


OPCODE(RETURN_VALUE) {
    RETVAL = POP();
    WHY = WHY_RETURN;
    BREAK();
} END_OPCODE

FAT_OPCODE(PRINT_ITEM) {
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

FAT_OPCODE(PRINT_NEWLINE) {
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

FAT_OPCODE(COMPARE_OP) {
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
    CONTINUE();
} END_OPCODE

__attribute__((used)) static int                                
is_top_true(interpreter_state* st) {
    int err = 0;
    PyObject* w = TOP();
    if (w == Py_True)
        return 1;
    else if (w == Py_False) 
        return 0;
    else {
        err = PyObject_IsTrue(w);
        if (err > 0) {
            err = 0;
            return 1;
        } else if (err == 0) {
            return 0;
        }
    }
    return 0; // err is nonzero
} 

FAT_OPCODE(SETUP_LOOP) {
    PyFrame_BlockSetup(F, opcode, INSTR_OFFSET() + oparg,
                       STACK_LEVEL());
    CONTINUE();
} END_OPCODE

FAT_OPCODE(BUILD_LIST) {
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

FAT_OPCODE(GET_ITER) {
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

FAT_OPCODE(FOR_ITER) {
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

FAT_OPCODE(POP_BLOCK) {
    PyTryBlock *b = PyFrame_BlockPop(F);
    while (STACK_LEVEL() > b->b_level) {
        v = POP();
        Py_DECREF(v);
    }
    CONTINUE();
} END_OPCODE

/* Logic for the raise statement (too complicated for inlining).
   This *consumes* a reference count to each of its arguments. */
static enum why_code
do_raise(PyObject *type, PyObject *value, PyObject *tb)
{
	if (type == NULL) {
		/* Reraise */
		PyThreadState *tstate = PyThreadState_GET();
		type = tstate->exc_type == NULL ? Py_None : tstate->exc_type;
		value = tstate->exc_value;
		tb = tstate->exc_traceback;
		Py_XINCREF(type);
		Py_XINCREF(value);
		Py_XINCREF(tb);
	}

	/* We support the following forms of raise:
	   raise <class>, <classinstance>
	   raise <class>, <argument tuple>
	   raise <class>, None
	   raise <class>, <argument>
	   raise <classinstance>, None
	   raise <string>, <object>
	   raise <string>, None

	   An omitted second argument is the same as None.

	   In addition, raise <tuple>, <anything> is the same as
	   raising the tuple's first item (and it better have one!);
	   this rule is applied recursively.

	   Finally, an optional third argument can be supplied, which
	   gives the traceback to be substituted (useful when
	   re-raising an exception after examining it).  */

	/* First, check the traceback argument, replacing None with
	   NULL. */
	if (tb == Py_None) {
		Py_DECREF(tb);
		tb = NULL;
	}
	else if (tb != NULL && !PyTraceBack_Check(tb)) {
		PyErr_SetString(PyExc_TypeError,
			   "raise: arg 3 must be a traceback or None");
		goto raise_error;
	}

	/* Next, replace a missing value with None */
	if (value == NULL) {
		value = Py_None;
		Py_INCREF(value);
	}

	/* Next, repeatedly, replace a tuple exception with its first item */
	while (PyTuple_Check(type) && PyTuple_Size(type) > 0) {
		PyObject *tmp = type;
		type = PyTuple_GET_ITEM(type, 0);
		Py_INCREF(type);
		Py_DECREF(tmp);
	}

	if (PyString_CheckExact(type)) {
		/* Raising builtin string is deprecated but still allowed --
		 * do nothing.  Raising an instance of a new-style str
		 * subclass is right out. */
		if (PyErr_Warn(PyExc_DeprecationWarning,
			   "raising a string exception is deprecated"))
			goto raise_error;
	}
	else if (PyExceptionClass_Check(type))
		PyErr_NormalizeException(&type, &value, &tb);

	else if (PyExceptionInstance_Check(type)) {
		/* Raising an instance.  The value should be a dummy. */
		if (value != Py_None) {
			PyErr_SetString(PyExc_TypeError,
			  "instance exception may not have a separate value");
			goto raise_error;
		}
		else {
			/* Normalize to raise <class>, <instance> */
			Py_DECREF(value);
			value = type;
			type = PyExceptionInstance_Class(type);
			Py_INCREF(type);
		}
	}
	else {
		/* Not something you can raise.  You get an exception
		   anyway, just not what you specified :-) */
		PyErr_Format(PyExc_TypeError,
			     "exceptions must be classes, instances, or "
			     "strings (deprecated), not %s",
			     type->ob_type->tp_name);
		goto raise_error;
	}
	PyErr_Restore(type, value, tb);
	if (tb == NULL)
		return WHY_EXCEPTION;
	else
		return WHY_RERAISE;
 raise_error:
	Py_XDECREF(value);
	Py_XDECREF(type);
	Py_XDECREF(tb);
	return WHY_EXCEPTION;
}

FAT_OPCODE(RAISE_VARARGS) {
    u = v = w = NULL;
    switch (oparg) {
    case 3:
        u = POP(); /* traceback */
        /* Fallthrough */
    case 2:
        v = POP(); /* value */
        /* Fallthrough */
    case 1:
        w = POP(); /* exc */
    case 0: /* Fallthrough */
        WHY = do_raise(w, v, u);
        break;
    default:
        PyErr_SetString(PyExc_SystemError,
                        "bad RAISE_VARARGS oparg");
        WHY = WHY_EXCEPTION;
        break;
    }
    BREAK();
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

static int
call_trace_protected(Py_tracefunc func, PyObject *obj, PyFrameObject *frame,
		     int what, PyObject *arg)
{
	PyObject *type, *value, *traceback;
	int err;
	PyErr_Fetch(&type, &value, &traceback);
	err = call_trace(func, obj, frame, what, arg);
	if (err == 0)
	{
		PyErr_Restore(type, value, traceback);
		return 0;
	}
	else {
		Py_XDECREF(type);
		Py_XDECREF(value);
		Py_XDECREF(traceback);
		return -1;
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


int unwind_stack(interpreter_state* st, int* jump_to) {
    int ret = 0;

    PyObject* v;
    
    if (WHY == WHY_YIELD)
        BREAK();
    
    if (WHY == WHY_NOT) {
        WHY = WHY_EXCEPTION;
    }
    
    /* Log traceback info if this is a real exception */
    
    if (WHY == WHY_EXCEPTION) {
        // XXX this is not under fast_block_end
        PyTraceBack_Here(F);
        
//         if (tstate->c_tracefunc != NULL)
//             call_exc_trace(tstate->c_tracefunc,
//                            tstate->c_traceobj, f);
    }

    if (WHY == WHY_RERAISE)
        WHY = WHY_EXCEPTION;
    
    // fast_block_end:
    while (WHY != WHY_NOT && F->f_iblock > 0) {
        PyTryBlock *b = PyFrame_BlockPop(F);

        assert(WHY != WHY_YIELD);
        if (b->b_type == SETUP_LOOP && WHY == WHY_CONTINUE) {
            /* For a continue inside a try block,
               don't pop the block for the loop. */
            PyFrame_BlockSetup(F, b->b_type, b->b_handler,
                               b->b_level);
            WHY = WHY_NOT;
            *jump_to = PyInt_AS_LONG(RETVAL);
            Py_DECREF(RETVAL);
            break;
        }

        while (STACK_LEVEL() > b->b_level) {
            v = POP();
            Py_XDECREF(v);
        }
        if (b->b_type == SETUP_LOOP && WHY == WHY_BREAK) {
            WHY = WHY_NOT;
            *jump_to = b->b_handler;
            break;
        }
        if (b->b_type == SETUP_FINALLY ||
            (b->b_type == SETUP_EXCEPT &&
             WHY == WHY_EXCEPTION)) {
            if (WHY == WHY_EXCEPTION) {
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
                    set_exc_info(TSTATE,
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
                if (WHY & (WHY_RETURN | WHY_CONTINUE))
                    PUSH(RETVAL);
                v = PyInt_FromLong((long)WHY);
                PUSH(v);
            }
            WHY = WHY_NOT;
            *jump_to = b->b_handler;
            break;
        }
    } /* unwind stack */
    
    if (WHY == WHY_NOT) {
        CONTINUE();
    }

    assert(WHY != WHY_YIELD);
    /* Pop remaining stack entries. */
    while (!EMPTY()) {
        v = POP();
        Py_XDECREF(v);
    }

    if (WHY != WHY_RETURN)
        RETVAL = NULL;

    BREAK();

 end:
    return ret;
}

FAT_OPCODE(END_FINALLY) {
    v = POP();
    if (PyInt_Check(v)) {
        WHY = (enum why_code) PyInt_AS_LONG(v);
        assert(WHY != WHY_YIELD);
        if (WHY == WHY_RETURN ||
            WHY == WHY_CONTINUE)
            RETVAL = POP();
    }
    else if (PyExceptionClass_Check(v) || PyString_Check(v)) {
        w = POP();
        u = POP();
        PyErr_Restore(v, w, u);
        WHY = WHY_RERAISE;
        BREAK();
    }
    else if (v != Py_None) {
        PyErr_SetString(PyExc_SystemError,
                        "'finally' pops bad exception");
        WHY = WHY_EXCEPTION;
    }
    Py_DECREF(v);
    // printf("why: %d\n", why); // XXX
    if (WHY == WHY_NOT)
        CONTINUE(); // XXX this is a break in ceval
    else  
        BREAK();
} END_OPCODE

static void
err_args(PyObject *func, int flags, int nargs)
{
	if (flags & METH_NOARGS)
		PyErr_Format(PyExc_TypeError,
			     "%.200s() takes no arguments (%d given)",
			     ((PyCFunctionObject *)func)->m_ml->ml_name,
			     nargs);
	else
		PyErr_Format(PyExc_TypeError,
			     "%.200s() takes exactly one argument (%d given)",
			     ((PyCFunctionObject *)func)->m_ml->ml_name,
			     nargs);
}

#define C_TRACE(x, call) \
if (tstate->use_tracing && tstate->c_profilefunc) { \
	if (call_trace(tstate->c_profilefunc, \
		tstate->c_profileobj, \
		tstate->frame, PyTrace_C_CALL, \
		func)) { \
		x = NULL; \
	} \
	else { \
		x = call; \
		if (tstate->c_profilefunc != NULL) { \
			if (x == NULL) { \
				call_trace_protected(tstate->c_profilefunc, \
					tstate->c_profileobj, \
					tstate->frame, PyTrace_C_EXCEPTION, \
					func); \
				/* XXX should pass (type, value, tb) */ \
			} else { \
				if (call_trace(tstate->c_profilefunc, \
					tstate->c_profileobj, \
					tstate->frame, PyTrace_C_RETURN, \
					func)) { \
					Py_DECREF(x); \
					x = NULL; \
				} \
			} \
		} \
	} \
} else { \
	x = call; \
	}



static PyObject *
call_function(PyObject ***pp_stack, int oparg
#ifdef WITH_TSC
		, uint64* pintr0, uint64* pintr1
#endif
		)
{
	int na = oparg & 0xff;
	int nk = (oparg>>8) & 0xff;
	int n = na + 2 * nk;
	PyObject **pfunc = (*pp_stack) - n - 1;
	PyObject *func = *pfunc;
	PyObject *x, *w;

	/* Always dispatch PyCFunction first, because these are
	   presumed to be the most frequent callable object.
	*/
	if (PyCFunction_Check(func) && nk == 0) {
		int flags = PyCFunction_GET_FLAGS(func);
		PyThreadState *tstate = PyThreadState_GET();

		PCALL(PCALL_CFUNCTION);
		if (flags & (METH_NOARGS | METH_O)) {
			PyCFunction meth = PyCFunction_GET_FUNCTION(func);
			PyObject *self = PyCFunction_GET_SELF(func);
			if (flags & METH_NOARGS && na == 0) {
				C_TRACE(x, (*meth)(self,NULL));
			}
			else if (flags & METH_O && na == 1) {
				PyObject *arg = EXT_POP(*pp_stack);
				C_TRACE(x, (*meth)(self,arg));
				Py_DECREF(arg);
			}
			else {
				err_args(func, flags, na);
				x = NULL;
			}
		}
		else {
			PyObject *callargs;
			callargs = load_args(pp_stack, na);
			READ_TIMESTAMP(*pintr0);
			C_TRACE(x, PyCFunction_Call(func,callargs,NULL));
			READ_TIMESTAMP(*pintr1);
			Py_XDECREF(callargs);
		}
	} else {
		if (PyMethod_Check(func) && PyMethod_GET_SELF(func) != NULL) {
			/* optimize access to bound methods */
			PyObject *self = PyMethod_GET_SELF(func);
			PCALL(PCALL_METHOD);
			PCALL(PCALL_BOUND_METHOD);
			Py_INCREF(self);
			func = PyMethod_GET_FUNCTION(func);
			Py_INCREF(func);
			Py_DECREF(*pfunc);
			*pfunc = self;
			na++;
			n++;
		} else
			Py_INCREF(func);
		READ_TIMESTAMP(*pintr0);
		if (PyFunction_Check(func))
			x = fast_function(func, pp_stack, n, na, nk);
		else
			x = do_call(func, pp_stack, na, nk);
		READ_TIMESTAMP(*pintr1);
		Py_DECREF(func);
	}

	/* Clear the stack of the function object.  Also removes
           the arguments in case they weren't consumed already
           (fast_function() and err_args() leave them on the stack).
	 */
	while ((*pp_stack) > pfunc) {
		w = EXT_POP(*pp_stack);
		Py_DECREF(w);
		PCALL(PCALL_POP);
	}
	return x;
}

/* The fast_function() function optimize calls for which no argument
   tuple is necessary; the objects are passed directly from the stack.
   For the simplest case -- a function that takes only positional
   arguments and is called with only positional arguments -- it
   inlines the most primitive frame setup code from
   PyEval_EvalCodeEx(), which vastly reduces the checks that must be
   done before evaluating the frame.
*/

static PyObject *
fast_function(PyObject *func, PyObject ***pp_stack, int n, int na, int nk)
{
	PyCodeObject *co = (PyCodeObject *)PyFunction_GET_CODE(func);
	PyObject *globals = PyFunction_GET_GLOBALS(func);
	PyObject *argdefs = PyFunction_GET_DEFAULTS(func);
	PyObject **d = NULL;
	int nd = 0;

	PCALL(PCALL_FUNCTION);
	PCALL(PCALL_FAST_FUNCTION);
	if (argdefs == NULL && co->co_argcount == n && nk==0 &&
	    co->co_flags == (CO_OPTIMIZED | CO_NEWLOCALS | CO_NOFREE)) {
		PyFrameObject *f;
		PyObject* retval = NULL;
		PyThreadState *tstate = PyThreadState_GET();
		PyObject **fastlocals, **stack;
		int i;

		PCALL(PCALL_FASTER_FUNCTION);
		assert(globals != NULL);
		/* XXX Perhaps we should create a specialized
		   PyFrame_New() that doesn't take locals, but does
		   take builtins without sanity checking them.
		*/
		assert(tstate != NULL);
		f = PyFrame_New(tstate, co, globals, NULL);
		if (f == NULL)
			return NULL;

		fastlocals = f->f_localsplus;
		stack = (*pp_stack) - n;

		for (i = 0; i < n; i++) {
			Py_INCREF(*stack);
			fastlocals[i] = *stack++;
		}
		retval = PyEval_EvalFrameEx(f,0);
		++tstate->recursion_depth;
		Py_DECREF(f);
		--tstate->recursion_depth;
		return retval;
	}
	if (argdefs != NULL) {
		d = &PyTuple_GET_ITEM(argdefs, 0);
		nd = ((PyTupleObject *)argdefs)->ob_size;
	}
	return PyEval_EvalCodeEx(co, globals,
				 (PyObject *)NULL, (*pp_stack)-n, na,
				 (*pp_stack)-2*nk, nk, d, nd,
				 PyFunction_GET_CLOSURE(func));
}

static PyObject *
update_keyword_args(PyObject *orig_kwdict, int nk, PyObject ***pp_stack,
                    PyObject *func)
{
	PyObject *kwdict = NULL;
	if (orig_kwdict == NULL)
		kwdict = PyDict_New();
	else {
		kwdict = PyDict_Copy(orig_kwdict);
		Py_DECREF(orig_kwdict);
	}
	if (kwdict == NULL)
		return NULL;
	while (--nk >= 0) {
		int err;
		PyObject *value = EXT_POP(*pp_stack);
		PyObject *key = EXT_POP(*pp_stack);
		if (PyDict_GetItem(kwdict, key) != NULL) {
                        PyErr_Format(PyExc_TypeError,
                                     "%.200s%s got multiple values "
                                     "for keyword argument '%.200s'",
				     PyEval_GetFuncName(func),
				     PyEval_GetFuncDesc(func),
				     PyString_AsString(key));
			Py_DECREF(key);
			Py_DECREF(value);
			Py_DECREF(kwdict);
			return NULL;
		}
		err = PyDict_SetItem(kwdict, key, value);
		Py_DECREF(key);
		Py_DECREF(value);
		if (err) {
			Py_DECREF(kwdict);
			return NULL;
		}
	}
	return kwdict;
}

static PyObject *
update_star_args(int nstack, int nstar, PyObject *stararg,
		 PyObject ***pp_stack)
{
	PyObject *callargs, *w;

	callargs = PyTuple_New(nstack + nstar);
	if (callargs == NULL) {
		return NULL;
	}
	if (nstar) {
		int i;
		for (i = 0; i < nstar; i++) {
			PyObject *a = PyTuple_GET_ITEM(stararg, i);
			Py_INCREF(a);
			PyTuple_SET_ITEM(callargs, nstack + i, a);
		}
	}
	while (--nstack >= 0) {
		w = EXT_POP(*pp_stack);
		PyTuple_SET_ITEM(callargs, nstack, w);
	}
	return callargs;
}

static PyObject *
load_args(PyObject ***pp_stack, int na)
{
	PyObject *args = PyTuple_New(na);
	PyObject *w;

	if (args == NULL)
		return NULL;
	while (--na >= 0) {
		w = EXT_POP(*pp_stack);
		PyTuple_SET_ITEM(args, na, w);
	}
	return args;
}

static PyObject *
do_call(PyObject *func, PyObject ***pp_stack, int na, int nk)
{
	PyObject *callargs = NULL;
	PyObject *kwdict = NULL;
	PyObject *result = NULL;

	if (nk > 0) {
		kwdict = update_keyword_args(NULL, nk, pp_stack, func);
		if (kwdict == NULL)
			goto call_fail;
	}
	callargs = load_args(pp_stack, na);
	if (callargs == NULL)
		goto call_fail;
#ifdef CALL_PROFILE
	/* At this point, we have to look at the type of func to
	   update the call stats properly.  Do it here so as to avoid
	   exposing the call stats machinery outside ceval.c
	*/
	if (PyFunction_Check(func))
		PCALL(PCALL_FUNCTION);
	else if (PyMethod_Check(func))
		PCALL(PCALL_METHOD);
	else if (PyType_Check(func))
		PCALL(PCALL_TYPE);
	else
		PCALL(PCALL_OTHER);
#endif
	result = PyObject_Call(func, callargs, kwdict);
 call_fail:
	Py_XDECREF(callargs);
	Py_XDECREF(kwdict);
	return result;
}

static PyObject *
ext_do_call(PyObject *func, PyObject ***pp_stack, int flags, int na, int nk)
{
	int nstar = 0;
	PyObject *callargs = NULL;
	PyObject *stararg = NULL;
	PyObject *kwdict = NULL;
	PyObject *result = NULL;

	if (flags & CALL_FLAG_KW) {
		kwdict = EXT_POP(*pp_stack);
		if (!(kwdict && PyDict_Check(kwdict))) {
			PyErr_Format(PyExc_TypeError,
				     "%s%s argument after ** "
				     "must be a dictionary",
				     PyEval_GetFuncName(func),
				     PyEval_GetFuncDesc(func));
			goto ext_call_fail;
		}
	}
	if (flags & CALL_FLAG_VAR) {
		stararg = EXT_POP(*pp_stack);
		if (!PyTuple_Check(stararg)) {
			PyObject *t = NULL;
			t = PySequence_Tuple(stararg);
			if (t == NULL) {
				if (PyErr_ExceptionMatches(PyExc_TypeError)) {
					PyErr_Format(PyExc_TypeError,
						     "%s%s argument after * "
						     "must be a sequence",
						     PyEval_GetFuncName(func),
						     PyEval_GetFuncDesc(func));
				}
				goto ext_call_fail;
			}
			Py_DECREF(stararg);
			stararg = t;
		}
		nstar = PyTuple_GET_SIZE(stararg);
	}
	if (nk > 0) {
		kwdict = update_keyword_args(kwdict, nk, pp_stack, func);
		if (kwdict == NULL)
			goto ext_call_fail;
	}
	callargs = update_star_args(na, nstar, stararg, pp_stack);
	if (callargs == NULL)
		goto ext_call_fail;
#ifdef CALL_PROFILE
	/* At this point, we have to look at the type of func to
	   update the call stats properly.  Do it here so as to avoid
	   exposing the call stats machinery outside ceval.c
	*/
	if (PyFunction_Check(func))
		PCALL(PCALL_FUNCTION);
	else if (PyMethod_Check(func))
		PCALL(PCALL_METHOD);
	else if (PyType_Check(func))
		PCALL(PCALL_TYPE);
	else
		PCALL(PCALL_OTHER);
#endif
	result = PyObject_Call(func, callargs, kwdict);
      ext_call_fail:
	Py_XDECREF(callargs);
	Py_XDECREF(kwdict);
	Py_XDECREF(stararg);
	return result;
}


FAT_OPCODE(CALL_FUNCTION) {
    x = call_function(&(STACK_POINTER), oparg);
    PUSH(x);
    if (x != NULL)
        CONTINUE();
    BREAK();
    
} END_OPCODE

FAT_OPCODE(MAKE_FUNCTION) {
    v = POP(); /* code object */
    x = PyFunction_New(v, F->f_globals);
    Py_DECREF(v);
    /* XXX Maybe this should be a separate opcode? */
    if (x != NULL && oparg > 0) {
        v = PyTuple_New(oparg);
        if (v == NULL) {
            Py_DECREF(x);
            x = NULL;
            BREAK();
        }
        while (--oparg >= 0) {
            w = POP();
            PyTuple_SET_ITEM(v, oparg, w);
        }
        err = PyFunction_SetDefaults(x, v);
        Py_DECREF(v);
    }
    PUSH(x);
    CONTINUE(); // XXX this is break in ceval
} END_OPCODE

FAT_OPCODE(MAKE_CLOSURE) {
    v = POP(); /* code object */
    x = PyFunction_New(v, F->f_globals);
    Py_DECREF(v);
    if (x != NULL) {
        v = POP();
        err = PyFunction_SetClosure(x, v);
        Py_DECREF(v);
    }
    if (x != NULL && oparg > 0) {
        v = PyTuple_New(oparg);
        if (v == NULL) {
            Py_DECREF(x);
            x = NULL;
            BREAK();
        }
        while (--oparg >= 0) {
            w = POP();
            PyTuple_SET_ITEM(v, oparg, w);
        }
        err = PyFunction_SetDefaults(x, v);
        Py_DECREF(v);
    }
    PUSH(x);
    CONTINUE(); // XXX this is break in ceval
} END_OPCODE

FAT_OPCODE(LOAD_ATTR) {
    w = GETITEM(NAMES, oparg);
    v = TOP();
    x = PyObject_GetAttr(v, w);
    Py_DECREF(v);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(STORE_ATTR) {
    w = GETITEM(NAMES, oparg);
    v = TOP();
    u = SECOND();
    STACKADJ(-2);
    err = PyObject_SetAttr(v, w, u); /* v.w = u */
    Py_DECREF(v);
    Py_DECREF(u);
    if (err == 0) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(DELETE_ATTR) {
    w = GETITEM(NAMES, oparg);
    v = POP();
    err = PyObject_SetAttr(v, w, (PyObject *)NULL);
    /* del v.w */
    Py_DECREF(v);
    if (err == 0) CONTINUE();
    BREAK();
} END_OPCODE


FAT_OPCODE(CALL_FUNCTION_VAR) {
    int na = oparg & 0xff;
    int nk = (oparg>>8) & 0xff;
    int flags = (opcode - CALL_FUNCTION) & 3;
    int n = na + 2 * nk;
    PyObject **pfunc, *func, **sp;
    PCALL(PCALL_ALL);
    if (flags & CALL_FLAG_VAR)
        n++;
    if (flags & CALL_FLAG_KW)
        n++;
    pfunc = (STACK_POINTER) - n - 1;
    func = *pfunc;

    if (PyMethod_Check(func)
        && PyMethod_GET_SELF(func) != NULL) {
        PyObject *self = PyMethod_GET_SELF(func);
        Py_INCREF(self);
        func = PyMethod_GET_FUNCTION(func);
        Py_INCREF(func);
        Py_DECREF(*pfunc);
        *pfunc = self;
        na++;
        n++;
    } else
        Py_INCREF(func);
    sp = (STACK_POINTER);
    READ_TIMESTAMP(intr0);
    x = ext_do_call(func, &sp, flags, na, nk);
    READ_TIMESTAMP(intr1);
    (STACK_POINTER) = sp;
    Py_DECREF(func);

    while ((STACK_POINTER) > pfunc) {
        w = POP();
        Py_DECREF(w);
    }
    PUSH(x);
    if (x != NULL)
        CONTINUE();
    BREAK();
} END_OPCODE

OPCODE(YIELD_VALUE) {
    RETVAL = POP();
    F->f_stacktop = (STACK_POINTER); 
    WHY = WHY_YIELD;
    BREAK();
} END_OPCODE                    

static PyObject *
import_from(PyObject *v, PyObject *name)
{
	PyObject *x;

	x = PyObject_GetAttr(v, name);
	if (x == NULL && PyErr_ExceptionMatches(PyExc_AttributeError)) {
		PyErr_Format(PyExc_ImportError,
			     "cannot import name %.230s",
			     PyString_AsString(name));
	}
	return x;
}

static int
import_all_from(PyObject *locals, PyObject *v)
{
	PyObject *all = PyObject_GetAttrString(v, "__all__");
	PyObject *dict, *name, *value;
	int skip_leading_underscores = 0;
	int pos, err;

	if (all == NULL) {
		if (!PyErr_ExceptionMatches(PyExc_AttributeError))
			return -1; /* Unexpected error */
		PyErr_Clear();
		dict = PyObject_GetAttrString(v, "__dict__");
		if (dict == NULL) {
			if (!PyErr_ExceptionMatches(PyExc_AttributeError))
				return -1;
			PyErr_SetString(PyExc_ImportError,
			"from-import-* object has no __dict__ and no __all__");
			return -1;
		}
		all = PyMapping_Keys(dict);
		Py_DECREF(dict);
		if (all == NULL)
			return -1;
		skip_leading_underscores = 1;
	}

	for (pos = 0, err = 0; ; pos++) {
		name = PySequence_GetItem(all, pos);
		if (name == NULL) {
			if (!PyErr_ExceptionMatches(PyExc_IndexError))
				err = -1;
			else
				PyErr_Clear();
			break;
		}
		if (skip_leading_underscores &&
		    PyString_Check(name) &&
		    PyString_AS_STRING(name)[0] == '_')
		{
			Py_DECREF(name);
			continue;
		}
		value = PyObject_GetAttr(v, name);
		if (value == NULL)
			err = -1;
		else if (PyDict_CheckExact(locals))
			err = PyDict_SetItem(locals, name, value);
		else
			err = PyObject_SetItem(locals, name, value);
		Py_DECREF(name);
		Py_XDECREF(value);
		if (err != 0)
			break;
	}
	Py_DECREF(all);
	return err;
}

static PyObject *
build_class(PyObject *methods, PyObject *bases, PyObject *name)
{
	PyObject *metaclass = NULL, *result, *base;

	if (PyDict_Check(methods))
		metaclass = PyDict_GetItemString(methods, "__metaclass__");
	if (metaclass != NULL)
		Py_INCREF(metaclass);
	else if (PyTuple_Check(bases) && PyTuple_GET_SIZE(bases) > 0) {
		base = PyTuple_GET_ITEM(bases, 0);
		metaclass = PyObject_GetAttrString(base, "__class__");
		if (metaclass == NULL) {
			PyErr_Clear();
			metaclass = (PyObject *)base->ob_type;
			Py_INCREF(metaclass);
		}
	}
	else {
		PyObject *g = PyEval_GetGlobals();
		if (g != NULL && PyDict_Check(g))
			metaclass = PyDict_GetItemString(g, "__metaclass__");
		if (metaclass == NULL)
			metaclass = (PyObject *) &PyClass_Type;
		Py_INCREF(metaclass);
	}
	result = PyObject_CallFunctionObjArgs(metaclass, name, bases, methods, NULL);
	Py_DECREF(metaclass);
	if (result == NULL && PyErr_ExceptionMatches(PyExc_TypeError)) {
		/* A type error here likely means that the user passed
		   in a base that was not a class (such the random module
		   instead of the random.random type).  Help them out with
		   by augmenting the error message with more information.*/

		PyObject *ptype, *pvalue, *ptraceback;

		PyErr_Fetch(&ptype, &pvalue, &ptraceback);
		if (PyString_Check(pvalue)) {
			PyObject *newmsg;
			newmsg = PyString_FromFormat(
				"Error when calling the metaclass bases\n    %s",
				PyString_AS_STRING(pvalue));
			if (newmsg != NULL) {
				Py_DECREF(pvalue);
				pvalue = newmsg;
			}
		}
		PyErr_Restore(ptype, pvalue, ptraceback);
	}
	return result;
}

static int
exec_statement(PyFrameObject *f, PyObject *prog, PyObject *globals,
	       PyObject *locals)
{
	int n;
	PyObject *v;
	int plain = 0;

	if (PyTuple_Check(prog) && globals == Py_None && locals == Py_None &&
	    ((n = PyTuple_Size(prog)) == 2 || n == 3)) {
		/* Backward compatibility hack */
		globals = PyTuple_GetItem(prog, 1);
		if (n == 3)
			locals = PyTuple_GetItem(prog, 2);
		prog = PyTuple_GetItem(prog, 0);
	}
	if (globals == Py_None) {
		globals = PyEval_GetGlobals();
		if (locals == Py_None) {
			locals = PyEval_GetLocals();
			plain = 1;
		}
		if (!globals || !locals) {
			PyErr_SetString(PyExc_SystemError,
					"globals and locals cannot be NULL");
			return -1;
		}
	}
	else if (locals == Py_None)
		locals = globals;
	if (!PyString_Check(prog) &&
	    !PyUnicode_Check(prog) &&
	    !PyCode_Check(prog) &&
	    !PyFile_Check(prog)) {
		PyErr_SetString(PyExc_TypeError,
			"exec: arg 1 must be a string, file, or code object");
		return -1;
	}
	if (!PyDict_Check(globals)) {
		PyErr_SetString(PyExc_TypeError,
		    "exec: arg 2 must be a dictionary or None");
		return -1;
	}
	if (!PyMapping_Check(locals)) {
		PyErr_SetString(PyExc_TypeError,
		    "exec: arg 3 must be a mapping or None");
		return -1;
	}
	if (PyDict_GetItemString(globals, "__builtins__") == NULL)
		PyDict_SetItemString(globals, "__builtins__", f->f_builtins);
	if (PyCode_Check(prog)) {
		if (PyCode_GetNumFree((PyCodeObject *)prog) > 0) {
			PyErr_SetString(PyExc_TypeError,
		"code object passed to exec may not contain free variables");
			return -1;
		}
		v = PyEval_EvalCode((PyCodeObject *) prog, globals, locals);
	}
	else if (PyFile_Check(prog)) {
		FILE *fp = PyFile_AsFile(prog);
		char *name = PyString_AsString(PyFile_Name(prog));
		PyCompilerFlags cf;
		if (name == NULL)
			return -1;
		cf.cf_flags = 0;
		if (PyEval_MergeCompilerFlags(&cf))
			v = PyRun_FileFlags(fp, name, Py_file_input, globals,
					    locals, &cf);
		else
			v = PyRun_File(fp, name, Py_file_input, globals,
				       locals);
	}
	else {
		PyObject *tmp = NULL;
		char *str;
		PyCompilerFlags cf;
		cf.cf_flags = 0;
#ifdef Py_USING_UNICODE
		if (PyUnicode_Check(prog)) {
			tmp = PyUnicode_AsUTF8String(prog);
			if (tmp == NULL)
				return -1;
			prog = tmp;
			cf.cf_flags |= PyCF_SOURCE_IS_UTF8;
		}
#endif
		if (PyString_AsStringAndSize(prog, &str, NULL))
			return -1;
		if (PyEval_MergeCompilerFlags(&cf))
			v = PyRun_StringFlags(str, Py_file_input, globals,
					      locals, &cf);
		else
			v = PyRun_String(str, Py_file_input, globals, locals);
		Py_XDECREF(tmp);
	}
	if (plain)
		PyFrame_LocalsToFast(f, 0);
	if (v == NULL)
		return -1;
	Py_DECREF(v);
	return 0;
}

FAT_OPCODE(IMPORT_NAME) {
    w = GETITEM(NAMES, oparg);
    x = PyDict_GetItemString(F->f_builtins, "__import__");
    if (x == NULL) {
        PyErr_SetString(PyExc_ImportError,
                        "__import__ not found");
        BREAK();
    }
    Py_INCREF(x);
    v = POP();
    u = TOP();
    if (PyInt_AsLong(u) != -1 || PyErr_Occurred())
        w = PyTuple_Pack(5,
                         w,
                         F->f_globals,
                         F->f_locals == NULL ?
                         Py_None : F->f_locals,
                         v,
                         u);
    else
        w = PyTuple_Pack(4,
                         w,
                         F->f_globals,
                         F->f_locals == NULL ?
                         Py_None : F->f_locals,
                         v);
    Py_DECREF(v);
    Py_DECREF(u);
    if (w == NULL) {
        u = POP();
        Py_DECREF(x);
        x = NULL;
        BREAK();
    }
    READ_TIMESTAMP(intr0);
    v = x;
    x = PyEval_CallObject(v, w);
    Py_DECREF(v);
    READ_TIMESTAMP(intr1);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(IMPORT_STAR) {
    v = POP();
    PyFrame_FastToLocals(F);
    if ((x = F->f_locals) == NULL) {
        PyErr_SetString(PyExc_SystemError,
                        "no locals found during 'import *'");
        BREAK();
    }
    READ_TIMESTAMP(intr0);
    err = import_all_from(x, v);
    READ_TIMESTAMP(intr1);
    PyFrame_LocalsToFast(F, 0);
    Py_DECREF(v);
    if (err == 0) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(IMPORT_FROM) {
    w = GETITEM(NAMES, oparg);
    v = TOP();
    READ_TIMESTAMP(intr0);
    x = import_from(v, w);
    READ_TIMESTAMP(intr1);
    PUSH(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(BUILD_CLASS) {
    u = TOP();
    v = SECOND();
    w = THIRD();
    STACKADJ(-2);
    x = build_class(u, v, w);
    SET_TOP(x);
    Py_DECREF(u);
    Py_DECREF(v);
    Py_DECREF(w);
    CONTINUE();
} END_OPCODE

FAT_OPCODE(EXEC_STMT) {
    w = TOP();
    v = SECOND();
    u = THIRD();
    STACKADJ(-3);
    READ_TIMESTAMP(intr0);
    err = exec_statement(F, u, v, w);
    READ_TIMESTAMP(intr1);
    Py_DECREF(u);
    Py_DECREF(v);
    Py_DECREF(w);
    CONTINUE();
} END_OPCODE

FAT_OPCODE(DELETE_NAME) {
    w = GETITEM(NAMES, oparg);
    if ((x = F->f_locals) != NULL) {
        if ((err = PyObject_DelItem(x, w)) != 0) {
            format_exc_check_arg(PyExc_NameError,
                                 NAME_ERROR_MSG ,w);
            BREAK();
        }
        CONTINUE();
    }
    PyErr_Format(PyExc_SystemError,
                 "no locals when deleting %s",
                 PyObject_REPR(w));
    BREAK();
} END_OPCODE

FAT_OPCODE(BUILD_TUPLE) {
    x = PyTuple_New(oparg);
    if (x != NULL) {
        for (; --oparg >= 0;) {
            w = POP();
            PyTuple_SET_ITEM(x, oparg, w);
        }
        PUSH(x);
        CONTINUE();
    }
    BREAK();
} END_OPCODE

/* Local variable macros */

#define GETLOCAL(i)	(FASTLOCALS[i])

/* The SETLOCAL() macro must not DECREF the local variable in-place and
   then store the new value; it must copy the old value to a temporary
   value, then store the new value, and then DECREF the temporary value.
   This is because it is possible that during the DECREF the frame is
   accessed by other code (e.g. a __del__ method or gc.collect()) and the
   variable would be pointing to already-freed memory. */
#define SETLOCAL(i, value)	do { PyObject *tmp = GETLOCAL(i); \
				     GETLOCAL(i) = value; \
                                     Py_XDECREF(tmp); } while (0)

OPCODE(LOAD_FAST) {
    x = GETLOCAL(oparg);
    if (x != NULL) {
        Py_INCREF(x);
        PUSH(x);
        CONTINUE();
    }
    format_exc_check_arg(PyExc_UnboundLocalError,
                         UNBOUNDLOCAL_ERROR_MSG,
                         PyTuple_GetItem(CO->co_varnames, oparg));
    BREAK();
} END_OPCODE

OPCODE(STORE_FAST) {
    v = POP();
    SETLOCAL(oparg, v);
    CONTINUE();
} END_OPCODE

FAT_OPCODE(DELETE_FAST) {
    x = GETLOCAL(oparg);
    if (x != NULL) {
        SETLOCAL(oparg, NULL);
        CONTINUE();
    }
    format_exc_check_arg(
                         PyExc_UnboundLocalError,
                         UNBOUNDLOCAL_ERROR_MSG,
                         PyTuple_GetItem(CO->co_varnames, oparg)
                         );
    BREAK();

} END_OPCODE

FAT_OPCODE(LOAD_LOCALS) {
    if ((x = F->f_locals) != NULL) {
        Py_INCREF(x);
        PUSH(x);
        CONTINUE();
    }
    PyErr_SetString(PyExc_SystemError, "no locals");
    BREAK();
} END_OPCODE

FAT_OPCODE(LOAD_GLOBAL) {
    w = GETITEM(NAMES, oparg);
    if (PyString_CheckExact(w)) {
        /* Inline the PyDict_GetItem() calls.
           WARNING: this is an extreme speed hack.
           Do not try this at home. */
        long hash = ((PyStringObject *)w)->ob_shash;
        if (hash != -1) {
            PyDictObject *d;
            PyDictEntry *e;
            d = (PyDictObject *)(F->f_globals);
            e = d->ma_lookup(d, w, hash);
            if (e == NULL) {
                x = NULL;
                BREAK();
            }
            x = e->me_value;
            if (x != NULL) {
                Py_INCREF(x);
                PUSH(x);
                CONTINUE();
            }
            d = (PyDictObject *)(F->f_builtins);
            e = d->ma_lookup(d, w, hash);
            if (e == NULL) {
                x = NULL;
                BREAK();
            }
            x = e->me_value;
            if (x != NULL) {
                Py_INCREF(x);
                PUSH(x);
                CONTINUE();
            }
            goto load_global_error;
        }
    }
    /* This is the un-inlined version of the code above */
    x = PyDict_GetItem(F->f_globals, w);
    if (x == NULL) {
        x = PyDict_GetItem(F->f_builtins, w);
        if (x == NULL) {
        load_global_error:
            format_exc_check_arg(
                                 PyExc_NameError,
                                 GLOBAL_NAME_ERROR_MSG, w);
            BREAK();
        }
    }
    Py_INCREF(x);
    PUSH(x);
    CONTINUE();
} END_OPCODE

FAT_OPCODE(STORE_GLOBAL) {
    w = GETITEM(NAMES, oparg);
    v = POP();
    err = PyDict_SetItem(F->f_globals, w, v);
    Py_DECREF(v);
    if (err == 0) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(BINARY_SUBSCR) {
    w = POP();
    v = TOP();
    if (PyList_CheckExact(v) && PyInt_CheckExact(w)) {
        /* INLINE: list[int] */
        Py_ssize_t i = PyInt_AsSsize_t(w);
        if (i < 0)
            i += PyList_GET_SIZE(v);
        if (i >= 0 && i < PyList_GET_SIZE(v)) {
            x = PyList_GET_ITEM(v, i);
            Py_INCREF(x);
        }
        else
            goto slow_get;
    }
    else
    slow_get:
        x = PyObject_GetItem(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(STORE_SUBSCR) {
    w = TOP();
    v = SECOND();
    u = THIRD();
    STACKADJ(-3);
    /* v[w] = u */
    err = PyObject_SetItem(v, w, u);
    Py_DECREF(u);
    Py_DECREF(v);
    Py_DECREF(w);
    if (err == 0) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(DELETE_SUBSCR) {
    w = TOP();
    v = SECOND();
    STACKADJ(-2);
    /* del v[w] */
    err = PyObject_DelItem(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    if (err == 0) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(LIST_APPEND) {
    w = POP();
    v = POP();
    err = PyList_Append(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    if (err == 0) {
        CONTINUE();
    }
    BREAK();
} END_OPCODE

FAT_OPCODE(BUILD_MAP) {
    x = PyDict_New();
    PUSH(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(PRINT_EXPR) {
    v = POP();
    w = PySys_GetObject("displayhook");
    if (w == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
                        "lost sys.displayhook");
        err = -1;
        x = NULL;
    }
    if (err == 0) {
        x = PyTuple_Pack(1, v);
        if (x == NULL)
            err = -1;
    }
    if (err == 0) {
        w = PyEval_CallObject(w, x);
        Py_XDECREF(w);
        if (w == NULL)
            err = -1;
    }
    Py_DECREF(v);
    Py_XDECREF(x);
    if (err == 0) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(UNARY_POSITIVE) {
    v = TOP();
    x = PyNumber_Positive(v);
    Py_DECREF(v);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(UNARY_NEGATIVE) {
    v = TOP();
    x = PyNumber_Negative(v);
    Py_DECREF(v);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(UNARY_NOT) {
    v = TOP();
    err = PyObject_IsTrue(v);
    Py_DECREF(v);
    if (err == 0) {
        Py_INCREF(Py_True);
        SET_TOP(Py_True);
        CONTINUE();
    }
    else if (err > 0) {
        Py_INCREF(Py_False);
        SET_TOP(Py_False);
        err = 0;
        CONTINUE();
    }
    STACKADJ(-1);
    BREAK();
} END_OPCODE

FAT_OPCODE(UNARY_CONVERT) {
    v = TOP();
    x = PyObject_Repr(v);
    Py_DECREF(v);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(UNARY_INVERT) {
    v = TOP();
    x = PyNumber_Invert(v);
    Py_DECREF(v);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(BINARY_POWER) {
    w = POP();
    v = TOP();
    x = PyNumber_Power(v, w, Py_None);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(BINARY_MULTIPLY) {
    w = POP();
    v = TOP();
    x = PyNumber_Multiply(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(BINARY_DIVIDE) {
    if (opcode == BINARY_DIVIDE && !_Py_QnewFlag) {
        w = POP();
        v = TOP();
        x = PyNumber_Divide(v, w);
        Py_DECREF(v);
        Py_DECREF(w);
        SET_TOP(x);
        if (x != NULL) CONTINUE();
        BREAK();
    }
    /* -Qnew is in effect:	fall through to
       BINARY_TRUE_DIVIDE */
    // case BINARY_TRUE_DIVIDE:
    w = POP();
    v = TOP();
    x = PyNumber_TrueDivide(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(BINARY_FLOOR_DIVIDE) {
    w = POP();
    v = TOP();
    x = PyNumber_FloorDivide(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
} END_OPCODE

FAT_OPCODE(BINARY_MODULO) {
    w = POP();
    v = TOP();
    x = PyNumber_Remainder(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

static PyObject *
string_concatenate(PyObject *v, PyObject *w,
		   PyFrameObject *f)
{
	/* This function implements 'variable += expr' when both arguments
	   are strings. */
	Py_ssize_t v_len = PyString_GET_SIZE(v);
	Py_ssize_t w_len = PyString_GET_SIZE(w);
	Py_ssize_t new_len = v_len + w_len;
	if (new_len < 0) {
		PyErr_SetString(PyExc_OverflowError,
				"strings are too large to concat");
		return NULL;
	}

        // HUGE XXX 
// 	if (v->ob_refcnt == 2) {
// 		/* In the common case, there are 2 references to the value
// 		 * stored in 'variable' when the += is performed: one on the
// 		 * value stack (in 'v') and one still stored in the 'variable'.
// 		 * We try to delete the variable now to reduce the refcnt to 1.
// 		 */
// 		switch (*next_instr) {
// 		case STORE_FAST:
// 		{
// 			int oparg = PEEKARG();
// 			PyObject **fastlocals = f->f_localsplus;
// 			if (GETLOCAL(oparg) == v)
// 				SETLOCAL(oparg, NULL);
// 			break;
// 		}
// 		case STORE_DEREF:
// 		{
// 			PyObject **freevars = f->f_localsplus + f->f_code->co_nlocals;
// 			PyObject *c = freevars[PEEKARG()];
// 			if (PyCell_GET(c) == v)
// 				PyCell_Set(c, NULL);
// 			break;
// 		}
// 		case STORE_NAME:
// 		{
// 			PyObject *names = f->f_code->co_names;
// 			PyObject *name = GETITEM(names, PEEKARG());
// 			PyObject *locals = f->f_locals;
// 			if (PyDict_CheckExact(locals) &&
// 			    PyDict_GetItem(locals, name) == v) {
// 				if (PyDict_DelItem(locals, name) != 0) {
// 					PyErr_Clear();
// 				}
// 			}
// 			break;
// 		}
// 		}
// 	}

	if (v->ob_refcnt == 1 && !PyString_CHECK_INTERNED(v)) {
		/* Now we own the last reference to 'v', so we can resize it
		 * in-place.
		 */
		if (_PyString_Resize(&v, new_len) != 0) {
			/* XXX if _PyString_Resize() fails, 'v' has been
			 * deallocated so it cannot be put back into 'variable'.
			 * The MemoryError is raised when there is no value in
			 * 'variable', which might (very remotely) be a cause
			 * of incompatibilities.
			 */
			return NULL;
		}
		/* copy 'w' into the newly allocated area of 'v' */
		memcpy(PyString_AS_STRING(v) + v_len,
		       PyString_AS_STRING(w), w_len);
		return v;
	}
	else {
		/* When in-place resizing is not an option. */
		PyString_Concat(&v, w);
		return v;
	}
}

FAT_OPCODE(BINARY_ADD) {
    w = POP();
    v = TOP();
    if (PyInt_CheckExact(v) && PyInt_CheckExact(w)) {
        /* INLINE: int + int */
        register long a, b, i;
        a = PyInt_AS_LONG(v);
        b = PyInt_AS_LONG(w);
        i = a + b;
        if ((i^a) < 0 && (i^b) < 0)
            goto slow_add;
        x = PyInt_FromLong(i);
    }
    else if (PyString_CheckExact(v) &&
             PyString_CheckExact(w)) {
        x = string_concatenate(v, w, F);
        /* string_concatenate consumed the ref to v */
        goto skip_decref_vx;
    }
    else {
    slow_add:
        x = PyNumber_Add(v, w);
    }
    Py_DECREF(v);
 skip_decref_vx:
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(BINARY_SUBTRACT) {
    w = POP();
    v = TOP();
    if (PyInt_CheckExact(v) && PyInt_CheckExact(w)) {
        /* INLINE: int - int */
        register long a, b, i;
        a = PyInt_AS_LONG(v);
        b = PyInt_AS_LONG(w);
        i = a - b;
        if ((i^a) < 0 && (i^~b) < 0)
            goto slow_sub;
        x = PyInt_FromLong(i);
    }
    else {
    slow_sub:
        x = PyNumber_Subtract(v, w);
    }
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

#undef ISINDEX
#define ISINDEX(x) ((x) == NULL || \
		    PyInt_Check(x) || PyLong_Check(x) || PyIndex_Check(x))

static PyObject *
apply_slice(PyObject *u, PyObject *v, PyObject *w) /* return u[v:w] */
{
	PyTypeObject *tp = u->ob_type;
	PySequenceMethods *sq = tp->tp_as_sequence;

	if (sq && sq->sq_slice && ISINDEX(v) && ISINDEX(w)) {
		Py_ssize_t ilow = 0, ihigh = PY_SSIZE_T_MAX;
		if (!_PyEval_SliceIndex(v, &ilow))
			return NULL;
		if (!_PyEval_SliceIndex(w, &ihigh))
			return NULL;
		return PySequence_GetSlice(u, ilow, ihigh);
	}
	else {
		PyObject *slice = PySlice_New(v, w, NULL);
		if (slice != NULL) {
			PyObject *res = PyObject_GetItem(u, slice);
			Py_DECREF(slice);
			return res;
		}
		else
			return NULL;
	}
}

static int
assign_slice(PyObject *u, PyObject *v, PyObject *w, PyObject *x)
	/* u[v:w] = x */
{
	PyTypeObject *tp = u->ob_type;
	PySequenceMethods *sq = tp->tp_as_sequence;

	if (sq && sq->sq_ass_slice && ISINDEX(v) && ISINDEX(w)) {
		Py_ssize_t ilow = 0, ihigh = PY_SSIZE_T_MAX;
		if (!_PyEval_SliceIndex(v, &ilow))
			return -1;
		if (!_PyEval_SliceIndex(w, &ihigh))
			return -1;
		if (x == NULL)
			return PySequence_DelSlice(u, ilow, ihigh);
		else
			return PySequence_SetSlice(u, ilow, ihigh, x);
	}
	else {
		PyObject *slice = PySlice_New(v, w, NULL);
		if (slice != NULL) {
			int res;
			if (x != NULL)
				res = PyObject_SetItem(u, slice, x);
			else
				res = PyObject_DelItem(u, slice);
			Py_DECREF(slice);
			return res;
		}
		else
			return -1;
	}
}

FAT_OPCODE(SLICE) {
    if ((opcode-SLICE) & 2)
        w = POP();
    else
        w = NULL;
    if ((opcode-SLICE) & 1)
        v = POP();
    else
        v = NULL;
    u = TOP();
    x = apply_slice(u, v, w);
    Py_DECREF(u);
    Py_XDECREF(v);
    Py_XDECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(STORE_SLICE) {
    if ((opcode-STORE_SLICE) & 2)
        w = POP();
    else
        w = NULL;
    if ((opcode-STORE_SLICE) & 1)
        v = POP();
    else
        v = NULL;
    u = POP();
    PyObject* t = POP();
    err = assign_slice(u, v, w, t); /* u[v:w] = t */
    Py_DECREF(t);
    Py_DECREF(u);
    Py_XDECREF(v);
    Py_XDECREF(w);
    if (err == 0) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(DELETE_SLICE) {
    if ((opcode-DELETE_SLICE) & 2)
        w = POP();
    else
        w = NULL;
    if ((opcode-DELETE_SLICE) & 1)
        v = POP();
    else
        v = NULL;
    u = POP();
    err = assign_slice(u, v, w, (PyObject *)NULL);
    /* del u[v:w] */
    Py_DECREF(u);
    Py_XDECREF(v);
    Py_XDECREF(w);
    if (err == 0) CONTINUE();
    BREAK();
} END_OPCODE

OPCODE(ROT_TWO) {
    v = TOP();
    w = SECOND();
    SET_TOP(w);
    SET_SECOND(v);
    CONTINUE();
} END_OPCODE
	
OPCODE(ROT_THREE) {
    v = TOP();
    w = SECOND();
    x = THIRD();
    SET_TOP(w);
    SET_SECOND(x);
    SET_THIRD(v);
    CONTINUE();
} END_OPCODE

OPCODE(ROT_FOUR) {
    u = TOP();
    v = SECOND();
    w = THIRD();
    x = FOURTH();
    SET_TOP(v);
    SET_SECOND(w);
    SET_THIRD(x);
    SET_FOURTH(u);
    CONTINUE();
} END_OPCODE

OPCODE(NOP) {
    CONTINUE();
} END_OPCODE

static int
unpack_iterable(PyObject *v, int argcnt, PyObject **sp)
{
	int i = 0;
	PyObject *it;  /* iter(v) */
	PyObject *w;

	assert(v != NULL);

	it = PyObject_GetIter(v);
	if (it == NULL)
		goto Error;

	for (; i < argcnt; i++) {
		w = PyIter_Next(it);
		if (w == NULL) {
			/* Iterator done, via error or exhaustion. */
			if (!PyErr_Occurred()) {
				PyErr_Format(PyExc_ValueError,
					"need more than %d value%s to unpack",
					i, i == 1 ? "" : "s");
			}
			goto Error;
		}
		*--sp = w;
	}

	/* We better have exhausted the iterator now. */
	w = PyIter_Next(it);
	if (w == NULL) {
		if (PyErr_Occurred())
			goto Error;
		Py_DECREF(it);
		return 1;
	}
	Py_DECREF(w);
	PyErr_SetString(PyExc_ValueError, "too many values to unpack");
	/* fall through */
Error:
	for (; i > 0; i--, sp++)
		Py_DECREF(*sp);
	Py_XDECREF(it);
	return 0;
}

FAT_OPCODE(UNPACK_SEQUENCE) {
    v = POP();
    if (PyTuple_CheckExact(v) && PyTuple_GET_SIZE(v) == oparg) {
        PyObject **items = ((PyTupleObject *)v)->ob_item;
        while (oparg--) {
            w = items[oparg];
            Py_INCREF(w);
            PUSH(w);
        }
        Py_DECREF(v);
        CONTINUE();
    } else if (PyList_CheckExact(v) && PyList_GET_SIZE(v) == oparg) {
        PyObject **items = ((PyListObject *)v)->ob_item;
        while (oparg--) {
            w = items[oparg];
            Py_INCREF(w);
            PUSH(w);
        }
        CONTINUE();
    } else if (unpack_iterable(v, oparg,
                               (STACK_POINTER) + oparg)) {
        (STACK_POINTER) += oparg;
        CONTINUE();
    } else {
        /* unpack_iterable() raised an exception */
        WHY = WHY_EXCEPTION;
    }
    Py_DECREF(v);
    BREAK();
} END_OPCODE

OPCODE(BREAK_LOOP) {
    WHY = WHY_BREAK;
    BREAK();
} END_OPCODE

FAT_OPCODE(BINARY_LSHIFT) {
    w = POP();
    v = TOP();
    x = PyNumber_Lshift(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(BINARY_RSHIFT) {
    w = POP();
    v = TOP();
    x = PyNumber_Rshift(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(BINARY_AND) {
    w = POP();
    v = TOP();
    x = PyNumber_And(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(BINARY_XOR) {
    w = POP();
    v = TOP();
    x = PyNumber_Xor(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(BINARY_OR) {
    w = POP();
    v = TOP();
    x = PyNumber_Or(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(INPLACE_POWER) {
    w = POP();
    v = TOP();
    x = PyNumber_InPlacePower(v, w, Py_None);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(INPLACE_MULTIPLY) {
    w = POP();
    v = TOP();
    x = PyNumber_InPlaceMultiply(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(INPLACE_DIVIDE) {
    if (opcode == INPLACE_DIVIDE && !_Py_QnewFlag) {
        w = POP();
        v = TOP();
        x = PyNumber_InPlaceDivide(v, w);
        Py_DECREF(v);
        Py_DECREF(w);
        SET_TOP(x);
        if (x != NULL) CONTINUE();
        BREAK();
    }
    /* -Qnew is in effect:	fall through to
       INPLACE_TRUE_DIVIDE */
    // case INPLACE_TRUE_DIVIDE:
    w = POP();
    v = TOP();
    x = PyNumber_InPlaceTrueDivide(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(INPLACE_FLOOR_DIVIDE) {
    w = POP();
    v = TOP();
    x = PyNumber_InPlaceFloorDivide(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(INPLACE_MODULO) {
    w = POP();
    v = TOP();
    x = PyNumber_InPlaceRemainder(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(INPLACE_ADD) {
    w = POP();
    v = TOP();
    if (PyInt_CheckExact(v) && PyInt_CheckExact(w)) {
        /* INLINE: int + int */
        register long a, b, i;
        a = PyInt_AS_LONG(v);
        b = PyInt_AS_LONG(w);
        i = a + b;
        if ((i^a) < 0 && (i^b) < 0)
            goto slow_iadd;
        x = PyInt_FromLong(i);
    }
    else if (PyString_CheckExact(v) &&
             PyString_CheckExact(w)) {
        x = string_concatenate(v, w, F); // XXX 
        /* string_concatenate consumed the ref to v */
        goto skip_decref_v;
    }
    else {
    slow_iadd:
        x = PyNumber_InPlaceAdd(v, w);
    }
    Py_DECREF(v);
 skip_decref_v:
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(INPLACE_SUBTRACT) {
    w = POP();
    v = TOP();
    if (PyInt_CheckExact(v) && PyInt_CheckExact(w)) {
        /* INLINE: int - int */
        register long a, b, i;
        a = PyInt_AS_LONG(v);
        b = PyInt_AS_LONG(w);
        i = a - b;
        if ((i^a) < 0 && (i^~b) < 0)
            goto slow_isub;
        x = PyInt_FromLong(i);
    }
    else {
    slow_isub:
        x = PyNumber_InPlaceSubtract(v, w);
    }
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(INPLACE_LSHIFT) {
    w = POP();
    v = TOP();
    x = PyNumber_InPlaceLshift(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(INPLACE_RSHIFT) {
    w = POP();
    v = TOP();
    x = PyNumber_InPlaceRshift(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(INPLACE_AND) {
    w = POP();
    v = TOP();
    x = PyNumber_InPlaceAnd(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(INPLACE_XOR) {
    w = POP();
    v = TOP();
    x = PyNumber_InPlaceXor(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(INPLACE_OR) {
    w = POP();
    v = TOP();
    x = PyNumber_InPlaceOr(v, w);
    Py_DECREF(v);
    Py_DECREF(w);
    SET_TOP(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(LOAD_CLOSURE) {
    PyObject** freevars = F->f_localsplus + F->f_code->co_nlocals;
    x = freevars[oparg];
    Py_INCREF(x);
    PUSH(x);
    if (x != NULL) CONTINUE();
    BREAK();
} END_OPCODE

FAT_OPCODE(LOAD_DEREF) {
    PyObject** freevars = F->f_localsplus + F->f_code->co_nlocals;
    x = freevars[oparg];
    w = PyCell_Get(x);
    if (w != NULL) {
        PUSH(w);
        CONTINUE();
    }
    err = -1;
    /* Don't stomp existing exception */
    if (PyErr_Occurred())
        BREAK();
    if (oparg < PyTuple_GET_SIZE(CO->co_cellvars)) {
        v = PyTuple_GET_ITEM(CO->co_cellvars,
                             oparg);
        format_exc_check_arg(
                             PyExc_UnboundLocalError,
                             UNBOUNDLOCAL_ERROR_MSG,
                             v);
    } else {
        v = PyTuple_GET_ITEM(
                             CO->co_freevars,
                             oparg - PyTuple_GET_SIZE(CO->co_cellvars));
        format_exc_check_arg(
                             PyExc_NameError,
                             UNBOUNDFREE_ERROR_MSG,
                             v);
    }
    BREAK();
} END_OPCODE

FAT_OPCODE(STORE_DEREF) {
    PyObject** freevars = F->f_localsplus + F->f_code->co_nlocals;
    w = POP();
    x = freevars[oparg];
    PyCell_Set(x, w);
    Py_DECREF(w);
    CONTINUE();
} END_OPCODE

OPCODE(DUP_TOPX) {
    if (oparg == 2) {
        x = TOP();
        Py_INCREF(x);
        w = SECOND();
        Py_INCREF(w);
        STACKADJ(2);
        SET_TOP(x);
        SET_SECOND(w);
        CONTINUE();
    } else if (oparg == 3) {
        x = TOP();
        Py_INCREF(x);
        w = SECOND();
        Py_INCREF(w);
        v = THIRD();
        Py_INCREF(v);
        STACKADJ(3);
        SET_TOP(x);
        SET_SECOND(w);
        SET_THIRD(v);
        CONTINUE();
    }
    Py_FatalError("invalid argument to DUP_TOPX"
                  " (bytecode corruption?)");
    BREAK();

} END_OPCODE
