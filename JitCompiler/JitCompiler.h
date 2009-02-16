/* -*- c-basic-offset: 4; indent-tabs-mode: nil; mode: c++ -*- */
#ifndef JIT_COMPILER_27012009
#define JIT_COMPILER_27012009

#include "Python.h"
#include "frameobject.h"

#ifdef __cplusplus
extern "C" {
#endif
    
    void init_jit_runtime(void);  
    void finalize_jit_runtime(void);
    
    struct PyJittedFunc;
    typedef PyObject* (*jitted_cfunc_t)(PyFrameObject*, PyThreadState*, int);

    jitted_cfunc_t get_jitted_function(PyCodeObject* co);
    void finalize_jitted_function(PyCodeObject* co);

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


    
#ifdef __cplusplus
}
#endif

#endif /* JIT_COMPILER_27012009 */
