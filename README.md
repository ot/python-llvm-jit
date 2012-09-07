python-llvm-jit
===============

Early experiments with a JIT compiler for CPython using the LLVM
framework. This code is here only for historical purposes.

This project implements a JIT compiler on top of Python 2.5.2. It
works by translating the Python bytecode into LLVM bitcode which calls
back the CPython runtime, basically unrolling the interpreter loop. 

No more work was done on this because of not very promising results
(in particular the compilation times are very high with LLVM 2.5, but
the situation may have improved with newer versions of the framework),
and because [Unladen Swallow][unladen] was announced shortly after, which uses
roughly the same approach. 

A short report on my experiments was posted in [this thread][thread] in the
Unladen Swallow mailing list.

[unladen]: http://code.google.com/p/unladen-swallow
[thread]: https://groups.google.com/d/msg/unladen-swallow/bqf9TzWHhts/1mDiQn5IRYoJ
