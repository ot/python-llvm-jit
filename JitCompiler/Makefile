CXXFLAGS= -I ../Include -I ../ -fno-strict-aliasing -no-cpp-precomp -mno-fused-madd -g -fwrapv -Wall # -O3 #-DNDEBUG
CFLAGS= $(CXXFLAGS) -Wstrict-prototypes 
LLVM_CFLAGS=`llvm-config --cppflags`
LLVM_LDFLAGS=`llvm-config --ldflags --libs core jit native bitreader bitwriter ipo interpreter`

LDFLAGS=-disable-opt

# This has to match Python Makefile's (or target triple will mismatch and no linking will be done (or will be?))
MACOSX_DEPLOYMENT_TARGET=10.3
export MACOSX_DEPLOYMENT_TARGET

all: JitCompiler vm_runtime.bc

vm_runtime.bc: vm_opcodes.c
	llvm-gcc --emit-llvm  -I ../Include -I ../ -fno-strict-aliasing -no-cpp-precomp -mno-fused-madd -fwrapv -Wall -DNDEBUG -O3 -g0 \
		 vm_opcodes.c -c -o vm_runtime.bc

JitCompiler: JitCompiler.cpp
	g++ $(CXXFLAGS) $(LLVM_CFLAGS) -DJIT_TEST JitCompiler.cpp $(LLVM_LDFLAGS) -lpython -o JitCompiler

JitCompiler.o: JitCompiler.cpp 
	g++  $(CXXFLAGS) -O3 $(LLVM_CFLAGS) JitCompiler.cpp -c -o JitCompiler.o
clean:
	rm -fr *.o *.bc JitCompiler JitCompiler.dSYM

.PHONY: all clean