CXXFLAGS= -I ../Include -I ../ -fno-strict-aliasing -no-cpp-precomp -mno-fused-madd -g -fwrapv -Wall #-O3 -DNDEBUG
CFLAGS= $(CXXFLAGS) -Wstrict-prototypes 
LLVM_CFLAGS=`llvm-config --cppflags`
LLVM_LDFLAGS=`llvm-config --ldflags --libs core jit native bitreader bitwriter ipo interpreter`

LDFLAGS=-disable-opt

# This has to match Python Makefile's (or target triple will mismatch and no linking will be done)
MACOSX_DEPLOYMENT_TARGET=10.3
export MACOSX_DEPLOYMENT_TARGET

all: llvm_compiler vm_runtime.bc

vm_opcodes.o: vm_opcodes.c
	llvm-gcc --emit-llvm $(CFLAGS) vm_opcodes.c -c -o vm_opcodes.o

vm_runtime.bc: vm_opcodes.o
	make -C ../ libpython2.5.a
	llvm-ld $(LDFLAGS) -link-as-library vm_opcodes.o ../libpython2.5.a -o vm_runtime.bc

llvm_compiler: llvm_compiler.cpp 
	g++ $(CXXFLAGS) $(LLVM_CFLAGS) llvm_compiler.cpp $(LLVM_LDFLAGS) -lpython -o llvm_compiler

clean:
	rm -f *.o *.bc llvm_compiler

.PHONY: all clean