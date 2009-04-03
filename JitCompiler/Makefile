CXXFLAGS= -I ../Include -I ../ -g 
CFLAGS= $(CXXFLAGS) -Wstrict-prototypes 
LLVM_CFLAGS=`llvm-config --cppflags`
LLVM_LDFLAGS=`llvm-config --ldflags --libs core jit native bitreader bitwriter ipo interpreter`

all: JitCompiler vm_runtime.bc

vm_runtime.bc: 
	make -C ../ JitCompiler/vm_runtime.bc

JitCompiler: JitCompiler.cpp vm_runtime.bc
	g++ $(CXXFLAGS) $(LLVM_CFLAGS) -DJIT_TEST JitCompiler.cpp $(LLVM_LDFLAGS) -lpython -o JitCompiler

clean:
	rm -fr *.o *.bc JitCompiler JitCompiler.dSYM

.PHONY: all clean vm_runtime.bc