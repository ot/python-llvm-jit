#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Bitcode/ReaderWriter.h>

#include <llvm/Transforms/Utils/Cloning.h>

#include <llvm/PassManager.h>
#include <llvm/Target/TargetData.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Analysis/LoopPass.h>
#include <llvm/CallingConv.h>
#include <llvm/Analysis/Verifier.h>

#include <llvm/Module.h>
#include <llvm/ModuleProvider.h>

#include <llvm/DerivedTypes.h>
#include <llvm/Support/IRBuilder.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>

