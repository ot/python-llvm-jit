/* -*- c-basic-offset: 4; indent-tabs-mode: nil; mode: c++ -*- */

#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Bitcode/ReaderWriter.h>

#include <llvm/Module.h>
#include <llvm/ModuleProvider.h>

#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/DerivedTypes.h>
#include <llvm/Support/IRBuilder.h>

#include "Python.h"
#include "opcode.h"
#include "pythonrun.h"
#include "frameobject.h"

#include <map>
#include <sstream>
#include <stdint.h>
#include <cstdlib>

intptr_t py_id(PyObject* o) {
    return (intptr_t)o;
}

typedef PyObject* (*jitted_cfunc_t)(PyFrameObject*);

class JITRuntime {
public:
  
    JITRuntime() {
        using namespace llvm;
        MemoryBuffer* buffer = MemoryBuffer::getFile("vm_runtime.bc");
        assert(buffer);				
        MP = getBitcodeModuleProvider(buffer);
        the_module = MP->getModule();
        EE = ExecutionEngine::create(MP, true);

        const Type* ty_pyframe = the_module->getTypeByName("struct.PyFrameObject");
        assert(ty_pyframe);
        ty_pyframe_ptr = PointerType::getUnqual(ty_pyframe);

        const Type* ty_pyobject = the_module->getTypeByName("struct.PyObject");
        ty_pyobject_ptr = PointerType::getUnqual(ty_pyobject);

        std::vector<const Type*> func_args;
        func_args.push_back(ty_pyframe_ptr);
        ty_jitted_function = FunctionType::get(ty_pyobject_ptr, func_args, false); // XXX return type

        opcode_unimplemented = the_module->getFunction("opcode_UNIMPLEMENTED");
        check_err = the_module->getFunction("check_err");

        register_opcodes();
    }
  
    ~JITRuntime() {
        delete EE;
    }
  
    llvm::Function* compile(PyCodeObject* co) {
        using namespace llvm;
    
        std::string fname = make_function_name(co);
        // XXX check if function already exists
        Function* func = Function::Create(ty_jitted_function, Function::ExternalLinkage, fname.c_str(), the_module);
        Value* func_f = func->arg_begin();
        func_f->setName("f");

        const uint8_t* bytecode = (const uint8_t*) PyString_AS_STRING(co->co_code);
        const uint8_t* cur_instr = bytecode;
    
        BasicBlock* entry = BasicBlock::Create("entry", func);
        BasicBlock* block_end_block = BasicBlock::Create("block_end", func);
        IRBuilder<> builder(entry);
  
        Value* err_var = builder.CreateAlloca(Type::Int32Ty, 0, "err");
        builder.CreateStore(ConstantInt::get(APInt(32, 0)), err_var);
        Value* why_var = builder.CreateAlloca(Type::Int32Ty, 0, "why"); 
        builder.CreateStore(ConstantInt::get(APInt(32, 1)), why_var); // WHY_NOT
        Value* retval_var = builder.CreateAlloca(ty_pyobject_ptr,
                                                 0, "retval");

        while (*cur_instr) {
            unsigned int opcode = *cur_instr++;
            unsigned int oparg = 0;
            if (HAS_ARG(opcode)) {
                unsigned int arg1 = *cur_instr++;
                unsigned int arg2 = *cur_instr++;
                oparg = (arg2 << 8) + arg1;
            }
            SmallVector<Value*, 5> opcode_args;
            opcode_args.push_back(func_f);
            opcode_args.push_back(ConstantInt::get(APInt(32, opcode)));
            opcode_args.push_back(ConstantInt::get(APInt(32, oparg)));
            opcode_args.push_back(err_var);
            opcode_args.push_back(why_var);
            opcode_args.push_back(retval_var);

            Function* ophandler = opcode_unimplemented;
            if (opcode_funcs.count(opcode)) {
                ophandler = opcode_funcs[opcode];
            }
            builder.CreateCall(ophandler, opcode_args.begin(), opcode_args.end());
            builder.CreateCall(check_err, err_var);

            //       char opblockname[20];
            //       sprintf(opblockname, "__op_%d", cur_instr - bytecode);
            //       BasicBlock* opblock = BasicBlock::Create(opblockname, func);
            //       builder.SetInsertPoint(opblock);
      
            switch(opcode) {
            case RETURN_VALUE:
                builder.CreateBr(block_end_block);
                break;
            default:
                break;
            }
        }
        BasicBlock* end_block = BasicBlock::Create("end", func);
        builder.SetInsertPoint(block_end_block);
        builder.CreateBr(end_block);
        builder.SetInsertPoint(end_block);

        Value* retvalval = builder.CreateLoad(retval_var);
        builder.CreateRet(retvalval);
        func->dump();
      
        return func;
    }

    void run(llvm::Function* func, PyFrameObject* f) {
        using namespace llvm;
        std::vector<GenericValue> args;
        args.push_back(GenericValue((void*)f));
        EE->runFunction(func, args);
    }

protected:
    void register_opcodes() {
        using namespace llvm;

#       define REGISTER_OPCODE(OPCODENAME)                              \
        {                                                               \
            Function* ophandler = the_module->getFunction("opcode_" #OPCODENAME); \
            opcode_funcs[OPCODENAME] = ophandler;                       \
        }                                                               \
        /**/
            
        REGISTER_OPCODE(STORE_NAME);
        REGISTER_OPCODE(RETURN_VALUE);
        REGISTER_OPCODE(LOAD_CONST);
        REGISTER_OPCODE(PRINT_ITEM);
        REGISTER_OPCODE(PRINT_NEWLINE);
            
#       undef REGISTER_OPCODE
        
    }
      
    llvm::ModuleProvider* MP;
    llvm::Module* the_module;
    llvm::ExecutionEngine* EE;

    std::map<int, llvm::Function*> opcode_funcs;
    llvm::Function* opcode_unimplemented;
    llvm::Function* check_err;

    const llvm::Type* ty_pyobject_ptr;
    const llvm::Type* ty_pyframe_ptr;
    llvm::FunctionType* ty_jitted_function;

    std::string make_function_name(PyCodeObject* co) {
        std::ostringstream os;
        os << "bytecode_at_";
        os << py_id((PyObject*)co);
        return os.str();
    }
};


int main() {
    JITRuntime jit;
    Py_InitializeEx(0);
    const char* code = 
        //"print 1\n"
        "x = 1\n";
  
    PyCodeObject* co = (PyCodeObject*)Py_CompileString(code, "<test.py>", Py_file_input);

    // show the bytecode
    PyObject* dis_module = PyImport_ImportModule("dis");
    PyObject* dis = PyObject_GetAttrString(dis_module, "dis");
    PyObject_CallFunctionObjArgs(dis, co, NULL);

    // show LLVM bitcode
    llvm::Function* cf = jit.compile(co);

    // try to execute function
    PyThreadState *tstate = PyThreadState_GET();
    PyObject* locals = PyDict_New();
    PyObject* globals = PyDict_New();
    PyFrameObject* f = PyFrame_New(tstate, co, locals, globals);
    assert(f);
    
    //    PyEval_EvalFrame(f);
    jit.run(cf, f);
    
    Py_DECREF(f);
    Py_DECREF(co);
}
