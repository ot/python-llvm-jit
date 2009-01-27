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
        EE = ExecutionEngine::create(MP, false);

        const Type* ty_pyframe = the_module->getTypeByName("struct.PyFrameObject");
        assert(ty_pyframe);
        ty_pyframe_ptr = PointerType::getUnqual(ty_pyframe);

        const Type* ty_pyobject = the_module->getTypeByName("struct.PyObject");
        ty_pyobject_ptr = PointerType::getUnqual(ty_pyobject);

        const Type* ty_pythreadstate = the_module->getTypeByName("struct.PyThreadState");
        ty_pythreadstate_ptr = PointerType::getUnqual(ty_pythreadstate);

        std::vector<const Type*> func_args;
        func_args.push_back(ty_pyframe_ptr);
        func_args.push_back(ty_pythreadstate_ptr);
        ty_jitted_function = FunctionType::get(ty_pyobject_ptr, func_args, false); // XXX return type

        opcode_unimplemented = the_module->getFunction("opcode_UNIMPLEMENTED");
        check_err = the_module->getFunction("check_err");
        is_top_true = the_module->getFunction("is_top_true");
        unwind_stack = the_module->getFunction("unwind_stack");

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
        Function::arg_iterator func_args = func->arg_begin();
        Value* func_f = func_args++;
        func_f->setName("f");
        Value* func_tstate = func_args++;
        func_tstate->setName("tstate");

        const uint8_t* bytecode = (const uint8_t*) PyString_AS_STRING(co->co_code);
    
        BasicBlock* entry = BasicBlock::Create("entry", func);
        IRBuilder<> builder(entry);
  
        Value* err_var = builder.CreateAlloca(Type::Int32Ty, 0, "err");
        builder.CreateStore(ConstantInt::get(APInt(32, 0)), err_var);
        Value* why_var = builder.CreateAlloca(Type::Int32Ty, 0, "why"); 
        builder.CreateStore(ConstantInt::get(APInt(32, 1)), why_var); // WHY_NOT
        Value* retval_var = builder.CreateAlloca(ty_pyobject_ptr,
                                                 0, "retval");
        Value* dispatch_var = builder.CreateAlloca(Type::Int32Ty, 0, "dispatch_to_instr"); 

        BasicBlock* end_block = BasicBlock::Create("end", func);
        builder.SetInsertPoint(end_block);
        Value* retvalval = builder.CreateLoad(retval_var);
        builder.CreateRet(retvalval);

        // create the opcode blocks

        BasicBlock* dispatch_block = BasicBlock::Create("dispatch", func);
        builder.SetInsertPoint(dispatch_block);
        Value* dispatch_val = builder.CreateLoad(dispatch_var);
        SwitchInst* dispatch_switch = builder.CreateSwitch(dispatch_val, end_block);

        std::map<int, BasicBlock*> opblocks; // XXX a vector would be better?
        char opblockname[20];
        for (const uint8_t* cur_instr = bytecode; *cur_instr; ++cur_instr) {
            int line = cur_instr - bytecode;
            unsigned int opcode = *cur_instr;
            if (HAS_ARG(opcode)) cur_instr += 2;
            
            sprintf(opblockname, "__op_%d", line);
            BasicBlock* opblock = BasicBlock::Create(std::string(opblockname), func);
            
            opblocks[line] = opblock; 
            dispatch_switch->addCase(ConstantInt::get(APInt(32, line)), opblock);
        }
        builder.SetInsertPoint(entry);
        builder.CreateBr(opblocks[0]);
        
        BasicBlock* block_end_block = BasicBlock::Create("block_end", func);

        // fill in the opcode blocks
        for (const uint8_t* cur_instr = bytecode; *cur_instr; ++cur_instr) {
            int line = cur_instr - bytecode;
            unsigned int opcode = *cur_instr;
            unsigned int oparg = 0;
            if (HAS_ARG(opcode)) {
                unsigned int arg1 = *++cur_instr;
                unsigned int arg2 = *++cur_instr;
                oparg = (arg2 << 8) + arg1;
            }

            builder.SetInsertPoint(opblocks[line]);

            SmallVector<Value*, 5> opcode_args;
            opcode_args.push_back(func_f);
            opcode_args.push_back(ConstantInt::get(APInt(32, line)));
            opcode_args.push_back(ConstantInt::get(APInt(32, opcode)));
            opcode_args.push_back(ConstantInt::get(APInt(32, oparg)));
            opcode_args.push_back(err_var);
            opcode_args.push_back(why_var);
            opcode_args.push_back(retval_var);

            Function* ophandler;
            Value* opret;
            Value* b_opret;
#           define DEFAULT_HANDLER                                      \
            if (opcode_funcs.count(opcode)) ophandler = opcode_funcs[opcode]; \
            else ophandler = opcode_unimplemented;                      \
            opret = builder.CreateCall(ophandler, opcode_args.begin(), opcode_args.end()); \
            /*            builder.CreateCall2(check_err, ConstantInt::get(APInt(32, line)), err_var); */ \
            /**/
      
            switch(opcode) {
            case RETURN_VALUE:
                DEFAULT_HANDLER;
                builder.CreateBr(block_end_block);
                break;
            case JUMP_FORWARD: {
                int next_line = line + 3 + oparg; // 3 is JUMP_FORWARD + oparg
                builder.CreateBr(opblocks[next_line]);
                break;
            }
            case JUMP_ABSOLUTE: {
                builder.CreateBr(opblocks[oparg]);
                break;
            }
            case JUMP_IF_TRUE:
            case JUMP_IF_FALSE: {
                int true_line = line + 3;
                int false_line = line + 3 + oparg;
                if (opcode == JUMP_IF_TRUE) std::swap(true_line, false_line);
                Value* cond = builder.CreateCall2(is_top_true, func_f, err_var);
                builder.CreateCall2(check_err, ConstantInt::get(APInt(32, line)), err_var); 
                Value* bcond = builder.CreateICmpEQ(cond, ConstantInt::get(APInt(32, 1)));
                builder.CreateCondBr(bcond, opblocks[true_line], opblocks[false_line]);
                break;
            }

            case FOR_ITER: {
                opret = builder.CreateCall(opcode_funcs[opcode], opcode_args.begin(), opcode_args.end());
                SwitchInst* sw = builder.CreateSwitch(opret, block_end_block);
                sw->addCase(ConstantInt::get(APInt(32, 0)), block_end_block); // error
                sw->addCase(ConstantInt::get(APInt(32, 1)), opblocks[line + 3]); // continue loop
                sw->addCase(ConstantInt::get(APInt(32, 2)), opblocks[line + 3 + oparg]); // end loop
                break;
            }
                
            default: {
                DEFAULT_HANDLER;
                int next_line = line + (HAS_ARG(opcode) ? 3 : 1);
                b_opret = builder.CreateICmpEQ(opret, ConstantInt::get(APInt(32, 1)));
                builder.CreateCondBr(b_opret, opblocks[next_line], block_end_block);
                break;
            }
            }
        }
        builder.SetInsertPoint(block_end_block);

        std::vector<Value*> args;
        args.push_back(func_f);
        args.push_back(func_tstate);
        args.push_back(err_var);
        args.push_back(why_var);
        args.push_back(retval_var);
        args.push_back(dispatch_var);
        
        Value* do_jump = builder.CreateCall(unwind_stack, args.begin(), args.end());
        Value* b_do_jump = builder.CreateICmpEQ(do_jump, ConstantInt::get(APInt(32, 1)));
        builder.CreateCondBr(b_do_jump, dispatch_block, end_block);

        //func->dump();
      
        return func;
    }

    void run(llvm::Function* func, PyFrameObject* f, PyThreadState* tstate) {
        using namespace llvm;
        std::vector<GenericValue> args;
        args.push_back(GenericValue((void*)f));
        args.push_back(GenericValue((void*)tstate));
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

#       define REGISTER_ALIAS(ALIAS, OPCODENAME)       \
        opcode_funcs[ALIAS] = opcode_funcs[OPCODENAME];          \
        /**/
            
        REGISTER_OPCODE(STORE_NAME);
        REGISTER_OPCODE(RETURN_VALUE);
        REGISTER_OPCODE(LOAD_CONST);
        REGISTER_OPCODE(PRINT_ITEM);
        REGISTER_OPCODE(PRINT_NEWLINE);
        REGISTER_OPCODE(LOAD_NAME);
        REGISTER_OPCODE(COMPARE_OP);

        REGISTER_OPCODE(POP_TOP);
        REGISTER_OPCODE(DUP_TOP);

        REGISTER_OPCODE(SETUP_LOOP);
        REGISTER_ALIAS(SETUP_EXCEPT, SETUP_LOOP);
        REGISTER_ALIAS(SETUP_FINALLY, SETUP_LOOP);
        REGISTER_OPCODE(RAISE_VARARGS);

        REGISTER_OPCODE(BUILD_LIST);

        REGISTER_OPCODE(GET_ITER);
        REGISTER_OPCODE(FOR_ITER);

        REGISTER_OPCODE(POP_BLOCK);
        REGISTER_OPCODE(END_FINALLY);

        REGISTER_OPCODE(MAKE_FUNCTION);
        REGISTER_OPCODE(MAKE_CLOSURE);
        REGISTER_OPCODE(CALL_FUNCTION);
        REGISTER_OPCODE(CALL_FUNCTION_VAR);
        REGISTER_ALIAS(CALL_FUNCTION_KW, CALL_FUNCTION_VAR);
        REGISTER_ALIAS(CALL_FUNCTION_VAR_KW, CALL_FUNCTION_VAR);

        REGISTER_OPCODE(LOAD_ATTR);
            
#       undef REGISTER_OPCODE
#       undef REGISTER_ALIAS
        
    }
      
    llvm::ModuleProvider* MP;
    llvm::Module* the_module;
    llvm::ExecutionEngine* EE;

    std::map<int, llvm::Function*> opcode_funcs;
    llvm::Function* opcode_unimplemented;
    llvm::Function* check_err;
    llvm::Function* is_top_true;
    llvm::Function* unwind_stack;

    const llvm::Type* ty_pyobject_ptr;
    const llvm::Type* ty_pyframe_ptr;
    const llvm::Type* ty_pythreadstate_ptr;

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
    /*
    const char* code = 
        "print 1\n"
        "x = 1\n"
        "if x == 0:\n"
        "  print 'T'\n"
        "else:\n"
        "  print 'F'\n"
        "if 1: print 'OK'\n"
        "else: print 'NOT OK'\n"
        "if 0: print 'NOT OK'\n"
        "print 0 == 0\n"
        "print 0 == 1\n"
        "print x == 1\n"
        "for i in [1, 2, 3]: print i\n"
        "try:\n"
        "  print 'A'\n"
        "  xx = Exception\n"
        "  print 'B'\n"
        "  raise xx\n"
        "  print 'NOT OK'\n"
        "except Exception, e:\n"
        "  print e\n"
        ;
    */
    
    // C or C++ do not have a function "read a file into a string"????
#define MAXCODE 1024
    char code[MAXCODE];
    int bytes = fread(code, 1, MAXCODE-1, stdin);
    code[bytes] = 0;
    
  
    PyCodeObject* co = (PyCodeObject*)Py_CompileString(code, "<test.py>", Py_file_input);

    // show the bytecode
    PyObject* dis_module = PyImport_ImportModule("dis");
    PyObject* dis = PyObject_GetAttrString(dis_module, "dis");
    PyObject_CallFunctionObjArgs(dis, co, NULL);

    // show LLVM bitcode
    llvm::Function* cf = jit.compile(co);

    // try to execute function
    PyThreadState *tstate = PyThreadState_GET();
    PyObject* m = PyImport_AddModule("__main__");
    PyObject* d = PyModule_GetDict(m);
//     PyObject* locals = PyDict_New();
//     PyObject* globals = PyDict_New();
    PyFrameObject* f = PyFrame_New(tstate, co, d, d);
    assert(f);
    
    //PyEval_EvalFrame(f);

    tstate->frame = f;
    jit.run(cf, f, tstate);
    
    Py_DECREF(f);
    Py_DECREF(co);
}
