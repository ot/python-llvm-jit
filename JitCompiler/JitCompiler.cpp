/* -*- c-basic-offset: 4; indent-tabs-mode: nil; mode: c++ -*- */

#include "JitCompiler.h"
#include "utility.h"

#include "Python.h"
#include "opcode.h"
#include "pythonrun.h"
#include "frameobject.h"

#include <map>
#include <sstream>
#include <stdint.h>
#include <cstdlib>

static intptr_t py_id(PyObject* o) {
    return (intptr_t)o;
}

class JITRuntime {
public:
    JITRuntime(int optimize = 1) {
        using namespace llvm;
        MemoryBuffer* buffer = MemoryBuffer::getFile("vm_runtime.bc");
        assert(buffer);				
        MP = getBitcodeModuleProvider(buffer);
        the_module = MP->materializeModule(); // XXX materialize needed for inlining?
        EE = ExecutionEngine::create(MP, false, 0, false);

        const Type* ty_pyframe = the_module->getTypeByName("struct.PyFrameObject");
        assert(ty_pyframe);
        ty_pyframe_ptr = PointerType::getUnqual(ty_pyframe);

        const Type* ty_pyobject = the_module->getTypeByName("struct.PyObject");
        ty_pyobject_ptr = PointerType::getUnqual(ty_pyobject);

        const Type* ty_pythreadstate = the_module->getTypeByName("struct.PyThreadState");
        ty_pythreadstate_ptr = PointerType::getUnqual(ty_pythreadstate);

        std::vector<const Type*> func_args = vector_of
            (ty_pyframe_ptr)
            (ty_pythreadstate_ptr)
            (Type::Int32Ty)
            .move();
        ty_jitted_function = FunctionType::get(ty_pyobject_ptr, func_args, false); // XXX return type

        opcode_unimplemented = the_module->getFunction("opcode_UNIMPLEMENTED");
        opcode_unimplemented->setCallingConv(CallingConv::Fast);
        is_top_true = the_module->getFunction("is_top_true");
        is_top_true->setCallingConv(CallingConv::Fast);
        unwind_stack = the_module->getFunction("unwind_stack");
        unwind_stack->setCallingConv(CallingConv::Fast);

        FPM = new FunctionPassManager(MP);
        FPM->add(new TargetData(*EE->getTargetData()));
        
        if (optimize == 1 || optimize == 2) {
            // mem2reg
            FPM->add(createPromoteMemoryToRegisterPass());
            // Do simple "peephole" optimizations and bit-twiddling optzns.
            FPM->add(createInstructionCombiningPass());
            // Dead code Elimination
            FPM->add(createDeadCodeEliminationPass());
            FPM->add(createCFGSimplificationPass());
        }
        if (optimize == 2) {
            // TailDuplication
            FPM->add(createTailDuplicationPass());
            // BlockPlacement
            FPM->add(createBlockPlacementPass());
            // Reassociate expressions.
            FPM->add(createReassociatePass());
            // Simplify the control flow graph (deleting unreachable blocks, etc).
            FPM->add(createCFGSimplificationPass());
        }

        if (optimize == 3) {
            // XXX Passes stolen from N3 VMKit -- recheck
            FPM->add(createCFGSimplificationPass());    // Clean up disgusting code
            FPM->add(createScalarReplAggregatesPass());// Kill useless allocas
            FPM->add(createInstructionCombiningPass()); // Clean up after IPCP & DAE
            FPM->add(createCFGSimplificationPass());    // Clean up after IPCP & DAE
            FPM->add(createPromoteMemoryToRegisterPass());// Kill useless allocas
            FPM->add(createInstructionCombiningPass()); // Clean up after IPCP & DAE
            FPM->add(createCFGSimplificationPass());    // Clean up after IPCP & DAE
  
            FPM->add(createTailDuplicationPass());      // Simplify cfg by copying code
            FPM->add(createInstructionCombiningPass()); // Cleanup for scalarrepl.
            FPM->add(createCFGSimplificationPass());    // Merge & remove BBs
            FPM->add(createScalarReplAggregatesPass()); // Break up aggregate allocas
            FPM->add(createInstructionCombiningPass()); // Combine silly seq's
            FPM->add(createCondPropagationPass());      // Propagate conditionals
  
   
            FPM->add(createTailCallEliminationPass());  // Eliminate tail calls
            FPM->add(createCFGSimplificationPass());    // Merge & remove BBs
            FPM->add(createReassociatePass());          // Reassociate expressions
            FPM->add(createLoopRotatePass());
            FPM->add(createLICMPass());                 // Hoist loop invariants
            FPM->add(createLoopUnswitchPass());         // Unswitch loops.
            FPM->add(createInstructionCombiningPass()); // Clean up after LICM/reassoc
            FPM->add(createIndVarSimplifyPass());       // Canonicalize indvars
            FPM->add(createLoopUnrollPass());           // Unroll small loops
            FPM->add(createInstructionCombiningPass()); // Clean up after the unroller
            //addPass(PM, mvm::createArrayChecksPass()); 
            FPM->add(createGVNPass());                  // GVN for load instructions
            //FPM->add(createGCSEPass());                 // Remove common subexprs
            FPM->add(createSCCPPass());                 // Constant prop with SCCP
            FPM->add(createPredicateSimplifierPass());                
        
        
            // Run instcombine after redundancy elimination to exploit opportunities
            // opened up by them.
            FPM->add(createInstructionCombiningPass());
            FPM->add(createCondPropagationPass());      // Propagate conditionals

            FPM->add(createDeadStoreEliminationPass()); // Delete dead stores
            FPM->add(createAggressiveDCEPass());        // SSA based 'Aggressive DCE'
            FPM->add(createCFGSimplificationPass());    // Merge & remove BBs
            //addPass(PM, mvm::createLowerArrayLengthPass());
        }

        PMverifier.add(llvm::createVerifierPass());

        register_opcodes();
    }
  
    ~JITRuntime() {
        delete EE;
        delete FPM;
    }
  
    llvm::Function* compile(PyCodeObject* co, int inlineopcodes = 1) {
        using namespace llvm;
    
        std::string fname = make_function_name(co);
        // XXX check if function already exists
        Function* func = Function::Create(ty_jitted_function, Function::ExternalLinkage, fname.c_str(), the_module);
        Function::arg_iterator func_args = func->arg_begin();
        Value* func_f = func_args++;
        func_f->setName("f");
        Value* func_tstate = func_args++;
        func_tstate->setName("tstate");
        Value* func_throwflag = func_args++; // XXX
        func_throwflag->setName("throwflag");

        std::vector<CallInst*> to_inline;

        const uint8_t* bytecode = (const uint8_t*) PyString_AS_STRING(co->co_code);
        Py_ssize_t codelen = PyString_Size(co->co_code);
        
        BasicBlock* entry = BasicBlock::Create("entry", func);
        BasicBlock* gen_throw_block = BasicBlock::Create("gen_throw", func);

        IRBuilder<> builder(entry);
  
        Value* st_var = builder.CreateAlloca(the_module->getTypeByName("struct.interpreter_state"), 0, "st"); 
        CallInst* init_st = builder.CreateCall3(the_module->getFunction("init_interpreter_state"), st_var, func_f, func_tstate);
        to_inline.push_back(init_st);

        Value* dispatch_var = builder.CreateAlloca(Type::Int32Ty, 0, "dispatch_to_instr"); 
        
        BasicBlock* end_block = BasicBlock::Create("end", func);
        {
            builder.SetInsertPoint(end_block);
            CallInst* retvalval = builder.CreateCall(the_module->getFunction("get_retval"), st_var);
            to_inline.push_back(retvalval);
            builder.CreateRet(retvalval);
        }
        // create the opcode blocks

        BasicBlock* dispatch_block = BasicBlock::Create("dispatch", func);
        builder.SetInsertPoint(dispatch_block);
        Value* dispatch_val = builder.CreateLoad(dispatch_var);
        SwitchInst* dispatch_switch = builder.CreateSwitch(dispatch_val, end_block);

        std::vector<BasicBlock*> opblocks(codelen);
        for (const uint8_t* cur_instr = bytecode; *cur_instr; ++cur_instr) {
            int line = cur_instr - bytecode;
            unsigned int opcode = *cur_instr;
            if (HAS_ARG(opcode)) cur_instr += 2;
            
            char opblockname[20];
            sprintf(opblockname, "__op_%d", line);
            BasicBlock* opblock = BasicBlock::Create(std::string(opblockname), func);
            
            opblocks[line] = opblock; 
            dispatch_switch->addCase(constant(line), opblock);
        }
        
        BasicBlock* block_end_block = BasicBlock::Create("block_end", func);

        // if throwflag goto block_end else dispatch to opblocks[f_lasti+1]
        builder.SetInsertPoint(entry);
        CallInst* gli = builder.CreateCall(the_module->getFunction("get_lasti"),
                                           func_f);
        to_inline.push_back(gli);
        Value* lastipp = builder.CreateAdd(gli, constant(1));
        builder.CreateStore(lastipp, dispatch_var);
        builder.CreateCondBr(is_zero(builder, func_throwflag), dispatch_block, gen_throw_block);

        builder.SetInsertPoint(gen_throw_block);
        to_inline.push_back(builder.CreateCall2(the_module->getFunction("set_why"), st_var, constant(WHY_EXCEPTION)));
        builder.CreateBr(block_end_block);
        
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

            std::vector<Value*> opcode_args = vector_of
                (st_var)
                (constant(line))
                (constant(opcode))
                (constant(oparg))
                .move();

            Function* ophandler;
            CallInst* opret;
#           define DEFAULT_HANDLER                                      \
            if (opcode_funcs.count(opcode)) ophandler = opcode_funcs[opcode]; \
            else ophandler = opcode_unimplemented;                      \
            assert(ophandler);                                          \
            opret = builder.CreateCall(ophandler, opcode_args.begin(), opcode_args.end()); \
            opret->setCallingConv(CallingConv::Fast);                   \
            if (!fat_opcode[opcode]) to_inline.push_back(opret);        \
            /**/
      
            switch(opcode) {
            case YIELD_VALUE: // XXX this will have to change (trace?)
            case RETURN_VALUE:
                DEFAULT_HANDLER;
                builder.CreateBr(block_end_block);
                break;
            case JUMP_FORWARD: {
                int next_line = line + 3 + oparg; // 3 is JUMP_FORWARD + oparg
                assert(next_line < codelen);
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
                CallInst* cond = builder.CreateCall(is_top_true, st_var);
                cond->setCallingConv(CallingConv::Fast);
                to_inline.push_back(cond);
                builder.CreateCondBr(is_zero(builder, cond), opblocks[false_line], opblocks[true_line]);
                break;
            }

            case FOR_ITER: {
                opret = builder.CreateCall(opcode_funcs[opcode], opcode_args.begin(), opcode_args.end());
                opret->setCallingConv(CallingConv::Fast);       
                to_inline.push_back(opret);
                SwitchInst* sw = builder.CreateSwitch(opret, block_end_block);
                sw->addCase(constant(1), block_end_block); // error
                sw->addCase(constant(0), opblocks[line + 3]); // continue loop
                sw->addCase(constant(2), opblocks[line + 3 + oparg]); // end loop
                break;
            }
                
            default: {
                DEFAULT_HANDLER;
                int next_line = line + (HAS_ARG(opcode) ? 3 : 1);
                if (next_line < codelen)
                    builder.CreateCondBr(is_zero(builder, opret), opblocks[next_line], block_end_block);
                else
                    builder.CreateBr(block_end_block);
                break;
            }
            }
        }
        
        builder.SetInsertPoint(block_end_block);
        
        CallInst* do_jump = builder.CreateCall2(unwind_stack, st_var, dispatch_var);
        do_jump->setCallingConv(CallingConv::Fast);
        //to_inline.push_back(do_jump);
        builder.CreateCondBr(is_zero(builder, do_jump), dispatch_block, end_block);

        //verify_function(func);

        if (inlineopcodes) {
            for (size_t i = 0; i < to_inline.size(); ++i)  {
                InlineFunction(to_inline[i]);
            }
        }
        FPM->run(*func);
        return func;
    }

    void verify_function(llvm::Function* func) {
        PMverifier.run(*func->getParent());
    }

    jitted_cfunc_t get_func_pointer(llvm::Function* func) {
        jitted_cfunc_t cfunc = (jitted_cfunc_t)EE->getPointerToFunction(func);
        return cfunc;
    }

protected:
    void register_opcodes() {
        using namespace llvm;
        fat_opcode.resize(256, false);
#       define REGISTER_OPCODE(OPCODENAME)                              \
        {                                                               \
            Function* ophandler = the_module->getFunction("opcode_" #OPCODENAME); \
            ophandler->setCallingConv(CallingConv::Fast);               \
            opcode_funcs[OPCODENAME] = ophandler;                       \
            if (the_module->getNamedGlobal("fat_opcode_" #OPCODENAME))  \
                fat_opcode[OPCODENAME] = true;                          \
        }                                                               \
        /**/
        
#       define REGISTER_ALIAS(ALIAS, OPCODENAME)                 \
        opcode_funcs[ALIAS] = opcode_funcs[OPCODENAME];          \
        fat_opcode[ALIAS] = fat_opcode[OPCODENAME];        \
        /**/
            
        REGISTER_OPCODE(NOP);
        REGISTER_OPCODE(ROT_TWO);
        REGISTER_OPCODE(ROT_THREE);
        REGISTER_OPCODE(ROT_FOUR);

        REGISTER_OPCODE(STORE_NAME);
        REGISTER_OPCODE(RETURN_VALUE);
        REGISTER_OPCODE(YIELD_VALUE);
        REGISTER_OPCODE(LOAD_CONST);
        REGISTER_OPCODE(PRINT_ITEM);
        REGISTER_OPCODE(PRINT_NEWLINE);
        REGISTER_OPCODE(PRINT_EXPR);
        REGISTER_OPCODE(LOAD_NAME);
        REGISTER_OPCODE(DELETE_NAME);
        REGISTER_OPCODE(COMPARE_OP);

        REGISTER_OPCODE(LOAD_FAST);
        REGISTER_OPCODE(STORE_FAST);
        REGISTER_OPCODE(DELETE_FAST);
        REGISTER_OPCODE(LOAD_LOCALS);

        REGISTER_OPCODE(POP_TOP);
        REGISTER_OPCODE(DUP_TOP);
        REGISTER_OPCODE(DUP_TOPX);

        REGISTER_OPCODE(SETUP_LOOP);
        REGISTER_ALIAS(SETUP_EXCEPT, SETUP_LOOP);
        REGISTER_ALIAS(SETUP_FINALLY, SETUP_LOOP);
        REGISTER_OPCODE(RAISE_VARARGS);

        REGISTER_OPCODE(BUILD_LIST);
        REGISTER_OPCODE(BUILD_TUPLE);
        REGISTER_OPCODE(BUILD_MAP);
        REGISTER_OPCODE(LIST_APPEND);

        REGISTER_OPCODE(GET_ITER);
        REGISTER_OPCODE(FOR_ITER); // XXX?
        REGISTER_OPCODE(UNPACK_SEQUENCE);
        REGISTER_OPCODE(BREAK_LOOP);

        REGISTER_OPCODE(POP_BLOCK);
        REGISTER_OPCODE(END_FINALLY);

        REGISTER_OPCODE(MAKE_FUNCTION);
        REGISTER_OPCODE(MAKE_CLOSURE);
        REGISTER_OPCODE(LOAD_CLOSURE);
        REGISTER_OPCODE(CALL_FUNCTION);
        REGISTER_OPCODE(CALL_FUNCTION_VAR);
        REGISTER_ALIAS(CALL_FUNCTION_KW, CALL_FUNCTION_VAR);
        REGISTER_ALIAS(CALL_FUNCTION_VAR_KW, CALL_FUNCTION_VAR);

        REGISTER_OPCODE(LOAD_ATTR);
        REGISTER_OPCODE(STORE_ATTR);
        REGISTER_OPCODE(DELETE_ATTR);

        REGISTER_OPCODE(IMPORT_FROM);
        REGISTER_OPCODE(IMPORT_STAR);
        REGISTER_OPCODE(IMPORT_NAME);
        
        REGISTER_OPCODE(BUILD_CLASS);
        REGISTER_OPCODE(EXEC_STMT);
        
        REGISTER_OPCODE(LOAD_GLOBAL);
        REGISTER_OPCODE(STORE_GLOBAL);

        REGISTER_OPCODE(BINARY_SUBSCR);
        REGISTER_OPCODE(STORE_SUBSCR);
        REGISTER_OPCODE(DELETE_SUBSCR);
            
        REGISTER_OPCODE(UNARY_POSITIVE);
        REGISTER_OPCODE(UNARY_NEGATIVE);
        REGISTER_OPCODE(UNARY_NOT);
        REGISTER_OPCODE(UNARY_CONVERT);
        REGISTER_OPCODE(UNARY_INVERT);
        REGISTER_OPCODE(BINARY_POWER);
        REGISTER_OPCODE(BINARY_MULTIPLY);
        REGISTER_OPCODE(BINARY_DIVIDE);
        REGISTER_ALIAS(BINARY_TRUE_DIVIDE, BINARY_DIVIDE);
        REGISTER_OPCODE(BINARY_FLOOR_DIVIDE);
        REGISTER_OPCODE(BINARY_MODULO);
        REGISTER_OPCODE(BINARY_ADD);
        REGISTER_OPCODE(BINARY_SUBTRACT);
        
        REGISTER_OPCODE(SLICE);
        REGISTER_ALIAS(SLICE+0, SLICE);
        REGISTER_ALIAS(SLICE+1, SLICE);
        REGISTER_ALIAS(SLICE+2, SLICE);
        REGISTER_ALIAS(SLICE+3, SLICE);

        REGISTER_OPCODE(STORE_SLICE);
        REGISTER_ALIAS(STORE_SLICE+0, STORE_SLICE);
        REGISTER_ALIAS(STORE_SLICE+1, STORE_SLICE);
        REGISTER_ALIAS(STORE_SLICE+2, STORE_SLICE);
        REGISTER_ALIAS(STORE_SLICE+3, STORE_SLICE);

        REGISTER_OPCODE(DELETE_SLICE);
        REGISTER_ALIAS(DELETE_SLICE+0, DELETE_SLICE);
        REGISTER_ALIAS(DELETE_SLICE+1, DELETE_SLICE);
        REGISTER_ALIAS(DELETE_SLICE+2, DELETE_SLICE);
        REGISTER_ALIAS(DELETE_SLICE+3, DELETE_SLICE);

        REGISTER_OPCODE(BINARY_LSHIFT);
        REGISTER_OPCODE(BINARY_RSHIFT);
        REGISTER_OPCODE(BINARY_AND);
        REGISTER_OPCODE(BINARY_XOR);
        REGISTER_OPCODE(BINARY_OR);

        REGISTER_OPCODE(INPLACE_POWER);
        REGISTER_OPCODE(INPLACE_MULTIPLY);
        REGISTER_OPCODE(INPLACE_DIVIDE);
        REGISTER_ALIAS(INPLACE_TRUE_DIVIDE, INPLACE_DIVIDE);
        REGISTER_OPCODE(INPLACE_FLOOR_DIVIDE);
        REGISTER_OPCODE(INPLACE_MODULO);
        REGISTER_OPCODE(INPLACE_ADD);
        REGISTER_OPCODE(INPLACE_SUBTRACT);
        REGISTER_OPCODE(INPLACE_LSHIFT);
        REGISTER_OPCODE(INPLACE_RSHIFT);
        REGISTER_OPCODE(INPLACE_AND);
        REGISTER_OPCODE(INPLACE_XOR);
        REGISTER_OPCODE(INPLACE_OR);

        REGISTER_OPCODE(LOAD_DEREF);
        REGISTER_OPCODE(STORE_DEREF);

#       undef REGISTER_OPCODE
#       undef REGISTER_ALIAS
    }
      
    llvm::ModuleProvider* MP;
    llvm::Module* the_module;
    llvm::ExecutionEngine* EE;
    llvm::FunctionPassManager* FPM;
    llvm::PassManager PMverifier;

    std::map<int, llvm::Function*> opcode_funcs;
    std::vector<int> fat_opcode;
    llvm::Function* opcode_unimplemented;
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

JITRuntime* jit = 0;

extern "C"
void init_jit_runtime() 
{
    jit = new JITRuntime(3);
}

extern "C"
void finalize_jit_runtime() 
{
    delete jit;
    jit = 0;
}

struct PyJittedFunc {
    PyJittedFunc(PyCodeObject* co) {
        //printf("Compiling %s in %s:%d\n", PyString_AS_STRING(co->co_name), PyString_AS_STRING(co->co_filename), co->co_firstlineno);
        func = jit->compile(co);
        //func->dump();
        cfunc = jit->get_func_pointer(func);
    }
    
    ~PyJittedFunc() {
        //printf("Deleting function %s\n", func->getName().c_str());
        // commenting out for now, it makes strange things happen
        //func->eraseFromParent(); // XXX is this enough?? what about machine code?
    }
    
    llvm::Function* func;
    jitted_cfunc_t cfunc;
};

extern "C"
jitted_cfunc_t get_jitted_function(PyCodeObject* co) 
{
    assert(jit);
    if (co->co_jitted == NULL)
        co->co_jitted = (void*) new PyJittedFunc(co);
    return ((PyJittedFunc*)co->co_jitted)->cfunc;
}

extern "C"
void finalize_jitted_function(PyCodeObject* co) 
{
    delete (PyJittedFunc*)co->co_jitted;
    co->co_jitted = 0;
}

#ifdef JIT_TEST

#include <llvm/Support/CommandLine.h>

int main(int argc, char** argv) {
    Py_InitializeEx(0);

    //char* args[] = {"", "-debug-only=jit"};
    //char* args[] = {"", "-print-machineinstrs"};
    //llvm::cl::ParseCommandLineOptions(2, args);

    // C or C++ do not have a function "read a file into a string"????
#define MAXCODE 65536
    char code[MAXCODE];
    int bytes = fread(code, 1, MAXCODE-1, stdin);
    code[bytes] = 0;
    int optimize = 1, inlineopcodes = 1;
    if (argc >= 2) {
        optimize = atoi(argv[1]);
    } 
    if (argc >= 3) {
        inlineopcodes = atoi(argv[2]);
    }
    
  
    PyCodeObject* co = (PyCodeObject*)Py_CompileString(code, "<test.py>", Py_file_input);
    assert(co);

    // show the bytecode
    PyObject* dis_module = PyImport_ImportModule("dis");
    PyObject* dis = PyObject_GetAttrString(dis_module, "dis");
    PyObject_CallFunctionObjArgs(dis, co, NULL);

    JITRuntime jit(optimize);
    // show LLVM bitcode
    llvm::Function* cf = jit.compile(co, inlineopcodes);
    cf->dump();

    jit.verify_function(cf);

    // try to execute function
    PyThreadState *tstate = PyThreadState_GET();
    PyObject* m = PyImport_AddModule("__main__");
    PyObject* d = PyModule_GetDict(m);
    PyFrameObject* f = PyFrame_New(tstate, co, d, d);
    assert(f);
    
    //PyEval_EvalFrame(f);

    {
        tstate->frame = f;
        jitted_cfunc_t jitted = jit.get_func_pointer(cf);
        PyObject* res = jitted(f, tstate, 0);
        printf("%x\n", (unsigned)res);
    }
    
    Py_DECREF(f);
    Py_DECREF(co);
}

#endif
