#include <iostream>
#include <chrono>
#include <ctime>
#include <fstream>
#include <sstream>
#include "llvm/ExecutionEngine/GenericValue.h"
#include "llvm/ExecutionEngine/Interpreter.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ExecutionEngine/MCJIT.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/TargetSelect.h"

using namespace llvm;

int readNValue(std::string matrixName) {
    int n;
    std::ifstream infoFile;
    infoFile.open("data/" + matrixName + "/" + matrixName + "_CSRbyNZ/info.csv");
    std::string token;
    while(getline(infoFile, token, ',')) {
        if(token == " n") {
            getline(infoFile, token, ',');
            n = std::stoi(token);
            return n;
        }
    }
    return 0;
}

void writeResultsToFile(std::string matrixName, long long int duration1_1, long long int duration1_2, long long int duration2) {
    std::ofstream benchmarkCSV;
    benchmarkCSV.open("./results/" + matrixName + "_CSRbyNZ_benchmark_type1.csv");
    benchmarkCSV << "FindFunctionNamed duration(ns); " << duration1_1 << ";" << "\n";
    benchmarkCSV << "getPointerToFunction duration(ns); " << duration1_2 << ";" << "\n";
    benchmarkCSV << "Run function duration(ns); " << duration2 << ";" << "\n";
    benchmarkCSV.close();
}


int main(int argc, char** argv) {

    if(argc != 4) {
        errs() << "Usage: ./benchmark <matrixName> <specType> <optLevel>";
        return 1;
    }

    std::string matrixName = argv[1];
    outs() << "Running benchmarks on " << matrixName << ".\n";

    std::string specType = argv[2];
    if (specType != "CSRbyNZ" && specType != "stencil"){
        errs() << "Wrong specType. Options are [CSRbyNZ, stencil]";
        return 2;
    }

    CodeGenOpt::Level optLevel;
    if (strcmp("None", argv[3]) == 0)          optLevel = CodeGenOpt::None;
    else if(strcmp("Less", argv[3]) == 0)      optLevel = CodeGenOpt::Less;
    else if(strcmp("Default", argv[3]) == 0)   optLevel = CodeGenOpt::Default;
    else if(strcmp("Aggressive", argv[3]) == 0)optLevel = CodeGenOpt::Aggressive;
    else {
        errs() << "Wrong optLevel. Options are [None, Less, Default, Aggressive]";
        return 3;
    }

    InitializeNativeTarget();
    InitializeNativeTargetAsmPrinter();
    InitializeNativeTargetAsmParser();

    LLVMContext Context;
    SMDiagnostic diag;

    std::unique_ptr<Module> Owner = parseIRFile(
            "data/" + matrixName + "/" + matrixName + "_" + specType + "/generated_merged.ll", diag, Context);
    if (!Owner) {
        errs() << "No such matrix";
        return 1;
    }


    Module *M = Owner.get();
    outs() << "Target: " << M->getTargetTriple() << "\n";
    M->materializeAllPermanently();
    ExecutionEngine *EE = EngineBuilder(std::move(Owner))
            .setOptLevel(optLevel)
            .setEngineKind(EngineKind::JIT)
            .create();
    auto start3 = std::chrono::high_resolution_clock::now();
    EE->finalizeObject();
    auto end3 = std::chrono::high_resolution_clock::now();

//    Test 1: FindFunctionNamed + getPointerToFunction
//    auto start1 = std::chrono::high_resolution_clock::now();
//    Function *func = EE->FindFunctionNamed("multByM");
//    auto end1_1 = std::chrono::high_resolution_clock::now();
//    void *rawptr = EE->getPointerToFunction(func);
//    auto end1_2 = std::chrono::high_resolution_clock::now();

    // Test 2: getPointerToNamedFunction
//    auto start1 = std::chrono::high_resolution_clock::now();
//    void * rawptr = EE->getPointerToNamedFunction("multByM", true);
//    auto end1 = std::chrono::high_resolution_clock::now();

    // Test 3: getFunctionAddress
    auto start1 = std::chrono::high_resolution_clock::now();
    uint64_t rawptr = EE->getFunctionAddress("multByM");
    auto end1 = std::chrono::high_resolution_clock::now();

    /*    std::vector<GenericValue> noargs;
    GenericValue GV = EE->runFunction(func, noargs);
    outs() << "Result: " << GV.IntVal; */

    /* generate mock values */
    int n = readNValue(matrixName);
    double *v = (double *) malloc(n * sizeof(double));
    double *w = (double *) malloc(n * sizeof(double));
    if (w == NULL || v == NULL) exit(1);
    for (int i = 0; i < n; i++) {
        v[i] = i;
        w[i] = 0;
    }

    /* run the function */
    auto start2 = std::chrono::high_resolution_clock::now();
    typedef void (*PFN)(double *, double *);
    PFN pfn = (PFN) (rawptr);
    for(int i = 0; i < 5000; i++){
        pfn(v, w);
    }
    auto end2 = std::chrono::high_resolution_clock::now();

    //For test 1
//    auto duration1_1 = std::chrono::duration_cast<std::chrono::nanoseconds>(end1_1 - start1).count();
//    auto duration1_2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end1_2 - end1_1).count();
//    auto duration2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end2 - start2).count();
//    outs() << "FindFunctionNamed duration (nanoseconds): \n" << duration1_1 << "\n";
//    outs() << "getPointerToFunction duration (nanoseconds): \n" << duration1_2 << "\n";
//    outs() << "Run function duration (nanoseconds): \n" << duration2 / 5000.0 << "\n";

    //For test 2
//    auto duration1 = std::chrono::duration_cast<std::chrono::nanoseconds>(end1 - start1).count();
//    auto duration2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end2 - start2).count();
//    outs() << "getFunctionAddress duration: " << duration1 << " nanoseconds\n";
//    outs() << "Run function duration (nanoseconds): \n" << duration2 / 5000.0 << "\n";

    //For test 3
    auto duration1 = std::chrono::duration_cast<std::chrono::microseconds>(end1 - start1).count();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end2 - start2).count();
    auto duration3 = std::chrono::duration_cast<std::chrono::microseconds>(end3 - start3).count();

    outs() << "getFunctionAddress duration (microseconds): \n" << duration1 << "\n";
    outs() << "Run function duration (microseconds): \n" << duration2 / 5000.0 << "\n";
    outs() << "Finalize duration (microseconds): \n" << duration3 << "\n";

    delete EE;
    llvm_shutdown();

//    writeResultsToFile(matrixName, duration1_1, duration1_2, duration2);

    return 0;
}

